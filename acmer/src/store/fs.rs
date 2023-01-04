use std::path::{Path, PathBuf};

use async_trait::async_trait;
use pem_rfc7468 as pem;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile as pemfile;
use tokio::{fs, try_join};

use super::{AccountStore, CertStore};

struct FileStore {
    directory: PathBuf,
}

impl FileStore {
    pub fn new(dir: impl AsRef<Path>) -> FileStore {
        Self {
            directory: dir.as_ref().into(),
        }
    }
}

#[async_trait]
impl CertStore for FileStore {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        let key = self.directory.join(format!("{domain}.key"));
        let cert = self.directory.join(format!("{domain}.crt"));

        let (key, cert) = try_join!(fs::read(key), fs::read(cert)).ok()?;

        let key = PrivateKey(key);
        let cert = pemfile::read_all(&mut std::io::Cursor::new(cert))
            .ok()?
            .into_iter()
            .filter_map(|item| match item {
                pemfile::Item::X509Certificate(der) => Some(der),
                _ => None,
            })
            .map(Certificate)
            .collect::<Vec<Certificate>>();

        Some((key, cert))
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        let key_path = self.directory.join(format!("{domain}.key"));
        let cert_path = self.directory.join(format!("{domain}.crt"));

        let cert = cert
            .into_iter()
            .map(|cert| pem::encode_string("CERTIFICATE", pem::LineEnding::default(), &cert.0))
            .collect::<Result<String, _>>()
            .unwrap();

        try_join!(fs::write(key_path, key.0), fs::write(cert_path, cert)).unwrap();
    }
}

#[async_trait]
impl AccountStore for FileStore {
    async fn get_account(&self, directory: &str) -> Option<PrivateKey> {
        let path = self.directory.join(format!("account.{directory}.key"));
        let key = fs::read(path).await.ok()?;

        pem::decode_vec(&key)
            .ok()
            .and_then(|(label, key)| match label {
                "PRIVATE KEY" => Some(key),
                _ => None,
            })
            .map(PrivateKey)
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) {
        let path = self.directory.join(format!("account.{directory}.key"));
        let key = pem::encode_string("PRIVATE KEY", pem::LineEnding::default(), &key.0).unwrap();
        fs::write(path, key).await.ok();
    }
}

pub struct CertFileStore(FileStore);

impl CertFileStore {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self(FileStore::new(dir))
    }
}

#[async_trait]
impl CertStore for CertFileStore {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        self.0.get_cert(domain).await
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        self.0.put_cert(domain, key, cert).await
    }
}

pub struct AccountFileStore(FileStore);

impl AccountFileStore {
    pub fn new(dir: impl AsRef<Path>) -> Self {
        Self(FileStore::new(dir))
    }
}

#[async_trait]
impl AccountStore for AccountFileStore {
    async fn get_account(&self, directory: &str) -> Option<PrivateKey> {
        self.0.get_account(directory).await
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) {
        self.0.put_account(directory, key).await
    }
}

#[cfg(test)]
mod test {
    use std::env::temp_dir;

    use super::*;

    #[tokio::test]
    async fn test_fs_account_store() {
        let store = AccountFileStore::new(temp_dir());
        let key = papaleguas::PrivateKey::random_ec_key(rand::thread_rng())
            .to_der()
            .map(PrivateKey)
            .unwrap();
        store.put_account("123", key.clone()).await;
        assert_eq!(store.get_account("123").await, Some(key));
    }
}
