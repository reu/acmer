use std::path::{Path, PathBuf};

use async_trait::async_trait;
use pem_rfc7468 as pem;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile as pemfile;
use tokio::{fs, io, try_join};

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
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        let key = self.directory.join(format!("{domain}.key"));
        let cert = self.directory.join(format!("{domain}.crt"));

        let (key, cert) = try_join!(fs::read(key), fs::read(cert))?;

        let key = PrivateKey(key);
        let cert = pemfile::read_all(&mut cert.as_ref())?
            .into_iter()
            .filter_map(|item| match item {
                pemfile::Item::X509Certificate(der) => Some(der),
                _ => None,
            })
            .map(Certificate)
            .collect::<Vec<Certificate>>();

        Ok(Some((key, cert)))
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
        let key_path = self.directory.join(format!("{domain}.key"));
        let cert_path = self.directory.join(format!("{domain}.crt"));

        let cert = cert
            .into_iter()
            .map(|cert| pem::encode_string("CERTIFICATE", pem::LineEnding::default(), &cert.0))
            .collect::<Result<String, _>>()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;

        try_join!(fs::write(key_path, key.0), fs::write(cert_path, cert))?;
        Ok(())
    }
}

#[async_trait]
impl AccountStore for FileStore {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        let path = self.directory.join(format!("account.{directory}.key"));
        let key = fs::read(path).await?;

        let key = pem::decode_vec(&key)
            .ok()
            .and_then(|(label, key)| match label {
                "PRIVATE KEY" => Some(key),
                _ => None,
            })
            .map(PrivateKey);

        Ok(key)
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
        let path = self.directory.join(format!("account.{directory}.key"));
        let key = pem::encode_string("PRIVATE KEY", pem::LineEnding::default(), &key.0)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        fs::write(path, key).await?;
        Ok(())
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
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        self.0.get_cert(domain).await
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
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
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        self.0.get_account(directory).await
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
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
        store.put_account("123", key.clone()).await.unwrap();
        assert_eq!(store.get_account("123").await.unwrap(), Some(key));
    }
}
