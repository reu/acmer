use std::{collections::HashMap, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use dashmap::DashMap;
use rustls::{Certificate, PrivateKey};
use tokio::{
    io,
    sync::{Mutex, OwnedRwLockWriteGuard, RwLock},
    try_join,
};
use tracing::trace;
use x509_cert::{der::Decode, Certificate as X509Certificate};

pub use boxed::*;
#[cfg(feature = "dynamodb-store")]
pub use dynamodb::*;
pub use fs::*;

mod boxed;
#[cfg(feature = "dynamodb-store")]
mod dynamodb;
mod fs;

#[async_trait]
pub trait CertStore: Send + Sync {
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>>;
    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()>;
}

#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>>;
    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()>;
}

#[async_trait]
pub trait AuthChallengeStore: Send + Sync {
    type LockGuard: AuthChallengeDomainLock + Send;
    async fn get_challenge(&self, domain: &str) -> io::Result<Option<String>>;
    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard>;
    async fn unlock(&self, domain: &str) -> io::Result<()>;
}

#[async_trait]
pub trait AuthChallengeDomainLock: Send + Sync {
    async fn put_challenge(&mut self, challenge: String) -> io::Result<()>;
}

#[async_trait]
impl CertStore for RwLock<HashMap<String, (PrivateKey, Vec<Certificate>)>> {
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        Ok(self.read().await.get(domain).cloned())
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
        self.write().await.insert(domain.to_owned(), (key, cert));
        Ok(())
    }
}

#[async_trait]
impl CertStore for DashMap<String, (PrivateKey, Vec<Certificate>)> {
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        Ok(self.get(domain).map(|item| item.value().clone()))
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
        self.insert(domain.to_owned(), (key, cert));
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryCertStore(DashMap<String, (PrivateKey, Vec<Certificate>)>);

#[async_trait]
impl CertStore for MemoryCertStore {
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

#[derive(Debug, Default)]
pub struct MemoryAccountStore(RwLock<HashMap<String, PrivateKey>>);

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        Ok(self.0.read().await.get(directory).cloned())
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
        self.0.write().await.insert(directory.to_owned(), key);
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryAuthChallengeStore {
    store: Mutex<HashMap<String, Arc<RwLock<String>>>>,
}

pub struct MemoryAuthChallengeStoreGuard(OwnedRwLockWriteGuard<String>);

#[async_trait]
impl AuthChallengeStore for MemoryAuthChallengeStore {
    type LockGuard = MemoryAuthChallengeStoreGuard;

    async fn get_challenge(&self, domain: &str) -> io::Result<Option<String>> {
        match self.store.lock().await.get(domain).cloned() {
            Some(entry) => Ok(Some(entry.clone().read().await.clone())),
            None => Ok(None),
        }
    }

    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard> {
        self.store
            .lock()
            .await
            .entry(domain.to_owned())
            .or_default()
            .clone()
            .try_write_owned()
            .map(MemoryAuthChallengeStoreGuard)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "could not arquire lock"))
    }

    async fn unlock(&self, domain: &str) -> io::Result<()> {
        self.store.lock().await.remove(domain);
        Ok(())
    }
}

#[async_trait]
impl AuthChallengeDomainLock for MemoryAuthChallengeStoreGuard {
    async fn put_challenge(&mut self, challenge: String) -> io::Result<()> {
        *self.0 = challenge;
        Ok(())
    }
}

pub struct CachedCertStore<S> {
    store: S,
    cache: MemoryCertStore,
}

impl<S: CertStore> CachedCertStore<S> {
    pub fn new(store: S) -> Self {
        CachedCertStore {
            store,
            cache: MemoryCertStore::default(),
        }
    }
}

pub trait CachedCertStoreExt {
    fn cached(self) -> CachedCertStore<Self>
    where
        Self: Sized;
}

impl<C: CertStore + 'static> CachedCertStoreExt for C {
    fn cached(self) -> CachedCertStore<Self> {
        CachedCertStore::new(self)
    }
}

#[async_trait]
impl<S: CertStore> CertStore for CachedCertStore<S> {
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        if let Some(cached) = self.cache.get_cert(domain).await? {
            return Ok(Some(cached));
        }

        if let Some((key, cert)) = self.store.get_cert(domain).await? {
            trace!(domain, "cert not cached, caching now");
            self.cache
                .put_cert(domain, key.clone(), cert.clone())
                .await?;
            return Ok(Some((key, cert)));
        }

        Ok(None)
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
        trace!(domain, "caching cert");
        try_join!(
            self.store.put_cert(domain, key.clone(), cert.clone()),
            self.cache.put_cert(domain, key, cert),
        )?;
        Ok(())
    }
}

pub struct CertExpirationTimeStore<S> {
    store: S,
    validities: DashMap<String, SystemTime>,
}

impl<S: CertStore> CertExpirationTimeStore<S> {
    pub fn new(store: S) -> Self {
        CertExpirationTimeStore {
            store,
            validities: DashMap::new(),
        }
    }
}

pub trait CertExpirationTimeStoreExt {
    fn with_validity_check(self) -> CertExpirationTimeStore<Self>
    where
        Self: Sized;
}

impl<C: CertStore + 'static> CertExpirationTimeStoreExt for C {
    fn with_validity_check(self) -> CertExpirationTimeStore<Self> {
        CertExpirationTimeStore::new(self)
    }
}

#[async_trait]
impl<S: CertStore> CertStore for CertExpirationTimeStore<S> {
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        match self.validities.get(domain) {
            Some(validity) if validity.value() < &SystemTime::now() => {
                let valid_until = validity
                    .value()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                trace!(domain, until = valid_until, "cert is expired");
                Ok(None)
            }
            _ => self.store.get_cert(domain).await,
        }
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
        if let Some(not_after) = cert
            .iter()
            .filter_map(|cert| X509Certificate::from_der(&cert.0).ok())
            .map(|cert| cert.tbs_certificate.validity)
            .map(|val| val.not_after.to_system_time())
            .min()
        {
            let valid_until = not_after
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            trace!(
                domain,
                until = valid_until,
                "cert is valid until {valid_until}"
            );
            self.validities.insert(domain.to_owned(), not_after);
        }

        self.store.put_cert(domain, key, cert).await
    }
}

pub struct SingleAccountStore(PrivateKey);

impl SingleAccountStore {
    pub fn new(key: PrivateKey) -> Self {
        SingleAccountStore(key)
    }
}

#[async_trait]
impl AccountStore for SingleAccountStore {
    async fn get_account(&self, _directory: &str) -> io::Result<Option<PrivateKey>> {
        Ok(Some(self.0.clone()))
    }

    async fn put_account(&self, _directory: &str, _key: PrivateKey) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use rustls::{Certificate, PrivateKey};

    use crate::store::{
        AuthChallengeDomainLock, AuthChallengeStore, CertStore, MemoryAuthChallengeStore,
        MemoryCertStore,
    };

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryCertStore::default();

        let pkey = PrivateKey(b"pkey".to_vec());
        let cert = vec![Certificate(b"cert".to_vec())];

        assert!(store.get_cert("lol.wut").await.unwrap().is_none());

        store
            .put_cert("lol.wut", pkey.clone(), cert.clone())
            .await
            .unwrap();

        let (stored_key, stored_cert) = store.get_cert("lol.wut").await.unwrap().unwrap();
        assert_eq!(stored_key, pkey);
        assert_eq!(stored_cert, cert);
    }

    #[tokio::test]
    async fn test_auth_store_lock() {
        let store = MemoryAuthChallengeStore::default();

        let mut lock1 = store.lock("lol.wut").await.unwrap();
        assert!(store.lock("lol.wut").await.is_err());

        let mut lock2 = store.lock("wtf.wut").await.unwrap();
        assert!(store.lock("wtf.wut").await.is_err());

        lock1.put_challenge("1".to_string()).await.unwrap();
        lock2.put_challenge("2".to_string()).await.unwrap();

        drop(lock1);
        assert_eq!(store.get_challenge("lol.wut").await.unwrap().unwrap(), "1");

        drop(lock2);
        assert_eq!(store.get_challenge("wtf.wut").await.unwrap().unwrap(), "2");

        assert!(store.get_challenge("other.wut").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_auth_store_unlock() {
        let store = MemoryAuthChallengeStore::default();

        let _lock = store.lock("lol.wut").await.unwrap();
        store.unlock("lol.wut").await.unwrap();
        let _lock = store.lock("lol.wut").await.unwrap();
    }
}
