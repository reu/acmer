use std::{collections::HashMap, sync::Arc, time::SystemTime};

use async_trait::async_trait;
use rustls::{Certificate, PrivateKey};
use tokio::{
    join,
    sync::{Mutex, OwnedRwLockWriteGuard, RwLock},
};
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
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)>;
    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>);
}

#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get_account(&self, directory: &str) -> Option<PrivateKey>;
    async fn put_account(&self, directory: &str, key: PrivateKey);
}

#[async_trait]
pub trait AuthChallengeStore: Send + Sync {
    type LockGuard: AuthChallengeDomainLock + Send;
    async fn get_challenge(&self, domain: &str) -> Option<String>;
    async fn lock(&self, domain: &str) -> Result<Self::LockGuard, AuthChallengeStoreLockError>;
    async fn unlock(&self, domain: &str);
}

#[derive(Debug)]
pub struct AuthChallengeStoreLockError;

#[async_trait]
pub trait AuthChallengeDomainLock: Send + Sync {
    async fn put_challenge(&mut self, challenge: String);
}

#[async_trait]
impl CertStore for RwLock<HashMap<String, (PrivateKey, Vec<Certificate>)>> {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        self.read().await.get(domain).cloned()
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        self.write().await.insert(domain.to_owned(), (key, cert));
    }
}

#[derive(Debug, Default)]
pub struct MemoryCertStore(RwLock<HashMap<String, (PrivateKey, Vec<Certificate>)>>);

#[async_trait]
impl CertStore for MemoryCertStore {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        self.0.read().await.get(domain).cloned()
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        self.0.write().await.insert(domain.to_owned(), (key, cert));
    }
}

#[derive(Debug, Default)]
pub struct MemoryAccountStore(RwLock<HashMap<String, PrivateKey>>);

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get_account(&self, directory: &str) -> Option<PrivateKey> {
        self.0.read().await.get(directory).cloned()
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) {
        self.0.write().await.insert(directory.to_owned(), key);
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

    async fn get_challenge(&self, domain: &str) -> Option<String> {
        let entry = self.store.lock().await.get(domain).cloned()?;
        Some(entry.clone().read().await.clone())
    }

    async fn lock(&self, domain: &str) -> Result<Self::LockGuard, AuthChallengeStoreLockError> {
        self.store
            .lock()
            .await
            .entry(domain.to_owned())
            .or_default()
            .clone()
            .try_write_owned()
            .map(MemoryAuthChallengeStoreGuard)
            .map_err(|_| AuthChallengeStoreLockError)
    }

    async fn unlock(&self, domain: &str) {
        self.store.lock().await.remove(domain);
    }
}

#[async_trait]
impl AuthChallengeDomainLock for MemoryAuthChallengeStoreGuard {
    async fn put_challenge(&mut self, challenge: String) {
        *self.0 = challenge
    }
}

pub struct CachedCertStore {
    store: Box<dyn CertStore>,
    cache: Box<dyn CertStore>,
}

impl CachedCertStore {
    pub fn new(store: impl CertStore + 'static) -> Self {
        CachedCertStore {
            store: Box::new(store),
            cache: Box::new(RwLock::new(HashMap::new())),
        }
    }
}

pub trait CachedCertStoreExt {
    fn cached(self) -> CachedCertStore;
}

impl<C: CertStore + 'static> CachedCertStoreExt for C {
    fn cached(self) -> CachedCertStore {
        CachedCertStore::new(self)
    }
}

#[async_trait]
impl CertStore for CachedCertStore {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        if let Some(cached) = self.cache.get_cert(domain).await {
            return Some(cached);
        }

        if let Some((key, cert)) = self.store.get_cert(domain).await {
            self.cache.put_cert(domain, key.clone(), cert.clone()).await;
            return Some((key, cert));
        }

        None
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        join!(
            self.store.put_cert(domain, key.clone(), cert.clone()),
            self.cache.put_cert(domain, key, cert),
        );
    }
}

pub struct CertExpirationTimeStore {
    store: Box<dyn CertStore>,
}

impl CertExpirationTimeStore {
    pub fn new(store: impl CertStore + 'static) -> Self {
        CertExpirationTimeStore {
            store: Box::new(store),
        }
    }
}

pub trait CertExpirationTimeStoreExt {
    fn with_validity_check(self) -> CertExpirationTimeStore;
}

impl<C: CertStore + 'static> CertExpirationTimeStoreExt for C {
    fn with_validity_check(self) -> CertExpirationTimeStore {
        CertExpirationTimeStore::new(self)
    }
}

#[async_trait]
impl CertStore for CertExpirationTimeStore {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        if let Some((key, cert)) = self.store.get_cert(domain).await {
            if cert
                .iter()
                .filter_map(|cert| X509Certificate::from_der(&cert.0).ok())
                .map(|cert| cert.tbs_certificate.validity)
                .any(|val| {
                    val.not_before.to_system_time() > SystemTime::now()
                        || val.not_after.to_system_time() < SystemTime::now()
                })
            {
                return None;
            }

            return Some((key, cert));
        }

        None
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
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
    async fn get_account(&self, _directory: &str) -> Option<PrivateKey> {
        Some(self.0.clone())
    }

    async fn put_account(&self, _directory: &str, _key: PrivateKey) {}
}

#[cfg(test)]
mod test {
    use crate::store::{AuthChallengeDomainLock, AuthChallengeStore, MemoryAuthChallengeStore};

    #[tokio::test]
    async fn test_auth_store_lock() {
        let store = MemoryAuthChallengeStore::default();

        let mut lock1 = store.lock("lol.wut").await.unwrap();
        assert!(store.lock("lol.wut").await.is_err());

        let mut lock2 = store.lock("wtf.wut").await.unwrap();
        assert!(store.lock("wtf.wut").await.is_err());

        lock1.put_challenge("1".to_string()).await;
        lock2.put_challenge("2".to_string()).await;

        drop(lock1);
        assert_eq!(store.get_challenge("lol.wut").await.unwrap(), "1");

        drop(lock2);
        assert_eq!(store.get_challenge("wtf.wut").await.unwrap(), "2");

        assert!(store.get_challenge("other.wut").await.is_none());
    }

    #[tokio::test]
    async fn test_auth_store_unlock() {
        let store = MemoryAuthChallengeStore::default();

        let _lock = store.lock("lol.wut").await.unwrap();
        store.unlock("lol.wut").await;
        let _lock = store.lock("lol.wut").await.unwrap();
    }
}
