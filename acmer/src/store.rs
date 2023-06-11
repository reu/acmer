use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::SystemTime,
};

use async_trait::async_trait;
use dashmap::DashMap;
pub use papaleguas::OrderStatus;
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::{
    io,
    sync::{OwnedRwLockWriteGuard, RwLock},
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

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    pub url: String,
    pub status: OrderStatus,
    #[serde(default, with = "time::serde::iso8601::option")]
    pub expires: Option<OffsetDateTime>,
}

impl std::hash::Hash for Order {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.url.hash(state)
    }
}

impl PartialEq for Order {
    fn eq(&self, other: &Self) -> bool {
        self.url.eq(&other.url)
    }
}

impl From<&papaleguas::Order> for Order {
    fn from(value: &papaleguas::Order) -> Self {
        Self {
            url: value.url().to_owned(),
            status: *value.status(),
            expires: value.expires(),
        }
    }
}

#[async_trait]
pub trait OrderStore: Send + Sync {
    async fn list_orders(&self, domain: &str) -> io::Result<HashSet<Order>>;
    async fn upsert_order(&self, domain: &str, order: Order) -> io::Result<()>;
    async fn remove_order(&self, domain: &str, order_url: &str) -> io::Result<()>;
}

#[async_trait]
pub trait AccountStore: Send + Sync {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>>;
    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()>;
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthChallenge {
    challenges: Vec<ChallengeKind>,
}

#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
enum ChallengeKind {
    TlsAlpn(String),
    Http01 { token: String, challenge: String },
}

impl AuthChallenge {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_http01(mut self, token: impl Into<String>, challenge: impl Into<String>) -> Self {
        self.add_http01(token, challenge);
        self
    }

    pub fn with_tls_alpn01(mut self, challenge: impl Into<String>) -> Self {
        self.add_tls_alpn01(challenge);
        self
    }

    pub fn add_http01(&mut self, token: impl Into<String>, challenge: impl Into<String>) {
        self.challenges.push(ChallengeKind::Http01 {
            token: token.into(),
            challenge: challenge.into(),
        });
    }

    pub fn add_tls_alpn01(&mut self, challenge: impl Into<String>) {
        self.challenges
            .push(ChallengeKind::TlsAlpn(challenge.into()));
    }

    pub fn http01_challenge(&self) -> Option<(&str, &str)> {
        self.challenges
            .iter()
            .find_map(|challenge| match challenge {
                ChallengeKind::Http01 { token, challenge } => {
                    Some((token.as_str(), challenge.as_str()))
                }
                _ => None,
            })
    }

    pub fn tls_alpn01_challenge(&self) -> Option<&str> {
        self.challenges
            .iter()
            .find_map(|challenge| match challenge {
                ChallengeKind::TlsAlpn(challenge) => Some(challenge.as_str()),
                _ => None,
            })
    }

    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }
}

#[async_trait]
pub trait AuthChallengeStore: Send + Sync {
    type LockGuard: AuthChallengeDomainLock + Send;
    async fn get_challenge(&self, domain: &str) -> io::Result<Option<AuthChallenge>>;
    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard>;
    async fn unlock(&self, domain: &str) -> io::Result<()>;
}

#[async_trait]
pub trait AuthChallengeDomainLock: Send + Sync {
    async fn put_challenge(&mut self, challenge: AuthChallenge) -> io::Result<()>;
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

#[async_trait]
impl OrderStore for DashMap<String, HashSet<Order>> {
    async fn list_orders(&self, domain: &str) -> io::Result<HashSet<Order>> {
        let orders = self
            .get(domain)
            .map(|item| item.value().clone())
            .unwrap_or_default();
        Ok(orders)
    }

    async fn upsert_order(&self, domain: &str, order: Order) -> io::Result<()> {
        let mut orders = self.entry(domain.to_string()).or_default();
        orders.replace(order);
        Ok(())
    }

    async fn remove_order(&self, domain: &str, order_url: &str) -> io::Result<()> {
        self.entry(domain.to_string())
            .and_modify(|orders| {
                orders.remove(&Order {
                    url: order_url.to_string(),
                    status: OrderStatus::Ready,
                    expires: None,
                });
            })
            .or_default();
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct MemoryOrderStore(DashMap<String, HashSet<Order>>);

#[async_trait]
impl OrderStore for MemoryOrderStore {
    async fn list_orders(&self, domain: &str) -> io::Result<HashSet<Order>> {
        self.0.list_orders(domain).await
    }

    async fn upsert_order(&self, domain: &str, order: Order) -> io::Result<()> {
        self.0.upsert_order(domain, order).await
    }

    async fn remove_order(&self, domain: &str, order_url: &str) -> io::Result<()> {
        self.0.remove_order(domain, order_url).await
    }
}

#[async_trait]
impl AccountStore for DashMap<String, PrivateKey> {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        Ok(self.get(directory).map(|item| item.value().clone()))
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
        self.insert(directory.to_owned(), key);
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryAccountStore(Arc<DashMap<String, PrivateKey>>);

#[async_trait]
impl AccountStore for MemoryAccountStore {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        self.0.get_account(directory).await
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
        self.0.put_account(directory, key).await
    }
}

#[derive(Debug, Default)]
pub struct MemoryAuthChallengeStore {
    store: DashMap<String, Arc<RwLock<AuthChallenge>>>,
}

pub struct MemoryAuthChallengeStoreGuard(OwnedRwLockWriteGuard<AuthChallenge>);

#[async_trait]
impl AuthChallengeStore for MemoryAuthChallengeStore {
    type LockGuard = MemoryAuthChallengeStoreGuard;

    async fn get_challenge(&self, domain: &str) -> io::Result<Option<AuthChallenge>> {
        match self.store.get(domain) {
            Some(entry) => Ok(Some(entry.value().clone().read().await.clone())),
            None => Ok(None),
        }
    }

    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard> {
        self.store
            .entry(domain.to_owned())
            .or_default()
            .clone()
            .try_write_owned()
            .map(MemoryAuthChallengeStoreGuard)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "could not arquire lock"))
    }

    async fn unlock(&self, domain: &str) -> io::Result<()> {
        self.store.remove(domain);
        Ok(())
    }
}

#[async_trait]
impl AuthChallengeDomainLock for MemoryAuthChallengeStoreGuard {
    async fn put_challenge(&mut self, challenge: AuthChallenge) -> io::Result<()> {
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
    use papaleguas::OrderStatus;
    use rustls::{Certificate, PrivateKey};

    use crate::store::{
        AuthChallenge, AuthChallengeDomainLock, AuthChallengeStore, CertStore,
        MemoryAuthChallengeStore, MemoryCertStore, MemoryOrderStore, OrderStore,
    };

    use super::Order;

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
    async fn test_order_memory_store() {
        let store = MemoryOrderStore::default();

        let order1 = Order {
            url: "http://order/1".to_string(),
            status: OrderStatus::Ready,
            expires: None,
        };

        let order2 = Order {
            url: "http://order/2".to_string(),
            status: OrderStatus::Invalid,
            expires: None,
        };

        let order3 = Order {
            url: "http://order/3".to_string(),
            status: OrderStatus::Invalid,
            expires: None,
        };

        store.upsert_order("lol.com", order1.clone()).await.unwrap();
        store.upsert_order("lol.com", order2.clone()).await.unwrap();
        store.upsert_order("wut.com", order3.clone()).await.unwrap();

        let orders = store.list_orders("lol.com").await.unwrap();
        assert!(orders.contains(&order1));
        assert!(orders.contains(&order2));
        assert!(!orders.contains(&order3));

        let orders = store.list_orders("wut.com").await.unwrap();
        assert!(orders.contains(&order3));

        store.remove_order("lol.com", &order1.url).await.unwrap();
        let orders = store.list_orders("lol.com").await.unwrap();
        assert!(!orders.contains(&order1));
        assert!(orders.contains(&order2));

        let orders = store.list_orders("wut.com").await.unwrap();
        assert!(orders.contains(&order3));
        store
            .upsert_order(
                "wut.com",
                Order {
                    status: OrderStatus::Valid,
                    ..order3.clone()
                },
            )
            .await
            .unwrap();
        let orders = store.list_orders("wut.com").await.unwrap();
        assert_eq!(orders.get(&order3).unwrap().status, OrderStatus::Valid);
    }

    #[tokio::test]
    async fn test_auth_store_lock() {
        let store = MemoryAuthChallengeStore::default();

        let mut lock1 = store.lock("lol.wut").await.unwrap();
        assert!(store.lock("lol.wut").await.is_err());

        let mut lock2 = store.lock("wtf.wut").await.unwrap();
        assert!(store.lock("wtf.wut").await.is_err());

        lock1
            .put_challenge(AuthChallenge::new().with_tls_alpn01("1"))
            .await
            .unwrap();
        lock2
            .put_challenge(
                AuthChallenge::new()
                    .with_http01("token", "chall")
                    .with_tls_alpn01("tls"),
            )
            .await
            .unwrap();

        drop(lock1);
        assert_eq!(
            store
                .get_challenge("lol.wut")
                .await
                .unwrap()
                .unwrap()
                .tls_alpn01_challenge(),
            Some("1")
        );

        drop(lock2);
        assert_eq!(
            store
                .get_challenge("wtf.wut")
                .await
                .unwrap()
                .unwrap()
                .http01_challenge(),
            Some(("token", "chall"))
        );
        assert_eq!(
            store
                .get_challenge("wtf.wut")
                .await
                .unwrap()
                .unwrap()
                .tls_alpn01_challenge(),
            Some("tls")
        );

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
