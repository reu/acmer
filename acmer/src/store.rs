use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::SystemTime,
};

use async_trait::async_trait;
use dashmap::DashMap;
pub use papaleguas::OrderStatus;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
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

pub type PrivateKey = PrivateKeyDer<'static>;
pub type Certificate = CertificateDer<'static>;

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
        Ok(self
            .read()
            .await
            .get(domain)
            .map(|(key, certs)| (key.clone_key(), certs.clone())))
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
        Ok(self.get(domain).map(|item| {
            let (key, certs) = item.value();
            (key.clone_key(), certs.clone())
        }))
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
        Ok(self.get(directory).map(|item| item.clone_key()))
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
                .put_cert(domain, key.clone_key(), cert.clone())
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
            self.store.put_cert(domain, key.clone_key(), cert.clone()),
            self.cache.put_cert(domain, key, cert),
        )?;
        Ok(())
    }
}

pub struct CertExpirationTimeStore<S> {
    store: S,
}

fn cert_validity(cert: &[Certificate]) -> Option<SystemTime> {
    cert.iter()
        .filter_map(|cert| X509Certificate::from_der(cert).ok())
        .map(|cert| cert.tbs_certificate.validity)
        .map(|val| val.not_after.to_system_time())
        .min()
}

impl<S: CertStore> CertExpirationTimeStore<S> {
    pub fn new(store: S) -> Self {
        CertExpirationTimeStore { store }
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
        match self.store.get_cert(domain).await? {
            Some(cert) => match cert_validity(&cert.1) {
                Some(validity) if validity < SystemTime::now() => {
                    let valid_until = validity
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    trace!(domain, until = valid_until, "cert is expired");
                    Ok(None)
                }
                Some(_validity) => Ok(Some(cert)),
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
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
        Ok(Some(self.0.clone_key()))
    }

    async fn put_account(&self, _directory: &str, _key: PrivateKey) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use indoc::indoc;
    use papaleguas::OrderStatus;
    use rustls_pki_types::pem::{PemObject, SectionKind};

    use crate::store::{
        AuthChallenge, AuthChallengeDomainLock, AuthChallengeStore, CertStore,
        MemoryAuthChallengeStore, MemoryCertStore, MemoryOrderStore, OrderStore,
    };

    use super::{Certificate, Order, PrivateKey};

    #[tokio::test]
    async fn test_memory_store() {
        let pkey = indoc! {"
            -----BEGIN PRIVATE KEY-----
            MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCq1WvODxLHgRNw
            Fq7rHh9gCfCEtbN7iE2W6arQ+zYPVWiNQrKNyBqe9n2Ao/77EBnhKzJ3YrVBesGs
            b+DE/mMXIR/2skchNTX314zaZ13fIn/QnQBtsnh3uzwfk9dFe2Z2v9WSWzumPXoP
            UyEVt8OShW3kfjRM7WNu8IDubU1SiskRUym86fJCqIEPIwf0EkXN9Lt7fU+00X2A
            A3Bay3uepg0uaPDmdiWwnTSXYaY4JxIVJ6V1ntzjpuRHaVEfXzCpcaWLBpJbr+uT
            Le2RBfa6Pa7QjlY6moYAwaDfoF0Kk8U4tpV5X4Fx4wWNhPqUg8Y6NY3WJYXlB6fu
            uDn+DPFrAgMBAAECggEASjJHkEebsGqvNo+jiRqcJeorPHhua8jXaiQyvHFfGWnO
            7wt44Xt3lHMaLzULGZ/0nYdVc+S7NKVMWMh+pxCVmQYaC9uCaTnjJrHHy1P5wWAK
            g2CtPve0usvnYQ+k/9iIuCq5Z8eYMKuix+UjCXu2xXyOLh9iN8ci2Jw8Y1G1s5M9
            vk5MW4lvtb/WTAh6jTRXHMdx1RHjY8nGtf+eYu52uYm0ZWMh+H7zGzApCX1mpPKr
            lMwwzGLIUcrBZ1Q98yRsdnOr5ErzWoRH44k0+CfmpWsnoWtWUbWM4WUeQDEywx6k
            8aAkuVQRKvKem3ifoPG8mAjij6sfV/v19ffusn/KAQKBgQDG5z8JTUGTxYar4H/D
            Gi1bMI9atzDdbsE499rWpPZ5BuwtSDmMACS5lWu8pT/YSELNOu5PtKK6H41ZADLW
            kGItzCOcPQTOAAdnD5T29+jVG3hnfQCIBEksa97uWGamX00P21qUAeRStWaKf//O
            dL6h9W7zP04tYah/zwQ5n4EcMQKBgQDb3234Di8/RQPLAJm2VoXCT/1+cRcgfKCm
            YvmmNOzPlGmYrSHx9khlZUXdTy2aZj0NGHaWJPbE5sCVnsw7dqXPibJ1TYN/PIHJ
            X1MYQjnHRkFZDpk/fSd8xl6ZcRHTjehhd8qbyZHTFIUHX59oC3e+uwNg862fkoYH
            TAsp3OesWwKBgQDDKtDNncLE7sKwD/8NP7hVjBZ92tbV0AFElt9iUkeOhd5kqEPf
            PZzLhPRMDJHS9USnADYqe4JYwvD87Zb0toO/kFk4yx7Vy214EPAITUVnJidE1IEa
            9amfLtF2acN/aG/DKWd9Z0XUai6No/8rY55SaPNPN0TMftDJaCYrLHmRYQKBgFX9
            kQWljobhF/Wp23P7bL6tCAgOdKwI8c+BAAAnzMH2WkIS3CbEWlYFgIhoMf6jo5be
            jWp1NGmXkZQykc9jvL9pK/lCgn4djOjTtizTocM0z9PjqL2y1eGvt0mtdfpWEp8j
            +YJqF/UEnm5e0HohmghnHZAqXSn+ZRqve+I4egbnAoGBALeuy9MMaLQEL4HzGyvy
            C2U5FYAohdbw05WSfuvE8weluvND2DbQvNXq/0MAt3D0AviGTR9k0zpO+OS/nLnv
            nuRgPCQl8N7RLKQqKf/grE9LAlZGj8pajn7ARhutjVs9z7CYQU8zthyUIvrqTLqQ
            b41I4V1EVPutE18LGpgWFRfJ
            -----END PRIVATE KEY-----
        "};

        let cert = indoc! {"
            -----BEGIN CERTIFICATE-----
            MIIDazCCAlOgAwIBAgIUVE8Tzvqz/Sd9VdOf94+FygbEMeIwDQYJKoZIhvcNAQEL
            BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
            GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNTAzMDkxMzUyMjFaFw0yNjAz
            MDkxMzUyMjFaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
            HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
            AQUAA4IBDwAwggEKAoIBAQCq1WvODxLHgRNwFq7rHh9gCfCEtbN7iE2W6arQ+zYP
            VWiNQrKNyBqe9n2Ao/77EBnhKzJ3YrVBesGsb+DE/mMXIR/2skchNTX314zaZ13f
            In/QnQBtsnh3uzwfk9dFe2Z2v9WSWzumPXoPUyEVt8OShW3kfjRM7WNu8IDubU1S
            iskRUym86fJCqIEPIwf0EkXN9Lt7fU+00X2AA3Bay3uepg0uaPDmdiWwnTSXYaY4
            JxIVJ6V1ntzjpuRHaVEfXzCpcaWLBpJbr+uTLe2RBfa6Pa7QjlY6moYAwaDfoF0K
            k8U4tpV5X4Fx4wWNhPqUg8Y6NY3WJYXlB6fuuDn+DPFrAgMBAAGjUzBRMB0GA1Ud
            DgQWBBSXhnoVxEQENyRiCooUeIov7R7yLDAfBgNVHSMEGDAWgBSXhnoVxEQENyRi
            CooUeIov7R7yLDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCB
            4oNLXCd6gP8MlOyaYA9NZEfihNOZ/lg24UAtTs92btWYpsERqIm3cuRQ/mhpUnYR
            rr4yzIHY3LzG2pK1LjbEIStRjCsPb/fCLcxx9tffxweiwpY+AxjdO4R/v9bFjxk4
            sfb8h0ls7idqJOzU43PfTbHLaiKaPITw3TBNi5tn88bGag4iWIUdFTXbInL603Pz
            R/g27O0Q3ohsA07C0i+GZbdtR1mghSlXj3m7bnAVDyCac670AE33c5dYKiyudRXB
            17dFJhag9cNIXgCIaoEGMmqByuZVCbZshJb1ac3sP3bk7LR35TPm0DmL4ReiycJg
            0W3rtqDKWRuaPAS8WMZw
            -----END CERTIFICATE-----
        "};

        let store = MemoryCertStore::default();

        let pkey = PrivateKey::from_pem(SectionKind::PrivateKey, pkey.as_bytes().to_vec()).unwrap();
        let cert = vec![Certificate::from_pem_slice(cert.as_bytes()).unwrap()];

        assert!(store.get_cert("lol.wut").await.unwrap().is_none());

        store
            .put_cert("lol.wut", pkey.clone_key(), cert.clone())
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
