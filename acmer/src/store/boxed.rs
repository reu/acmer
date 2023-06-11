use std::collections::HashSet;

use async_trait::async_trait;
use rustls::{Certificate, PrivateKey};
use tokio::io;

use super::{
    AccountStore, AuthChallengeDomainLock, AuthChallengeStore, CertStore, Order, OrderStore,
};

pub struct BoxedCertStore(Box<dyn CertStore>);

impl BoxedCertStore {
    pub fn new(store: impl CertStore + 'static) -> Self {
        Self(Box::new(store))
    }
}

#[async_trait]
impl CertStore for BoxedCertStore {
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

pub trait BoxedCertStoreExt {
    fn boxed(self) -> BoxedCertStore;
}

impl<C: CertStore + 'static> BoxedCertStoreExt for C {
    fn boxed(self) -> BoxedCertStore {
        BoxedCertStore::new(self)
    }
}

pub struct BoxedOrderStore(Box<dyn OrderStore>);

impl BoxedOrderStore {
    pub fn new(store: impl OrderStore + 'static) -> Self {
        Self(Box::new(store))
    }
}

#[async_trait]
impl OrderStore for BoxedOrderStore {
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

pub trait BoxedOrderStoreExt {
    fn boxed(self) -> BoxedOrderStore;
}

impl<C: OrderStore + 'static> BoxedOrderStoreExt for C {
    fn boxed(self) -> BoxedOrderStore {
        BoxedOrderStore::new(self)
    }
}

pub struct BoxedAccountStore(Box<dyn AccountStore>);

impl BoxedAccountStore {
    pub fn new(store: impl AccountStore + 'static) -> Self {
        Self(Box::new(store))
    }
}

pub trait BoxedAccountStoreExt {
    fn boxed(self) -> BoxedAccountStore;
}

impl<A: AccountStore + 'static> BoxedAccountStoreExt for A {
    fn boxed(self) -> BoxedAccountStore {
        BoxedAccountStore::new(self)
    }
}

#[async_trait]
impl AccountStore for BoxedAccountStore {
    async fn get_account(&self, domain: &str) -> io::Result<Option<PrivateKey>> {
        self.0.get_account(domain).await
    }

    async fn put_account(&self, domain: &str, key: PrivateKey) -> io::Result<()> {
        self.0.put_account(domain, key).await
    }
}

struct MapAuthChallengeStore<T, F> {
    inner: T,
    f: F,
}

#[async_trait]
impl<T, F, L> AuthChallengeStore for MapAuthChallengeStore<T, F>
where
    T: AuthChallengeStore,
    L: AuthChallengeDomainLock,
    F: Fn(T::LockGuard) -> L,
    F: Send + Sync,
{
    type LockGuard = L;

    async fn get_challenge(&self, domain: &str) -> io::Result<Option<String>> {
        self.inner.get_challenge(domain).await
    }

    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard> {
        let lock = self.inner.lock(domain).await?;
        Ok((self.f)(lock))
    }

    async fn unlock(&self, domain: &str) -> io::Result<()> {
        self.inner.unlock(domain).await
    }
}

pub struct BoxedAuthChallengeStore(
    Box<dyn AuthChallengeStore<LockGuard = BoxedAuthChallengeStoreGuard> + Send + Sync>,
);

impl BoxedAuthChallengeStore {
    pub fn new<T>(inner: T) -> Self
    where
        T: AuthChallengeStore + 'static,
    {
        let inner = MapAuthChallengeStore {
            inner,
            f: |lock| BoxedAuthChallengeStoreGuard(Box::new(lock)),
        };

        Self(Box::new(inner))
    }
}

#[async_trait]
impl AuthChallengeStore for BoxedAuthChallengeStore {
    type LockGuard = BoxedAuthChallengeStoreGuard;

    async fn get_challenge(&self, domain: &str) -> io::Result<Option<String>> {
        self.0.get_challenge(domain).await
    }

    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard> {
        self.0.lock(domain).await
    }

    async fn unlock(&self, domain: &str) -> io::Result<()> {
        self.0.unlock(domain).await
    }
}

pub trait BoxedAuthChallengeStoreExt {
    fn boxed(self) -> BoxedAuthChallengeStore;
}

impl<A: AuthChallengeStore + 'static> BoxedAuthChallengeStoreExt for A {
    fn boxed(self) -> BoxedAuthChallengeStore {
        BoxedAuthChallengeStore::new(self)
    }
}

pub struct BoxedAuthChallengeStoreGuard(Box<dyn AuthChallengeDomainLock + Send>);

#[async_trait]
impl AuthChallengeDomainLock for BoxedAuthChallengeStoreGuard {
    async fn put_challenge(&mut self, challenge: String) -> io::Result<()> {
        self.0.put_challenge(challenge).await
    }
}
