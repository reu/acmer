use std::{
    collections::HashSet,
    error::Error,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use aws_sdk_dynamodb::{
    error::SdkError,
    operation::{create_table::CreateTableError, get_item::GetItemOutput},
    primitives::Blob,
    types::{
        AttributeDefinition, AttributeValue, BillingMode, ComparisonOperator, Condition,
        KeySchemaElement, KeyType, ScalarAttributeType, TableStatus, TimeToLiveSpecification,
    },
    Client,
};
use pem_rfc7468 as pem;
use rand::Rng;
use rustls_pki_types::pem::PemObject;
use serde_json as json;
use tokio::{io, time::sleep};

use super::{
    AccountStore, AuthChallenge, AuthChallengeDomainLock, AuthChallengeStore, CertStore,
    Certificate, Order, OrderStore, PrivateKey,
};

#[derive(Debug, Clone)]
struct DynamodbStore {
    client: Arc<Client>,
    table_name: String,
}

impl DynamodbStore {
    pub fn new(client: Client, table_name: String) -> Self {
        Self {
            client: Arc::new(client),
            table_name,
        }
    }

    pub async fn from_env(table_name: impl Into<String>) -> Self {
        let config = aws_config::load_from_env().await;
        Self::new(Client::new(&config), table_name.into())
    }

    pub async fn create_certs_table(&self) -> Result<(), SdkError<CreateTableError>> {
        self.client
            .create_table()
            .table_name(&self.table_name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hostname")
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hostname")
                    .attribute_type(ScalarAttributeType::S)
                    .build()?,
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .map(|_| ())
    }

    pub async fn create_accounts_table(&self) -> Result<(), SdkError<CreateTableError>> {
        self.client
            .create_table()
            .table_name(&self.table_name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("directory")
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("directory")
                    .attribute_type(ScalarAttributeType::S)
                    .build()?,
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .map(|_| ())
    }

    pub async fn create_orders_table(&self) -> Result<(), Box<dyn Error>> {
        self.client
            .create_table()
            .table_name(&self.table_name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hostname")
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("order_url")
                    .key_type(KeyType::Range)
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hostname")
                    .attribute_type(ScalarAttributeType::S)
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("order_url")
                    .attribute_type(ScalarAttributeType::S)
                    .build()?,
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await?;

        loop {
            sleep(Duration::from_secs(5)).await;

            let description = self
                .client
                .describe_table()
                .table_name(&self.table_name)
                .send()
                .await?;

            if let Some(table) = description.table() {
                match table.table_status() {
                    Some(TableStatus::Active) => break,
                    Some(TableStatus::Deleting) => return Err("Table is being deleted".into()),
                    _ => continue,
                }
            };
        }

        self.client
            .update_time_to_live()
            .table_name(&self.table_name)
            .time_to_live_specification(
                TimeToLiveSpecification::builder()
                    .attribute_name("ttl")
                    .enabled(true)
                    .build()?,
            )
            .send()
            .await?;

        Ok(())
    }

    pub async fn create_auth_challenges_table(&self) -> Result<(), Box<dyn Error>> {
        self.client
            .create_table()
            .table_name(&self.table_name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hostname")
                    .key_type(KeyType::Hash)
                    .build()?,
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hostname")
                    .attribute_type(ScalarAttributeType::S)
                    .build()?,
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await?;

        loop {
            sleep(Duration::from_secs(5)).await;

            let description = self
                .client
                .describe_table()
                .table_name(&self.table_name)
                .send()
                .await?;

            if let Some(table) = description.table() {
                match table.table_status() {
                    Some(TableStatus::Active) => break,
                    Some(TableStatus::Deleting) => return Err("Table is being deleted".into()),
                    _ => continue,
                }
            };
        }

        self.client
            .update_time_to_live()
            .table_name(&self.table_name)
            .time_to_live_specification(
                TimeToLiveSpecification::builder()
                    .attribute_name("ttl")
                    .enabled(true)
                    .build()?,
            )
            .send()
            .await?;

        Ok(())
    }
}

#[async_trait]
impl CertStore for DynamodbStore {
    async fn get_cert(&self, domain: &str) -> io::Result<Option<(PrivateKey, Vec<Certificate>)>> {
        let record = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .send()
            .await
            .map_err(io::Error::other)?;

        fn get_key(record: &GetItemOutput) -> Option<PrivateKey> {
            PrivateKey::try_from(
                record
                    .item()?
                    .get("pkey")?
                    .as_b()
                    .ok()
                    .cloned()?
                    .into_inner(),
            )
            .ok()
        }

        fn get_cert(record: &GetItemOutput) -> Option<&str> {
            Some(record.item()?.get("cert")?.as_s().ok()?)
        }

        match (get_key(&record), get_cert(&record)) {
            (Some(key), Some(cert)) => {
                let cert = Certificate::pem_slice_iter(cert.as_bytes())
                    .filter_map(|cert| cert.ok())
                    .collect();
                Ok(Some((key, cert)))
            }
            _ => Ok(None),
        }
    }

    async fn put_cert(
        &self,
        domain: &str,
        key: PrivateKey,
        cert: Vec<Certificate>,
    ) -> io::Result<()> {
        let cert = cert
            .into_iter()
            .map(|cert| pem::encode_string("CERTIFICATE", pem::LineEnding::default(), &cert))
            .collect::<Result<String, _>>()
            .map_err(|err| io::Error::other(err.to_string()))?;

        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(domain.to_string()))
            .item("pkey", AttributeValue::B(Blob::new(key.secret_der())))
            .item("cert", AttributeValue::S(cert))
            .send()
            .await
            .map_err(|err| io::Error::other(err.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl OrderStore for DynamodbStore {
    async fn list_orders(&self, domain: &str) -> io::Result<HashSet<Order>> {
        let orders = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_conditions(
                "hostname",
                Condition::builder()
                    .comparison_operator(ComparisonOperator::Eq)
                    .attribute_value_list(AttributeValue::S(domain.to_owned()))
                    .build()
                    .unwrap(),
            )
            .send()
            .await
            .map_err(io::Error::other)?
            .items()
            .iter()
            .filter_map(|item| json::from_str(item.get("order")?.as_s().ok()?).ok())
            .collect();
        Ok(orders)
    }

    async fn upsert_order(&self, domain: &str, order: Order) -> io::Result<()> {
        let req = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(domain.to_owned()))
            .item("order_url", AttributeValue::S(order.url.clone()))
            .item(
                "order",
                AttributeValue::S(json::to_string(&order).unwrap_or_default()),
            );

        let req = match order.expires {
            None => req,
            Some(time) => req.item("ttl", AttributeValue::N(time.unix_timestamp().to_string())),
        };

        req.send()
            .await
            .map_err(io::Error::other)?;

        Ok(())
    }

    async fn remove_order(&self, domain: &str, order_url: &str) -> io::Result<()> {
        self.client
            .delete_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .key("order_url", AttributeValue::S(order_url.to_string()))
            .send()
            .await
            .map_err(io::Error::other)?;
        Ok(())
    }
}

#[async_trait]
impl AccountStore for DynamodbStore {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        Ok(self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("directory", AttributeValue::S(directory.to_string()))
            .send()
            .await
            .map_err(io::Error::other)?
            .item()
            .and_then(|item| item.get("pkey")?.as_b().ok().cloned())
            .and_then(|key| PrivateKey::try_from(key.into_inner()).ok()))
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("directory", AttributeValue::S(directory.to_string()))
            .item("pkey", AttributeValue::B(Blob::new(key.secret_der())))
            .send()
            .await
            .map_err(io::Error::other)?;

        Ok(())
    }
}

#[async_trait]
impl AuthChallengeStore for DynamodbStore {
    type LockGuard = DynamodbAuthChallengeLock;

    async fn get_challenge(&self, domain: &str) -> io::Result<Option<AuthChallenge>> {
        Ok(self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .send()
            .await
            .map_err(io::Error::other)?
            .item()
            .and_then(|item| json::from_str(item.get("challenge")?.as_s().ok()?).ok()))
    }

    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard> {
        let lock_id = rand::thread_rng().gen::<[u8; 32]>();
        // TODO: make this configurable
        let ttl = Duration::from_secs(120);

        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(domain.to_string()))
            .item("lock_id", AttributeValue::B(Blob::new(lock_id)))
            .item(
                "ttl",
                AttributeValue::N(
                    (SystemTime::now() + ttl)
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_err(io::Error::other)?
                        .as_secs()
                        .to_string(),
                ),
            )
            .condition_expression(
                "attribute_not_exists(hostname) or (#ttl <> :null and #ttl < :now)",
            )
            .expression_attribute_names("#ttl", "ttl")
            .expression_attribute_values(":null", AttributeValue::Null(true))
            .expression_attribute_values(
                ":now",
                AttributeValue::N(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map_err(io::Error::other)?
                        .as_secs()
                        .to_string(),
                ),
            )
            .send()
            .await
            .map_err(io::Error::other)?;

        Ok(DynamodbAuthChallengeLock {
            client: self.client.clone(),
            table_name: self.table_name.clone(),
            domain: domain.to_owned(),
            lock_id,
            ttl,
        })
    }

    async fn unlock(&self, domain: &str) -> io::Result<()> {
        self.client
            .delete_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .send()
            .await
            .map_err(io::Error::other)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DynamodbAuthChallengeLock {
    client: Arc<Client>,
    table_name: String,
    domain: String,
    lock_id: [u8; 32],
    ttl: Duration,
}

#[async_trait]
impl AuthChallengeDomainLock for DynamodbAuthChallengeLock {
    async fn put_challenge(&mut self, challenge: AuthChallenge) -> io::Result<()> {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(self.domain.clone()))
            .item(
                "challenge",
                AttributeValue::S(json::to_string(&challenge).unwrap_or_default()),
            )
            .item("lock_id", AttributeValue::B(Blob::new(self.lock_id)))
            .item(
                "ttl",
                AttributeValue::N(
                    (SystemTime::now() + self.ttl)
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .to_string(),
                ),
            )
            .condition_expression("attribute_not_exists(hostname) or lock_id = :lock")
            .expression_attribute_values(":lock", AttributeValue::B(Blob::new(self.lock_id)))
            .send()
            .await
            .map_err(io::Error::other)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CertDynamodbStore(DynamodbStore);

impl CertDynamodbStore {
    pub fn new(client: Client, table_name: String) -> Self {
        Self(DynamodbStore::new(client, table_name))
    }

    pub async fn from_env(table_name: impl Into<String>) -> Self {
        Self(DynamodbStore::from_env(table_name).await)
    }

    pub async fn create_table(&self) -> Result<(), SdkError<CreateTableError>> {
        self.0.create_certs_table().await
    }
}

#[async_trait]
impl CertStore for CertDynamodbStore {
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

#[derive(Debug, Clone)]
pub struct OrderDynamodbStore(DynamodbStore);

impl OrderDynamodbStore {
    pub fn new(client: Client, table_name: String) -> Self {
        Self(DynamodbStore::new(client, table_name))
    }

    pub async fn from_env(table_name: impl Into<String>) -> Self {
        Self(DynamodbStore::from_env(table_name).await)
    }

    pub async fn create_table(&self) -> Result<(), Box<dyn Error>> {
        self.0.create_orders_table().await
    }
}

#[async_trait]
impl OrderStore for OrderDynamodbStore {
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

#[derive(Debug, Clone)]
pub struct AccountDynamodbStore(DynamodbStore);

impl AccountDynamodbStore {
    pub fn new(client: Client, table_name: String) -> Self {
        Self(DynamodbStore::new(client, table_name))
    }

    pub async fn from_env(table_name: impl Into<String>) -> Self {
        Self(DynamodbStore::from_env(table_name).await)
    }

    pub async fn create_table(&self) -> Result<(), SdkError<CreateTableError>> {
        self.0.create_accounts_table().await
    }
}

#[async_trait]
impl AccountStore for AccountDynamodbStore {
    async fn get_account(&self, directory: &str) -> io::Result<Option<PrivateKey>> {
        self.0.get_account(directory).await
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) -> io::Result<()> {
        self.0.put_account(directory, key).await
    }
}

#[derive(Debug, Clone)]
pub struct AuthChallengeDynamodbStore(DynamodbStore);

impl AuthChallengeDynamodbStore {
    pub fn new(client: Client, table_name: String) -> Self {
        Self(DynamodbStore::new(client, table_name))
    }

    pub async fn from_env(table_name: impl Into<String>) -> Self {
        Self(DynamodbStore::from_env(table_name).await)
    }

    pub async fn create_table(&self) -> Result<(), Box<dyn Error>> {
        self.0.create_auth_challenges_table().await
    }
}

#[async_trait]
impl AuthChallengeStore for AuthChallengeDynamodbStore {
    type LockGuard = DynamodbAuthChallengeLock;

    async fn get_challenge(&self, domain: &str) -> io::Result<Option<AuthChallenge>> {
        self.0.get_challenge(domain).await
    }

    async fn lock(&self, domain: &str) -> io::Result<Self::LockGuard> {
        self.0.lock(domain).await
    }

    async fn unlock(&self, domain: &str) -> io::Result<()> {
        self.0.unlock(domain).await
    }
}

#[cfg(test)]
mod test {
    use rand::distributions::{Alphanumeric, DistString};

    use crate::store::{BoxedAuthChallengeStoreExt, OrderStatus};

    use super::*;

    async fn create_dynamodb_client() -> Client {
        let creds = aws_credential_types::Credentials::from_keys(
            "XXXXXXXXXXXXXXXXXXXX",
            "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY",
            None,
        );

        let config = aws_sdk_dynamodb::Config::builder()
            .region(aws_config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .endpoint_url("http://localhost:8000")
            .behavior_version_latest()
            .build();

        let dynamo = Client::from_conf(config);

        if let Err(_err) = dynamo.list_tables().send().await {
            panic!("could not connect to dynamodb-local on http://localhost:8000");
        }

        dynamo
    }

    #[tokio::test]
    async fn test_dynamo_lock() {
        let dynamo = create_dynamodb_client().await;

        let table_name = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let store = AuthChallengeDynamodbStore::new(dynamo, table_name);

        store.create_table().await.unwrap();

        let store = store.boxed();

        let mut lock1 = store.lock("lol.wut").await.unwrap();
        assert!(store.lock("lol.wut").await.is_err());

        let mut lock2 = store.lock("wtf.wut").await.unwrap();
        assert!(&store.lock("wtf.wut").await.is_err());

        lock1
            .put_challenge(AuthChallenge::new().with_tls_alpn01("1"))
            .await
            .unwrap();
        lock2
            .put_challenge(
                AuthChallenge::new()
                    .with_http01("token", "challenge")
                    .with_tls_alpn01("tls"),
            )
            .await
            .unwrap();

        drop(lock1);
        assert_eq!(
            AuthChallengeStore::get_challenge(&store, "lol.wut")
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
            Some(("token", "challenge"))
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

        assert!(AuthChallengeStore::get_challenge(&store, "other.wut")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_order_dynamodb_store() {
        let dynamo = create_dynamodb_client().await;

        let table_name = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        let store = OrderDynamodbStore::new(dynamo, table_name);

        store.create_table().await.unwrap();

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
}
