use std::{
    error::Error,
    sync::Arc,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use aws_sdk_dynamodb::{
    error::CreateTableError,
    model::{
        AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType,
        ScalarAttributeType, TableStatus, TimeToLiveSpecification,
    },
    types::{Blob, SdkError},
    Client,
};
use pem_rfc7468 as pem;
use rand::Rng;
use rustls::{Certificate, PrivateKey};
use rustls_pemfile as pemfile;
use tokio::time::sleep;

use super::{
    AccountStore, AuthChallengeDomainLock, AuthChallengeStore, AuthChallengeStoreLockError,
    CertStore,
};

#[derive(Debug)]
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
                    .build(),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hostname")
                    .attribute_type(ScalarAttributeType::S)
                    .build(),
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
                    .build(),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("directory")
                    .attribute_type(ScalarAttributeType::S)
                    .build(),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .map(|_| ())
    }

    pub async fn create_auth_challenges_table(&self) -> Result<(), Box<dyn Error>> {
        self.client
            .create_table()
            .table_name(&self.table_name)
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name("hostname")
                    .key_type(KeyType::Hash)
                    .build(),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name("hostname")
                    .attribute_type(ScalarAttributeType::S)
                    .build(),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await?;

        loop {
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
                    _ => {}
                }
            };

            sleep(Duration::from_secs(5)).await;
        }

        self.client
            .update_time_to_live()
            .table_name(&self.table_name)
            .time_to_live_specification(
                TimeToLiveSpecification::builder()
                    .attribute_name("ttl")
                    .enabled(true)
                    .build(),
            )
            .send()
            .await?;

        Ok(())
    }
}

#[async_trait]
impl CertStore for DynamodbStore {
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        let record = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .send()
            .await
            .ok()?;

        let key = record
            .item()?
            .get("pkey")?
            .as_b()
            .ok()
            .cloned()?
            .into_inner();

        let cert = record.item()?.get("cert")?.as_s().ok()?;

        let cert = pemfile::read_all(&mut std::io::Cursor::new(cert))
            .ok()?
            .into_iter()
            .filter_map(|item| match item {
                pemfile::Item::X509Certificate(der) => Some(der),
                _ => None,
            })
            .map(Certificate)
            .collect::<Vec<Certificate>>();

        Some((PrivateKey(key), cert))
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        let cert = cert
            .into_iter()
            .map(|cert| pem::encode_string("CERTIFICATE", pem::LineEnding::default(), &cert.0))
            .collect::<Result<String, _>>()
            .unwrap();

        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(domain.to_string()))
            .item("pkey", AttributeValue::B(Blob::new(key.0)))
            .item("cert", AttributeValue::S(cert))
            .send()
            .await
            .unwrap();
    }
}

#[async_trait]
impl AccountStore for DynamodbStore {
    async fn get_account(&self, directory: &str) -> Option<PrivateKey> {
        self.client
            .get_item()
            .table_name(&self.table_name)
            .key("directory", AttributeValue::S(directory.to_string()))
            .send()
            .await
            .ok()?
            .item()?
            .get("pkey")?
            .as_b()
            .ok()
            .cloned()
            .map(|key| PrivateKey(key.into_inner()))
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("directory", AttributeValue::S(directory.to_string()))
            .item("pkey", AttributeValue::B(Blob::new(key.0)))
            .send()
            .await
            .unwrap();
    }
}

#[async_trait]
impl AuthChallengeStore for DynamodbStore {
    type LockGuard = DynamodbAuthChallengeLock;

    async fn get_challenge(&self, domain: &str) -> Option<String> {
        self.client
            .get_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .send()
            .await
            .ok()?
            .item()?
            .get("challenge")?
            .as_s()
            .ok()
            .cloned()
    }

    async fn lock(&self, domain: &str) -> Result<Self::LockGuard, AuthChallengeStoreLockError> {
        let lock_id = rand::thread_rng().gen::<[u8; 32]>();

        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(domain.to_string()))
            .item("lock_id", AttributeValue::B(Blob::new(lock_id)))
            .item(
                "ttl",
                AttributeValue::N(
                    (SystemTime::now() + Duration::from_secs(120))
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        .to_string(),
                ),
            )
            .condition_expression("attribute_not_exists(hostname)")
            .send()
            .await
            .map_err(|_| AuthChallengeStoreLockError)?;

        Ok(DynamodbAuthChallengeLock {
            client: self.client.clone(),
            table_name: self.table_name.clone(),
            domain: domain.to_owned(),
            lock_id,
        })
    }

    async fn unlock(&self, domain: &str) {
        self.client
            .delete_item()
            .table_name(&self.table_name)
            .key("hostname", AttributeValue::S(domain.to_string()))
            .send()
            .await
            .unwrap();
    }
}

#[derive(Debug)]
pub struct DynamodbAuthChallengeLock {
    client: Arc<Client>,
    table_name: String,
    domain: String,
    lock_id: [u8; 32],
}

#[async_trait]
impl AuthChallengeDomainLock for DynamodbAuthChallengeLock {
    async fn put_challenge(&mut self, challenge: String) {
        self.client
            .put_item()
            .table_name(&self.table_name)
            .item("hostname", AttributeValue::S(self.domain.clone()))
            .item("challenge", AttributeValue::S(challenge))
            .item("lock_id", AttributeValue::B(Blob::new(self.lock_id)))
            .item(
                "ttl",
                AttributeValue::N(
                    (SystemTime::now() + Duration::from_secs(120))
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
            .unwrap();
    }
}

#[derive(Debug)]
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
    async fn get_cert(&self, domain: &str) -> Option<(PrivateKey, Vec<Certificate>)> {
        self.0.get_cert(domain).await
    }

    async fn put_cert(&self, domain: &str, key: PrivateKey, cert: Vec<Certificate>) {
        self.0.put_cert(domain, key, cert).await
    }
}

#[derive(Debug)]
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
    async fn get_account(&self, directory: &str) -> Option<PrivateKey> {
        self.0.get_account(directory).await
    }

    async fn put_account(&self, directory: &str, key: PrivateKey) {
        self.0.put_account(directory, key).await
    }
}

#[derive(Debug)]
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

    async fn get_challenge(&self, domain: &str) -> Option<String> {
        self.0.get_challenge(domain).await
    }

    async fn lock(&self, domain: &str) -> Result<Self::LockGuard, AuthChallengeStoreLockError> {
        self.0.lock(domain).await
    }

    async fn unlock(&self, domain: &str) {
        self.0.unlock(domain).await
    }
}

#[cfg(test)]
mod test {
    use aws_sdk_dynamodb::{Config, Endpoint, Region};
    use rand::distributions::{Alphanumeric, DistString};

    use crate::store::{BoxxedTest, BoxAuthChallengeStore};

    use super::*;

    #[tokio::test]
    async fn test_dynamo_lock() {
        let creds = aws_types::Credentials::from_keys(
            "AKIA4KHOLBWFWHAVUKYX",
            "tmbEKq94+A9GuHrRfmb/k5v5HpgMsYwkv6DssrVD",
            None,
        );

        let config = Config::builder()
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .endpoint_resolver(Endpoint::immutable("http://localhost:8000").unwrap())
            .build();

        let dynamo = Client::from_conf(config);

        let table_name = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);

        let store = AuthChallengeDynamodbStore::new(dynamo, table_name);

        store.create_table().await.unwrap();

        let store = store.boxed();

        // let store = BoxxedTest::new(store);

        let mut lock1 = store.lock("lol.wut").await.unwrap();
        assert!(store.lock("lol.wut").await.is_err());

        let mut lock2 = store.lock("wtf.wut").await.unwrap();
        assert!(&store.lock("wtf.wut").await.is_err());

        lock1.put_challenge("1".to_string()).await;
        lock2.put_challenge("2".to_string()).await;

        drop(lock1);
        assert_eq!(
            AuthChallengeStore::get_challenge(&store, "lol.wut")
                .await
                .unwrap(),
            "1"
        );

        drop(lock2);
        assert_eq!(
            AuthChallengeStore::get_challenge(&store, "wtf.wut")
                .await
                .unwrap(),
            "2"
        );

        assert!(AuthChallengeStore::get_challenge(&store, "other.wut")
            .await
            .is_none());
    }
}
