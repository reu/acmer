use std::error::Error;

use acmer::{
    store::{AccountStore, MemoryAccountStore},
    AcmeAcceptor,
};
use papaleguas::PrivateKey;
use rand::thread_rng;
use tokio::net::TcpListener;
use tracing_test::traced_test;

const DIRCTORY_URL: &'static str = "https://localhost:14000/dir";

async fn pebble_http_client() -> Result<reqwest::Client, Box<dyn Error>> {
    let cert = tokio::fs::read("./tests/pebble.minica.pem").await?;
    let cert = reqwest::Certificate::from_pem(&cert)?;
    let http = reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()?;
    Ok(http)
}

#[tokio::test]
#[traced_test]
async fn create_account_with_auto_generated_key_test() -> Result<(), Box<dyn Error + Send + Sync>> {
    let account_repo = MemoryAccountStore::default();

    AcmeAcceptor::builder()
        .with_directory_url(DIRCTORY_URL)
        .with_http_client(pebble_http_client().await.unwrap())
        .with_contact("test1@example.org")
        .with_contact("test2@example.org")
        .with_account_store(account_repo.clone())
        .build_from_tcp_listener(TcpListener::bind("0.0.0.0:0").await?)
        .await
        .unwrap();

    let account = account_repo.get_account(DIRCTORY_URL).await.unwrap();

    assert!(!account.is_none());

    Ok(())
}

#[tokio::test]
#[traced_test]
async fn create_account_with_key_test() -> Result<(), Box<dyn Error + Send + Sync>> {
    let key = PrivateKey::random_ec_key(thread_rng());

    AcmeAcceptor::builder()
        .with_directory_url(DIRCTORY_URL)
        .with_http_client(pebble_http_client().await.unwrap())
        .with_account_pem_key(key.to_pem().unwrap())
        .with_contact("test1@example.org")
        .with_contact("test2@example.org")
        .build_from_tcp_listener(TcpListener::bind("0.0.0.0:0").await?)
        .await
        .unwrap();

    Ok(())
}
