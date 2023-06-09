use std::{error::Error, io::Cursor, sync::Arc};

use acmer::{
    store::{AccountStore, MemoryAccountStore},
    AcmeAcceptor,
};
use papaleguas::PrivateKey;
use rand::thread_rng;
use rustls::OwnedTrustAnchor;
use test_log::test;
use tokio::{
    fs,
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsConnector;

const DIRCTORY_URL: &'static str = "https://localhost:14000/dir";

async fn pebble_http_client() -> Result<reqwest::Client, Box<dyn Error>> {
    let cert = tokio::fs::read("./tests/pebble.minica.pem").await?;
    let cert = reqwest::Certificate::from_pem(&cert)?;
    let http = reqwest::Client::builder()
        .add_root_certificate(cert)
        .build()?;
    Ok(http)
}

#[test(tokio::test)]
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

#[test(tokio::test)]
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

#[test(tokio::test)]
async fn accept_certificate_test() -> Result<(), Box<dyn Error + Send + Sync>> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let addr = listener.local_addr().unwrap();

    let root_cert_store = {
        let mut root_cert_store = rustls::RootCertStore::empty();
        let pem = fs::read_to_string("./tests/pebble.minica.pem")
            .await
            .unwrap();
        let mut pem = Cursor::new(pem);
        let certs = rustls_pemfile::certs(&mut pem)?;
        let trust_anchors = certs.iter().map(|cert| {
            let ta = webpki::TrustAnchor::try_from_cert_der(&cert[..]).unwrap();
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        });
        root_cert_store.add_server_trust_anchors(trust_anchors);
        root_cert_store
    };

    let mut acceptor = AcmeAcceptor::builder()
        .with_directory_url(DIRCTORY_URL)
        .with_http_client(pebble_http_client().await.unwrap())
        .with_contact("test1@example.org")
        .with_contact("test2@example.org")
        .build_from_tcp_listener(listener)
        .await
        .unwrap();

    let connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(),
    ));

    let server = acceptor.accept();

    let client = async {
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let domain = rustls::ServerName::try_from("lol.acmer.org").unwrap();
        let _tls = connector.connect(domain, tcp).await.ok();
    };

    tokio::join!(server, client);

    Ok(())
}
