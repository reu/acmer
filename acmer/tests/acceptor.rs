use std::{error::Error, sync::Arc};

use acmer::{
    store::{AccountStore, MemoryAccountStore},
    AcmeAcceptor,
};
use papaleguas::{AcmeClient, PrivateKey};
use rand::thread_rng;
use rustls::client::danger::ServerCertVerifier;
use rustls_pki_types::ServerName;
use test_log::test;
use tokio::net::{TcpListener, TcpStream};
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
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

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
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

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
async fn acceptor_with_created_account_test() -> Result<(), Box<dyn Error + Send + Sync>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let key = PrivateKey::random_ec_key(thread_rng());

    let acme = AcmeClient::builder()
        .http_client(pebble_http_client().await.unwrap())
        .build_with_directory_url(DIRCTORY_URL)
        .await
        .unwrap();

    acme.new_account()
        .contact("test@example.org")
        .private_key(key.clone())
        .terms_of_service_agreed(true)
        .send()
        .await
        .unwrap();

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
    #[derive(Debug)]
    struct NoCa;

    impl ServerCertVerifier for NoCa {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls_pki_types::CertificateDer<'_>,
            _intermediates: &[rustls_pki_types::CertificateDer<'_>],
            _server_name: &rustls_pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls_pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::ED448,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            ]
        }
    }

    let listener = TcpListener::bind("0.0.0.0:0").await?;
    let addr = listener.local_addr().unwrap();

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
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCa))
            .with_no_client_auth(),
    ));

    let server = acceptor.accept();

    let client = async {
        let tcp = TcpStream::connect(&addr).await.unwrap();
        let domain = ServerName::try_from("lol.acmer.org").unwrap();
        let _tls = connector.connect(domain, tcp).await.ok();
    };

    tokio::join!(server, client);

    Ok(())
}
