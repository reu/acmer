use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use papaleguas::{AcmeClient, OrderStatus};
use rustls::{server::Acceptor, Certificate, PrivateKey, ServerConfig};
use rustls_pemfile as pemfile;
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
};
use tokio_rustls::{server::TlsStream, LazyConfigAcceptor};
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};

use crate::store::{
    AccountStore, AuthChallengeDomainLock, AuthChallengeStore, CertStore, MemoryAccountStore,
    MemoryAuthChallengeStore, MemoryCertStore,
};

use self::builder::AcmeAcceptorBuilder;

mod builder;

const ACME_ALPN: &[u8] = b"acme-tls/1";

pub struct AcmeAcceptor {
    connections: UnboundedReceiverStream<io::Result<TlsStream<TcpStream>>>,
    task: JoinHandle<io::Result<()>>,
}

impl Drop for AcmeAcceptor {
    fn drop(&mut self) {
        self.task.abort()
    }
}

impl AcmeAcceptor {
    pub fn builder(
    ) -> AcmeAcceptorBuilder<MemoryAuthChallengeStore, MemoryCertStore, MemoryAccountStore> {
        AcmeAcceptorBuilder::default()
    }

    pub fn new(
        acme_client: AcmeClient,
        tcp: TcpListener,
        certs: impl CertStore + 'static,
        auths: impl AuthChallengeStore + 'static,
        accounts: impl AccountStore + 'static,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<io::Result<_>>();

        let certs = Arc::new(certs);
        let auths = Arc::new(auths);
        let accounts = Arc::new(accounts);

        #[allow(unreachable_code)]
        let task = tokio::spawn(async move {
            loop {
                let auths = auths.clone();
                let certs = certs.clone();
                let accounts = accounts.clone();
                let acme_client = acme_client.clone();

                let tx = tx.clone();

                let (tcp_stream, _) = tcp.accept().await?;

                tokio::spawn(async move {
                    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), tcp_stream);
                    let handshake = acceptor.await?;
                    let hello = handshake.client_hello();

                    let has_acme_tls = hello
                        .alpn()
                        .map(|mut alpn| alpn.any(|proto| proto == ACME_ALPN))
                        .unwrap_or(false);

                    let domain = hello.server_name().unwrap_or_default();

                    loop {
                        let mut cert = certs.get_cert(domain).await;

                        if has_acme_tls {
                            if let Some(auth) = auths.get_challenge(domain).await {
                                let auth = Sha256::new().chain_update(auth).finalize();

                                let cert = rcgen::Certificate::from_params({
                                    let domain = domain.to_owned();
                                    let mut params = rcgen::CertificateParams::new([domain]);
                                    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
                                    params.custom_extensions =
                                        vec![rcgen::CustomExtension::new_acme_identifier(&auth)];
                                    params
                                })
                                .unwrap();

                                let key = PrivateKey(cert.serialize_private_key_der());
                                let cert = Certificate(cert.serialize_der().unwrap());

                                let mut conn = handshake
                                    .into_stream(Arc::new({
                                        let mut config = ServerConfig::builder()
                                            .with_safe_defaults()
                                            .with_no_client_auth()
                                            .with_single_cert(vec![cert], key)
                                            .unwrap();
                                        config.alpn_protocols.push(ACME_ALPN.to_vec());
                                        config
                                    }))
                                    .await?;

                                conn.shutdown().await.ok();
                                break;
                            }
                        } else if let Some((key, cert)) = cert.take() {
                            let conn = handshake
                                .into_stream(Arc::new(
                                    ServerConfig::builder()
                                        .with_safe_defaults()
                                        .with_no_client_auth()
                                        .with_single_cert(cert, key)
                                        .unwrap(),
                                ))
                                .await?;

                            tx.send(Ok(conn)).ok();
                            break;
                        } else if auths.get_challenge(domain).await.is_none() {
                            let mut auth = match auths.lock(domain).await {
                                Ok(lock) => lock,
                                Err(_) => {
                                    tokio::time::sleep(Duration::from_secs(10)).await;
                                    continue;
                                }
                            };

                            let acme_account = accounts
                                .get_account(acme_client.directory_url())
                                .await
                                .unwrap();

                            let acme_account = acme_client
                                .existing_account_from_private_key(
                                    papaleguas::PrivateKey::from_der(&acme_account.0).unwrap(),
                                )
                                .await
                                .unwrap();

                            let order = acme_account.new_order().dns(domain).send().await.unwrap();

                            let authorizations = order.authorizations().await.unwrap();

                            let challenge = authorizations
                                .iter()
                                .find_map(|auth| auth.tls_alpn01_challenge())
                                .unwrap();

                            auth.put_challenge(challenge.key_authorization().unwrap())
                                .await;

                            drop(auth);

                            challenge.validate().await.unwrap();

                            let key = papaleguas::PrivateKey::random_ec_key(rand::thread_rng());
                            let cert = loop {
                                let order = acme_account.find_order(order.url()).await.unwrap();
                                match order.status() {
                                    OrderStatus::Pending | OrderStatus::Processing => {
                                        tokio::time::sleep(Duration::from_secs(3)).await;
                                    }
                                    OrderStatus::Ready => {
                                        order.finalize(&key).await.unwrap();
                                    }
                                    OrderStatus::Valid => break order.certificate().await.unwrap(),
                                    OrderStatus::Invalid => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::Other,
                                            "Invalid order",
                                        ))
                                    }
                                }
                            };

                            let key = key.to_der().unwrap();
                            let key = PrivateKey(key);

                            let cert = pemfile::read_all(&mut std::io::Cursor::new(cert))?;
                            let cert = cert
                                .into_iter()
                                .filter_map(|item| match item {
                                    pemfile::Item::X509Certificate(der) => Some(der),
                                    _ => None,
                                })
                                .map(Certificate)
                                .collect::<Vec<Certificate>>();

                            certs.put_cert(domain, key, cert).await;

                            continue;
                        }
                    }
                    Ok::<_, io::Error>(())
                });
            }
            Ok::<_, io::Error>(())
        });

        Self {
            connections: UnboundedReceiverStream::new(rx),
            task,
        }
    }
}

impl Stream for AcmeAcceptor {
    type Item = io::Result<TlsStream<TcpStream>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.connections).poll_next(cx)
    }
}
