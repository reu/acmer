use std::{
    pin::{pin, Pin},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use papaleguas::{AcmeClient, OrderStatus};
use rustls::{
    server::{Acceptor, WantsServerCert},
    ConfigBuilder, ServerConfig,
};
use rustls_pki_types::pem::PemObject;
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
};
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream, StreamExt};
use tracing::{debug, error, trace};

use crate::store::{
    AccountStore, AuthChallenge, AuthChallengeDomainLock, AuthChallengeStore, CertStore,
    Certificate, MemoryAccountStore, MemoryAuthChallengeStore, MemoryCertStore, MemoryOrderStore,
    Order, OrderStore, PrivateKey,
};

pub use tokio_rustls::server::TlsStream;
pub use {builder::*, config::ConfigResolver, domain_check::DomainCheck};

mod builder;
mod config;
mod domain_check;

const ACME_ALPN: &[u8] = b"acme-tls/1";

pub struct AcmeAcceptor<S> {
    connections: UnboundedReceiverStream<io::Result<TlsStream<S>>>,
    task: JoinHandle<io::Result<()>>,
}

impl<S> Drop for AcmeAcceptor<S> {
    fn drop(&mut self) {
        self.task.abort()
    }
}

impl AcmeAcceptor<TcpStream> {
    pub fn builder() -> AcmeAcceptorBuilder<
        MemoryAuthChallengeStore,
        MemoryCertStore,
        MemoryOrderStore,
        MemoryAccountStore,
        bool,
        ConfigBuilder<ServerConfig, WantsServerCert>,
    > {
        AcmeAcceptorBuilder::default()
    }
}

impl<S> AcmeAcceptor<S> {
    #[allow(clippy::too_many_arguments)]
    fn start<L>(
        acme_client: AcmeClient,
        mut incoming: L,
        certs: impl CertStore + 'static,
        orders: impl OrderStore + 'static,
        auths: impl AuthChallengeStore + 'static,
        accounts: impl AccountStore + 'static,
        domain_check: impl DomainCheck + 'static,
        ruslts_config: impl ConfigResolver + 'static,
        http_challenge: bool,
    ) -> Self
    where
        L: Stream<Item = io::Result<S>>,
        L: Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, rx) = mpsc::unbounded_channel::<io::Result<_>>();

        let certs = Arc::new(certs);
        let orders = Arc::new(orders);
        let auths = Arc::new(auths);
        let accounts = Arc::new(accounts);
        let domain_check = Arc::new(domain_check);
        let ruslts_config = Arc::new(ruslts_config);

        let task = tokio::spawn(async move {
            loop {
                let tx = tx.clone();

                let conn = match incoming.next().await {
                    Some(Ok(stream)) => stream,
                    Some(Err(err)) => {
                        tx.send(Err(err)).ok();
                        continue;
                    }
                    None => break,
                };

                let certs = certs.clone();
                let orders = orders.clone();
                let auths = auths.clone();
                let accounts = accounts.clone();
                let acme_client = acme_client.clone();
                let domain_check = domain_check.clone();
                let ruslts_config = ruslts_config.clone();

                tokio::spawn(async move {
                    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), conn);

                    trace!("starting handshake");
                    let Ok(handshake) = acceptor.await else {
                        trace!("handlshake cancelled");
                        return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                    };
                    let hello = handshake.client_hello();

                    trace!("handshake started");

                    let has_acme_tls = hello
                        .alpn()
                        .map(|mut alpn| alpn.any(|proto| proto == ACME_ALPN))
                        .unwrap_or(false);

                    let domain = hello.server_name().unwrap_or_default().to_owned();
                    trace!(domain, "tls sni");

                    if !domain_check.allow_domain(&domain) {
                        debug!(domain, "domain not allowed");
                        return Ok(());
                    }

                    loop {
                        let mut cert = certs.get_cert(&domain).await?;

                        if has_acme_tls {
                            debug!(domain, "tls-alpn-01 validation received");

                            if let Some(auth) = auths
                                .get_challenge(&domain)
                                .await?
                                .and_then(|c| c.tls_alpn01_challenge().map(|c| c.to_owned()))
                            {
                                debug!(domain, "tls-alpn-01 answering validation request");

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

                                trace!(domain, "tls-alpn-01 certificate generated");

                                let key = PrivateKey::try_from(cert.serialize_private_key_der())?;
                                let cert = Certificate::from(cert.serialize_der().unwrap());

                                trace!(domain, "finishing tls-alpn-01 handshake");
                                let mut conn = handshake
                                    .into_stream(Arc::new({
                                        let mut config = ServerConfig::builder()
                                            .with_no_client_auth()
                                            .with_single_cert(vec![cert], key)
                                            .unwrap();
                                        config.alpn_protocols.push(ACME_ALPN.to_vec());
                                        config
                                    }))
                                    .await?;

                                trace!(domain, "closing tls-alpn-01 connection");
                                conn.shutdown().await.ok();

                                debug!(domain, "tls-alpn-01 answered validation request");
                                break;
                            } else {
                                debug!(domain, "tls-alpn-01 validation request of unknown domain");
                            }
                        } else if let Some((key, cert)) = cert.take() {
                            trace!(domain, "establishing connection");

                            let config = ruslts_config.rustls_config(&domain, key, cert)?;

                            match handshake.into_stream(Arc::new(config)).await {
                                Ok(conn) => {
                                    trace!(domain, "connection established");
                                    tx.send(Ok(conn)).ok();
                                }
                                Err(error) => {
                                    error!(domain, %error, "failed to establish connection");
                                    return Err(error)?;
                                }
                            }

                            break;
                        } else if auths.get_challenge(&domain).await?.is_none() {
                            debug!(domain = ?domain, "starting validation challenge");

                            let mut auth = match auths.lock(&domain).await {
                                Ok(lock) => lock,
                                Err(_) => {
                                    debug!(domain, "domain already being validated");
                                    tokio::time::sleep(Duration::from_secs(10)).await;
                                    continue;
                                }
                            };

                            let acme_account = {
                                let account_pk = accounts
                                    .get_account(acme_client.directory_url())
                                    .await?
                                    .and_then(|acc| {
                                        papaleguas::PrivateKey::from_der(acc.secret_der()).ok()
                                    });

                                let account = match account_pk {
                                    Some(pk) => {
                                        acme_client.existing_account_from_private_key(pk).await
                                    }
                                    None => {
                                        error!(domain, "account private key not found");
                                        break;
                                    }
                                };

                                match account {
                                    Ok(acc) => acc,
                                    Err(err) => {
                                        error!(domain, error = ?err, "account not found");
                                        break;
                                    }
                                }
                            };

                            let existing_orders =
                                orders.list_orders(&domain).await.unwrap_or_default();

                            let existing_order = if let Some(order) = existing_orders
                                .into_iter()
                                .filter(|order| order.status != OrderStatus::Invalid)
                                .find(|order| match order.expires {
                                    Some(exp) => exp > SystemTime::now(),
                                    _ => true,
                                }) {
                                match acme_account.find_order(&order.url).await {
                                    Ok(order) => Some(order),
                                    Err(_) => {
                                        orders.remove_order(&domain, &order.url).await.ok();
                                        None
                                    }
                                }
                            } else {
                                None
                            };

                            let order = match existing_order {
                                Some(order) => order,
                                None => {
                                    let order =
                                        acme_account.new_order().dns(&domain).send().await?;
                                    orders.upsert_order(&domain, Order::from(&order)).await.ok();
                                    order
                                }
                            };

                            if order.status() == &OrderStatus::Pending {
                                let authorizations = order.authorizations().await?;

                                let mut auth_challenge = AuthChallenge::new();

                                if let Some(challenge) = authorizations
                                    .iter()
                                    .find_map(|auth| auth.tls_alpn01_challenge())
                                {
                                    let key_auth = challenge.key_authorization()?;
                                    auth_challenge.add_tls_alpn01(key_auth);
                                };

                                if http_challenge {
                                    if let Some(challenge) = authorizations
                                        .iter()
                                        .find_map(|auth| auth.http01_challenge())
                                    {
                                        let key_auth = challenge.key_authorization()?;
                                        auth_challenge.add_http01(challenge.token(), key_auth);
                                    };
                                }

                                if auth_challenge.is_empty() {
                                    let err =
                                        format!("no available challenge for order {}", order.url());
                                    return Err(err.into());
                                }

                                auth.put_challenge(auth_challenge).await?;

                                drop(auth);

                                trace!(domain, "ready to validate challenge");

                                if let Some(challenge) = authorizations
                                    .iter()
                                    .find_map(|auth| auth.tls_alpn01_challenge())
                                {
                                    challenge.validate().await?;
                                };

                                if http_challenge {
                                    if let Some(challenge) = authorizations
                                        .iter()
                                        .find_map(|auth| auth.http01_challenge())
                                    {
                                        challenge.validate().await?;
                                    };
                                }
                            } else {
                                trace!(domain, status = ?order.status(), order = order.url(), "domain already being challenged");
                                drop(auth);
                            }

                            let key = papaleguas::PrivateKey::random_ec_key(rand::thread_rng());
                            let cert = loop {
                                let order = acme_account.find_order(order.url()).await?;

                                orders.upsert_order(&domain, Order::from(&order)).await.ok();

                                debug!(domain, status = ?order.status(), order = order.url(), "acme order status");
                                match order.status() {
                                    OrderStatus::Pending | OrderStatus::Processing => {
                                        tokio::time::sleep(Duration::from_secs(3)).await;
                                    }
                                    OrderStatus::Ready => {
                                        order.finalize(&key).await?;
                                    }
                                    OrderStatus::Valid => {
                                        break order.certificate().await?;
                                    }
                                    OrderStatus::Invalid => {
                                        orders.remove_order(&domain, order.url()).await.ok();
                                        let err = format!("invalid order {}", order.url());
                                        return Err(err.into());
                                    }
                                }
                            };

                            let key = PrivateKey::try_from(key.to_der()?)?;

                            let cert = Certificate::pem_slice_iter(cert.as_bytes())
                                .filter_map(|cert| cert.ok())
                                .collect::<Vec<Certificate>>();

                            certs.put_cert(&domain, key, cert).await?;
                            debug!(domain = ?domain, "certificate generated");

                            orders.remove_order(&domain, order.url()).await.ok();
                        }
                    }
                    Ok(())
                });
            }
            Ok::<_, io::Error>(())
        });

        Self {
            connections: UnboundedReceiverStream::new(rx),
            task,
        }
    }

    pub async fn accept(&mut self) -> Option<io::Result<TlsStream<S>>> {
        self.next().await
    }
}

impl<S> Stream for AcmeAcceptor<S> {
    type Item = io::Result<TlsStream<S>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        pin!(&mut self.connections).poll_next(cx)
    }
}
