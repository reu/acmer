use std::{
    pin::{pin, Pin},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime},
};

use papaleguas::{AcmeClient, OrderStatus};
use rustls::{
    server::{Acceptor, WantsServerCert},
    Certificate, ConfigBuilder, PrivateKey, ServerConfig,
};
use rustls_pemfile as pemfile;
use sha2::{Digest, Sha256};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    task::JoinHandle,
};
use tokio_rustls::{server::TlsStream, LazyConfigAcceptor};
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream, StreamExt};
use tracing::{debug, error, trace};

use crate::store::{
    AccountStore, AuthChallengeDomainLock, AuthChallengeStore, CertStore, MemoryAccountStore,
    MemoryAuthChallengeStore, MemoryCertStore, MemoryOrderStore, Order, OrderStore,
};

pub use {builder::*, config::ConfigResolver, domain_check::DomainCheck};

mod builder;
mod config;
mod domain_check;

const ACME_ALPN: &[u8] = b"acme-tls/1";

pub struct AcmeAcceptor<S> {
    connections: UnboundedReceiverStream<io::Result<Connection<S>>>,
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

        #[allow(unreachable_code)]
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

                let task = tokio::spawn(async move {
                    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), conn);
                    let handshake = acceptor.await?;
                    let hello = handshake.client_hello();

                    let has_acme_tls = hello
                        .alpn()
                        .map(|mut alpn| alpn.any(|proto| proto == ACME_ALPN))
                        .unwrap_or(false);

                    let domain = hello.server_name().unwrap_or_default().to_owned();

                    if !domain_check.allow_domain(&domain) {
                        debug!(domain, "domain not allowed");
                        return io::Result::Ok(());
                    }

                    loop {
                        let mut cert = certs.get_cert(&domain).await?;

                        if has_acme_tls {
                            if let Some(auth) = auths.get_challenge(&domain).await? {
                                debug!(domain, "answering validation request");

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

                                debug!(domain, "answered validation request");
                                break;
                            } else {
                                debug!(domain, "validation request of unknown domain");
                            }
                        } else if let Some((key, cert)) = cert.take() {
                            let config = ruslts_config
                                .rustls_config(&domain, key, cert)
                                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

                            let conn = handshake.into_stream(Arc::new(config)).await?;

                            let conn = Connection { stream: conn };

                            trace!(domain, "connection established");

                            tx.send(Ok(conn)).ok();
                            break;
                        } else if auths.get_challenge(&domain).await?.is_none() {
                            trace!(domain = ?domain, "starting validation challenge");

                            let mut auth = match auths.lock(&domain).await {
                                Ok(lock) => lock,
                                Err(_) => {
                                    trace!(domain, "domain already being validated");
                                    tokio::time::sleep(Duration::from_secs(10)).await;
                                    continue;
                                }
                            };

                            let acme_account = {
                                let account_pk = accounts
                                    .get_account(acme_client.directory_url())
                                    .await?
                                    .and_then(|acc| papaleguas::PrivateKey::from_der(&acc.0).ok());

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
                                })
                            {
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
                                    let order = acme_account
                                        .new_order()
                                        .dns(&domain)
                                        .send()
                                        .await
                                        .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                                    orders.upsert_order(&domain, Order::from(&order)).await.ok();
                                    order
                                }
                            };

                            if order.status() == &OrderStatus::Pending {
                                let authorizations = order
                                    .authorizations()
                                    .await
                                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

                                let challenge = authorizations
                                    .iter()
                                    .find_map(|auth| auth.tls_alpn01_challenge())
                                    .ok_or(io::Error::new(
                                        io::ErrorKind::Other,
                                        format!(
                                            "tls alpn01 challenge not found for order {}",
                                            order.url()
                                        ),
                                    ))?;

                                let key_auth = challenge
                                    .key_authorization()
                                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

                                auth.put_challenge(key_auth).await?;

                                drop(auth);

                                challenge
                                    .validate()
                                    .await
                                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
                            } else {
                                trace!(domain, status = ?order.status(), order = order.url(), "domain already being challenged");
                                drop(auth);
                            }

                            let key = papaleguas::PrivateKey::random_ec_key(rand::thread_rng());
                            let cert = loop {
                                let order = acme_account
                                    .find_order(order.url())
                                    .await
                                    .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

                                orders.upsert_order(&domain, Order::from(&order)).await.ok();

                                trace!(domain, status = ?order.status(), order = order.url(), "acme order status");
                                match order.status() {
                                    OrderStatus::Pending | OrderStatus::Processing => {
                                        tokio::time::sleep(Duration::from_secs(3)).await;
                                    }
                                    OrderStatus::Ready => {
                                        order.finalize(&key).await.map_err(|err| {
                                            io::Error::new(io::ErrorKind::Other, err)
                                        })?;
                                    }
                                    OrderStatus::Valid => {
                                        break order.certificate().await.map_err(|err| {
                                            io::Error::new(io::ErrorKind::Other, err)
                                        })?;
                                    }
                                    OrderStatus::Invalid => {
                                        orders.remove_order(&domain, order.url()).await.ok();
                                        return Err(io::Error::new(
                                            io::ErrorKind::Other,
                                            format!("invalid order {}", order.url()),
                                        ));
                                    }
                                }
                            };

                            let key = key
                                .to_der()
                                .map(PrivateKey)
                                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

                            let cert = pemfile::read_all(&mut cert.as_bytes())?;
                            let cert = cert
                                .into_iter()
                                .filter_map(|item| match item {
                                    pemfile::Item::X509Certificate(der) => Some(der),
                                    _ => None,
                                })
                                .map(Certificate)
                                .collect::<Vec<Certificate>>();

                            certs.put_cert(&domain, key, cert).await?;

                            orders.remove_order(&domain, order.url()).await.ok();

                            continue;
                        }
                    }
                    Ok::<_, io::Error>(())
                });

                match task.await {
                    Ok(Err(error)) => error!(%error),
                    Err(error) => error!(%error),
                    _ => continue,
                }
            }
            Ok::<_, io::Error>(())
        });

        Self {
            connections: UnboundedReceiverStream::new(rx),
            task,
        }
    }

    pub async fn accept(&mut self) -> Option<io::Result<Connection<S>>> {
        self.next().await
    }
}

impl<S> Stream for AcmeAcceptor<S> {
    type Item = io::Result<Connection<S>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        pin!(&mut self.connections).poll_next(cx)
    }
}

pub struct Connection<S> {
    stream: TlsStream<S>,
}

impl<S> Connection<S> {
    pub fn sni(&self) -> &str {
        self.stream.get_ref().1.sni_hostname().unwrap_or_default()
    }

    pub fn into_inner(self) -> TlsStream<S> {
        self.stream
    }
}

impl<S> AsyncRead for Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        pin!(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        pin!(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        pin!(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        pin!(&mut self.stream).poll_shutdown(cx)
    }
}
