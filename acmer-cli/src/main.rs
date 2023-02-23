use std::{env, error::Error, net::SocketAddr, sync::Arc};

use acmer::{
    acceptor::{AcmeAcceptor, Connection},
    store::{
        AccountDynamodbStore, AccountFileStore, AuthChallengeDynamodbStore, BoxedAccountStoreExt,
        BoxedAuthChallengeStoreExt, BoxedCertStoreExt, CachedCertStoreExt, CertDynamodbStore,
        CertExpirationTimeStoreExt, CertFileStore, MemoryAccountStore, MemoryAuthChallengeStore,
        MemoryCertStore,
    },
};
use hyper::{
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING},
    http::{uri::Scheme, HeaderValue},
    server, service, Uri,
};
use tokio::{
    io,
    net::{TcpListener, TcpStream},
};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
#[allow(unreachable_code)]
async fn main() -> io::Result<()> {
    let https_port = env::var("PORT")
        .ok()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(4443);

    let acme_email = env::var("ACME_EMAIL").expect("ACME_EMAIL is required");

    let acceptor = AcmeAcceptor::builder()
        .with_contact(acme_email)
        .with_account_store(if let Ok(table) = env::var("DYNAMO_ACCOUNT_STORE_TABLE") {
            let store = AccountDynamodbStore::from_env(table).await;
            store.create_table().await.ok();
            store.boxed()
        } else if let Ok(path) = env::var("ACCOUNT_STORE_PATH") {
            AccountFileStore::new(path).boxed()
        } else {
            MemoryAccountStore::default().boxed()
        })
        .with_cert_store(if let Ok(table) = env::var("DYNAMO_CERT_STORE_TABLE") {
            let store = CertDynamodbStore::from_env(table).await;
            store.create_table().await.ok();
            store.cached().with_validity_check().boxed()
        } else if let Ok(path) = env::var("CERT_STORE_PATH") {
            CertFileStore::new(path)
                .cached()
                .with_validity_check()
                .boxed()
        } else {
            MemoryCertStore::default().with_validity_check().boxed()
        })
        .with_auth_challenge_store(
            if let Ok(table_name) = env::var("DYNAMO_AUTH_CHALLENGE_TABLE") {
                let store = AuthChallengeDynamodbStore::from_env(table_name).await;
                store.create_table().await.ok();
                store.boxed()
            } else {
                MemoryAuthChallengeStore::default().boxed()
            },
        )
        .build_with_tcp_listener(
            TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], https_port))).await?,
        )
        .await;

    if let Ok(addr) = env::var("TCP_PROXY_ADDRESS") {
        let addr: SocketAddr = addr.parse().unwrap();
        tcp_proxy(addr, acceptor).await;
    } else if let Ok(uri) = env::var("HTTP_PROXY_ADDRESS") {
        let uri: Uri = uri.parse().unwrap();
        http_proxy(uri, acceptor).await;
    }

    Ok(())
}

async fn http_proxy<T>(proxy_uri: Uri, conns: impl Stream<Item = io::Result<Connection<T>>>)
where
    T: 'static,
    T: Send + Unpin,
    T: io::AsyncRead + io::AsyncWrite,
{
    let authority = proxy_uri.authority().cloned();

    hyper::Server::builder(server::accept::from_stream(conns))
        .serve(service::make_service_fn(move |conn: &Connection<_>| {
            let sni = Arc::new(conn.sni().to_owned());
            let authority = authority.clone();
            let http = Arc::new(hyper::Client::new());
            let https_proto = HeaderValue::from_str("https").unwrap();

            async move {
                Ok::<_, Box<dyn Error + Send + Sync>>(service::service_fn(move |mut req| {
                    let sni = sni.clone();
                    let http = http.clone();
                    let authority = authority.clone();
                    let https_proto = https_proto.clone();

                    async move {
                        let http = http.clone();

                        for key in &[
                            CONTENT_LENGTH,
                            TRANSFER_ENCODING,
                            ACCEPT_ENCODING,
                            CONTENT_ENCODING,
                        ] {
                            req.headers_mut().remove(key);
                        }

                        if req.uri().host() != Some(&sni) {
                            return Err("Host doesn´t match SNI".into());
                        }

                        if let Some(host) = req
                            .uri()
                            .host()
                            .and_then(|host| HeaderValue::from_str(host).ok())
                        {
                            req.headers_mut().insert("x-forwarded-host", host);
                        }

                        req.headers_mut().insert("x-forwarded-proto", https_proto);

                        let mut parts = req.uri().clone().into_parts();
                        parts.scheme = Some(Scheme::HTTP);
                        parts.authority = authority;
                        *req.uri_mut() = Uri::from_parts(parts)?;

                        Ok::<_, Box<dyn Error + Send + Sync>>(http.request(req).await?)
                    }
                }))
            }
        }))
        .await
        .unwrap();
}

async fn tcp_proxy<T>(addr: SocketAddr, mut connections: impl Stream<Item = io::Result<T>> + Unpin)
where
    T: 'static,
    T: Send + Unpin,
    T: io::AsyncRead + io::AsyncWrite,
{
    while let Some(conn) = connections.next().await {
        tokio::spawn(async move {
            let mut src = conn?;
            let mut dst = TcpStream::connect(addr).await?;
            io::copy_bidirectional(&mut src, &mut dst).await?;
            io::Result::Ok(())
        });
    }
}
