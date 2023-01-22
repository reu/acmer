use std::{env, error::Error, net::SocketAddr, sync::Arc};

use acmer::{
    acceptor::AcmeAcceptor,
    store::{
        AccountDynamodbStore, AccountFileStore, AuthChallengeDynamodbStore, BoxedAccountStoreExt,
        BoxedAuthChallengeStoreExt, BoxedCertStoreExt, CachedCertStoreExt, CertDynamodbStore,
        CertFileStore, MemoryAccountStore, MemoryAuthChallengeStore, MemoryCertStore,
    },
};
use hyper::{
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING},
    http::{uri::Scheme, HeaderValue},
    server, service, Uri,
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpSocket},
    try_join,
};
use tokio_stream::{Stream, StreamExt};

#[tokio::main]
#[allow(unreachable_code)]
async fn main() -> io::Result<()> {
    let https_port = env::var("PORT")
        .ok()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(4443);

    let acceptor = AcmeAcceptor::builder()
        .with_contact("rnavarro1+acmer-test@gmail.com")
        .with_account_store(if let Ok(table) = env::var("DYNAMO_ACCOUNT_STORE_TABLE") {
            let store = AccountDynamodbStore::from_env(table).await;
            store.create_table().await.unwrap();
            store.boxed()
        } else if let Ok(path) = env::var("ACCOUNT_STORE_PATH") {
            AccountFileStore::new(path).boxed()
        } else {
            MemoryAccountStore::default().boxed()
        })
        .with_cert_store(if let Ok(table) = env::var("DYNAMO_CERT_STORE_TABLE") {
            let store = CertDynamodbStore::from_env(table).await;
            store.create_table().await.unwrap();
            store.cached().boxed()
        } else if let Ok(path) = env::var("CERT_STORE_PATH") {
            CertFileStore::new(path).cached().boxed()
        } else {
            MemoryCertStore::default().boxed()
        })
        .with_auth_challenge_store(
            if let Ok(table_name) = env::var("DYNAMO_AUTH_CHALLENGE_TABLE") {
                let store = AuthChallengeDynamodbStore::from_env(table_name).await;
                store.create_table().await.unwrap();
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

async fn http_proxy<T>(proxy_uri: Uri, conns: impl Stream<Item = io::Result<T>>)
where
    T: 'static,
    T: Send + Unpin,
    T: io::AsyncRead + io::AsyncWrite,
{
    let authority = proxy_uri.authority().cloned();

    hyper::Server::builder(server::accept::from_stream(conns))
        .serve(service::make_service_fn(move |_| {
            let authority = authority.clone();
            let http = Arc::new(hyper::Client::new());
            let https_proto = HeaderValue::from_str("https").unwrap();

            async move {
                Ok::<_, Box<dyn Error + Send + Sync>>(service::service_fn(move |mut req| {
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
            let src = conn?;
            let dst = TcpSocket::new_v4()?.connect(addr).await?;

            let (mut src_reader, mut src_writer) = io::split(src);
            let (mut dst_reader, mut dst_writer) = io::split(dst);

            let client_to_server = async {
                let bytes = io::copy(&mut src_reader, &mut dst_writer).await?;
                dst_writer.shutdown().await?;
                io::Result::Ok(bytes)
            };

            let server_to_client = async {
                let bytes = io::copy(&mut dst_reader, &mut src_writer).await?;
                src_writer.shutdown().await?;
                io::Result::Ok(bytes)
            };

            try_join!(client_to_server, server_to_client)?;

            io::Result::Ok(())
        });
    }
}
