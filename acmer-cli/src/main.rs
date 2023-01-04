use std::{env, error::Error, net::SocketAddr};

use acmer::{
    acceptor::AcmeAcceptor,
    store::{
        AccountDynamodbStore, AccountFileStore, AuthChallengeDynamodbStore, BoxAuthChallengeStore,
        BoxedAccountStoreExt, BoxedCertStoreExt, CachedCertStoreExt, CertDynamodbStore,
        CertFileStore, MemoryAccountStore, MemoryAuthChallengeStore, MemoryCertStore,
    },
};
use hyper::{server, service, Body, Response, StatusCode};
use tokio::{io, net::TcpListener};

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
            // store.create_table().await.unwrap();
            store.boxed()
        } else if let Ok(path) = env::var("ACCOUNT_STORE_PATH") {
            AccountFileStore::new(path).boxed()
        } else {
            MemoryAccountStore::default().boxed()
        })
        .with_cert_store(if let Ok(table) = env::var("DYNAMO_CERT_STORE_TABLE") {
            let store = CertDynamodbStore::from_env(table).await;
            // store.create_table().await.unwrap();
            store.cached().boxed()
        } else if let Ok(path) = env::var("CERT_STORE_PATH") {
            CertFileStore::new(path).cached().boxed()
        } else {
            MemoryCertStore::default().boxed()
        })
        .with_auth_challenge_store(
            if let Ok(table_name) = env::var("DYNAMO_AUTH_CHALLENGE_TABLE") {
                let store = AuthChallengeDynamodbStore::from_env(table_name).await;
                // store.create_table().await.unwrap();
                store.boxed()
            } else {
                MemoryAuthChallengeStore::default().boxed()
            },
        )
        .build_with_tcp_listener(
            TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], https_port))).await?,
        )
        .await;

    let connections = server::accept::from_stream(acceptor.into_stream());

    hyper::Server::builder(connections)
        .serve(service::make_service_fn(|_| async {
            Ok::<_, Box<dyn Error + Send + Sync>>(service::service_fn(|_req| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("Lol"))
            }))
        }))
        .await
        .unwrap();

    Ok(())
}
