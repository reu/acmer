use std::{env, net::SocketAddr};

use acmer::{
    acceptor::AcmeAcceptor,
    store::{
        AccountDynamodbStore, AccountFileStore, AuthChallengeDynamodbStore, BoxedAccountStoreExt,
        BoxedAuthChallengeStoreExt, BoxedCertStoreExt, CachedCertStoreExt, CertDynamodbStore,
        CertExpirationTimeStoreExt, CertFileStore, MemoryAccountStore, MemoryAuthChallengeStore,
        MemoryCertStore,
    },
};
use tokio::{io, net::TcpListener};

#[cfg(feature = "http")]
mod http_proxy;
mod tcp_proxy;

#[tokio::main]
#[allow(unreachable_code)]
async fn main() -> io::Result<()> {
    let https_port = env::var("PORT")
        .ok()
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(443);

    let acme_email = env::var("ACME_EMAIL").expect("ACME_EMAIL is required");

    let acceptor = AcmeAcceptor::builder();

    let acceptor = match env::var("ACME_DIRECTORY") {
        Ok(dir) if dir == "staging" => acceptor.with_lets_encrypt_staging(),
        Ok(dir) => acceptor.with_directory_url(dir),
        _ => acceptor.with_lets_encrypt_staging(),
    };

    let acceptor = acceptor
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
        .build_from_tcp_listener(
            TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], https_port))).await?,
        )
        .await
        .unwrap();

    if let Ok(addr) = env::var("TCP_PROXY_ADDRESS") {
        let addr: SocketAddr = addr.parse().unwrap();
        tcp_proxy::proxy(addr, acceptor).await;
    } else if env::var("HTTP_PROXY_ADDRESS").is_ok() {
        if cfg!(feature = "http") {
            #[cfg(feature = "http")]
            http_proxy::proxy(env::var("HTTP_PROXY_ADDRESS").unwrap(), acceptor).await;
        } else {
            panic!("ACMER was not compiled with HTTP proxy support")
        }
    } else {
        panic!("No proxy address informed")
    }

    Ok(())
}
