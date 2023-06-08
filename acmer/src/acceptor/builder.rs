use papaleguas::AcmeClient;
use rustls::{server::WantsServerCert, ConfigBuilder, PrivateKey, ServerConfig};
use rustls_pemfile as pemfile;
use thiserror::Error;
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream, UnixListener, UnixStream},
};
use tokio_stream::{
    wrappers::{TcpListenerStream, UnixListenerStream},
    Stream,
};

use crate::store::{
    AccountStore, AuthChallengeStore, BoxedAccountStoreExt, CertStore, MemoryAccountStore,
    MemoryAuthChallengeStore, MemoryCertStore, SingleAccountStore,
};

use super::{config::ConfigResolver, domain_check::DomainCheck, AcmeAcceptor};

pub struct AcmeAcceptorBuilder<Auth, Cert, Acc, Domain, Config> {
    http_client: reqwest::Client,
    acme_directory: String,
    account_pk: Option<AccountKey>,
    contacts: Option<Vec<String>>,
    challenge_store: Auth,
    cert_store: Cert,
    account_store: Acc,
    domain_checker: Domain,
    config_resolver: Config,
}

#[derive(Debug)]
enum AccountKey {
    Pem(String),
    Der(Vec<u8>),
}

impl Default
    for AcmeAcceptorBuilder<
        MemoryAuthChallengeStore,
        MemoryCertStore,
        MemoryAccountStore,
        bool,
        ConfigBuilder<ServerConfig, WantsServerCert>,
    >
{
    fn default() -> Self {
        Self {
            http_client: reqwest::Client::default(),
            acme_directory: String::from("https://acme-staging-v02.api.letsencrypt.org/directory"),
            account_pk: None,
            contacts: None,
            challenge_store: MemoryAuthChallengeStore::default(),
            cert_store: MemoryCertStore::default(),
            account_store: MemoryAccountStore::default(),
            domain_checker: true,
            config_resolver: ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AcmeAcceptorBuilderError {
    #[error("no ACME account provided")]
    NoAccountProvided,
    #[error("failed to create ACME account")]
    FailToCreateAccount,
    #[error("failed to fetch ACME directory")]
    FailToFetchAcmeDirectory,
    #[error("invalid ACME account private key")]
    InvalidAccountPrivateKey,
}

type BuilderResult<S> = Result<AcmeAcceptor<S>, AcmeAcceptorBuilderError>;

impl<Auth, Cert, Acc, Domain, Config> AcmeAcceptorBuilder<Auth, Cert, Acc, Domain, Config>
where
    Cert: CertStore + 'static,
    Auth: AuthChallengeStore + 'static,
    Acc: AccountStore + 'static,
    Domain: DomainCheck + 'static,
    Config: ConfigResolver + 'static,
{
    /// The ACME account private key to be used. The key must be encoded on PKCS8 PEM format.
    ///
    /// # Example
    /// ```no_run
    /// # use acmer::{AcmeAcceptor, acceptor::AcmeAcceptorBuilderError};
    /// # use tokio::{fs, net::{TcpListener, TcpStream}};
    /// # async fn test() -> Result<AcmeAcceptor<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    /// # let acceptor =
    /// AcmeAcceptor::builder()
    ///     .with_account_pem_key(fs::read_to_string("acme.pem").await?)
    ///     .build_from_tcp_listener(TcpListener::bind("0.0.0.0:443").await?)
    ///     .await;
    /// #    Ok(acceptor?)
    /// # }
    /// ```
    pub fn with_account_pem_key(self, account_pk: impl Into<String>) -> Self {
        Self {
            account_pk: Some(AccountKey::Pem(account_pk.into())),
            ..self
        }
    }

    /// The ACME account private key to be used. The key must be encoded on PKCS8 DER format.
    ///
    /// # Example
    /// ```no_run
    /// # use acmer::{AcmeAcceptor, acceptor::AcmeAcceptorBuilderError};
    /// # use tokio::{fs, net::{TcpListener, TcpStream}};
    /// # async fn test() -> Result<AcmeAcceptor<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    /// # let acceptor =
    /// AcmeAcceptor::builder()
    ///     .with_account_der_key(fs::read("acme.der").await?)
    ///     .build_from_tcp_listener(TcpListener::bind("0.0.0.0:443").await?)
    ///     .await;
    /// #    Ok(acceptor?)
    /// # }
    /// ```
    pub fn with_account_der_key(self, account_pk: impl Into<Vec<u8>>) -> Self {
        Self {
            account_pk: Some(AccountKey::Der(account_pk.into())),
            ..self
        }
    }

    /// If the given private key is not yet registered, the
    ///
    /// # Example
    /// ```no_run
    /// # use acmer::{AcmeAcceptor, acceptor::AcmeAcceptorBuilderError};
    /// # use tokio::{fs, net::{TcpListener, TcpStream}};
    /// # async fn test() -> Result<AcmeAcceptor<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    /// # let acceptor =
    /// AcmeAcceptor::builder()
    ///     .with_account_pem_key(fs::read_to_string("acme.der").await?)
    ///     .build_from_tcp_listener(TcpListener::bind("0.0.0.0:443").await?)
    ///     .await;
    /// #    Ok(acceptor?)
    /// # }
    /// ```
    pub fn with_contact(self, contact: impl Into<String>) -> Self {
        let mut contacts = self.contacts.unwrap_or_default();
        contacts.push(contact.into());
        Self {
            contacts: Some(contacts),
            ..self
        }
    }

    pub fn allowed_domains<D>(
        self,
        domain_checker: D,
    ) -> AcmeAcceptorBuilder<Auth, Cert, Acc, D, Config>
    where
        D: DomainCheck + 'static,
    {
        AcmeAcceptorBuilder {
            http_client: self.http_client,
            acme_directory: self.acme_directory,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store: self.cert_store,
            account_store: self.account_store,
            domain_checker,
            config_resolver: self.config_resolver,
        }
    }

    pub fn with_rustls_config<C>(
        self,
        config_resolver: C,
    ) -> AcmeAcceptorBuilder<Auth, Cert, Acc, Domain, C>
    where
        C: ConfigResolver + 'static,
    {
        AcmeAcceptorBuilder {
            http_client: self.http_client,
            acme_directory: self.acme_directory,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store: self.cert_store,
            account_store: self.account_store,
            domain_checker: self.domain_checker,
            config_resolver,
        }
    }

    pub fn with_auth_challenge_store<A>(
        self,
        challenge_store: A,
    ) -> AcmeAcceptorBuilder<A, Cert, Acc, Domain, Config>
    where
        A: AuthChallengeStore + 'static,
    {
        AcmeAcceptorBuilder {
            http_client: self.http_client,
            acme_directory: self.acme_directory,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store,
            cert_store: self.cert_store,
            account_store: self.account_store,
            domain_checker: self.domain_checker,
            config_resolver: self.config_resolver,
        }
    }

    pub fn with_cert_store<C>(
        self,
        cert_store: C,
    ) -> AcmeAcceptorBuilder<Auth, C, Acc, Domain, Config>
    where
        C: CertStore + 'static,
    {
        AcmeAcceptorBuilder {
            http_client: self.http_client,
            acme_directory: self.acme_directory,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store,
            account_store: self.account_store,
            domain_checker: self.domain_checker,
            config_resolver: self.config_resolver,
        }
    }

    pub fn with_account_store<A>(
        self,
        account_store: A,
    ) -> AcmeAcceptorBuilder<Auth, Cert, A, Domain, Config>
    where
        A: AccountStore + 'static,
    {
        AcmeAcceptorBuilder {
            http_client: self.http_client,
            acme_directory: self.acme_directory,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store: self.cert_store,
            account_store,
            domain_checker: self.domain_checker,
            config_resolver: self.config_resolver,
        }
    }

    pub fn with_lets_encrypt_production(self) -> Self {
        Self {
            acme_directory: String::from("https://acme-v02.api.letsencrypt.org/directory"),
            ..self
        }
    }

    pub fn with_lets_encrypt_staging(self) -> Self {
        Self {
            acme_directory: String::from("https://acme-staging-v02.api.letsencrypt.org/directory"),
            ..self
        }
    }

    pub fn with_directory_url(self, url: impl Into<String>) -> Self {
        Self {
            acme_directory: url.into(),
            ..self
        }
    }

    pub fn with_http_client(self, http_client: reqwest::Client) -> Self {
        Self {
            http_client,
            ..self
        }
    }

    pub async fn build_from_stream<S, I>(self, incoming: S) -> BuilderResult<I>
    where
        S: Stream<Item = io::Result<I>>,
        S: Send + Unpin + 'static,
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let acme = AcmeClient::builder()
            .http_client(self.http_client)
            .build_with_directory_url(self.acme_directory)
            .await
            .map_err(|_| AcmeAcceptorBuilderError::FailToFetchAcmeDirectory)?;

        let private_key = if let Some(AccountKey::Der(pk)) = self.account_pk {
            Some(pk)
        } else if let Some(AccountKey::Pem(pk)) = self.account_pk {
            Some(
                pemfile::read_one(&mut pk.as_bytes())
                    .map_err(|_| AcmeAcceptorBuilderError::InvalidAccountPrivateKey)
                    .and_then(|key| match key {
                        Some(pemfile::Item::PKCS8Key(key)) => Ok(key),
                        _ => Err(AcmeAcceptorBuilderError::InvalidAccountPrivateKey),
                    })?,
            )
        } else {
            None
        };

        let contacts = self.contacts.unwrap_or_default();
        let account = acme
            .new_account()
            .contacts(contacts.iter().map(|s| s.as_str()).collect::<Vec<_>>())
            .terms_of_service_agreed(true);

        let account_store = if let Some(key) = private_key {
            account
                .private_key(&key)
                .send()
                .await
                .map_err(|_| AcmeAcceptorBuilderError::FailToCreateAccount)?;
            SingleAccountStore::new(PrivateKey(key)).boxed()
        } else {
            let account_store = self.account_store;
            let acme_directory = acme.directory_url();
            if account_store
                .get_account(acme_directory)
                .await
                .map_err(|_| AcmeAcceptorBuilderError::FailToCreateAccount)?
                .is_none()
            {
                let account = account
                    .with_auto_generated_ec_key()
                    .terms_of_service_agreed(true)
                    .send()
                    .await
                    .map_err(|_| AcmeAcceptorBuilderError::FailToCreateAccount)?;
                account_store
                    .put_account(acme_directory, PrivateKey(account.key().to_der().unwrap()))
                    .await
                    .map_err(|_| AcmeAcceptorBuilderError::FailToCreateAccount)?;
            }

            account_store.boxed()
        };

        Ok(AcmeAcceptor::start(
            acme,
            incoming,
            self.cert_store,
            self.challenge_store,
            account_store,
            self.domain_checker,
            self.config_resolver,
        ))
    }

    pub async fn build_from_tcp_stream<L>(self, incoming: L) -> BuilderResult<TcpStream>
    where
        L: Stream<Item = io::Result<TcpStream>>,
        L: Send + Unpin + 'static,
    {
        self.build_from_stream(incoming).await
    }

    pub async fn build_from_tcp_listener(self, listener: TcpListener) -> BuilderResult<TcpStream> {
        self.build_from_tcp_stream(TcpListenerStream::new(listener))
            .await
    }

    pub async fn build_from_unix_listener(
        self,
        listener: UnixListener,
    ) -> BuilderResult<UnixStream> {
        self.build_from_stream(UnixListenerStream::new(listener))
            .await
    }
}
