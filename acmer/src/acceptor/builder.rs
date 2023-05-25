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

use super::{config::ConfigResolver, AcmeAcceptor, DomainCheck};

pub struct AcmeAcceptorBuilder<Auth, Cert, Acc, Domain, Config> {
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
    pub fn with_account_pem_key(self, account_pk: impl Into<String>) -> Self {
        Self {
            account_pk: Some(AccountKey::Pem(account_pk.into())),
            ..self
        }
    }
    pub fn with_account_der_key(self, account_pk: impl Into<Vec<u8>>) -> Self {
        Self {
            account_pk: Some(AccountKey::Der(account_pk.into())),
            ..self
        }
    }

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

    pub async fn build_from_stream<S, I>(self, incoming: S) -> BuilderResult<I>
    where
        S: Stream<Item = io::Result<I>>,
        S: Send + Unpin + 'static,
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let acme = AcmeClient::from_directory_url(self.acme_directory)
            .await
            .map_err(|_| AcmeAcceptorBuilderError::FailToFetchAcmeDirectory)?;

        let account_store = if let Some(AccountKey::Der(pk)) = self.account_pk {
            SingleAccountStore::new(PrivateKey(pk)).boxed()
        } else if let Some(AccountKey::Pem(pk)) = self.account_pk {
            pemfile::read_one(&mut pk.as_bytes())
                .map_err(|_| AcmeAcceptorBuilderError::InvalidAccountPrivateKey)
                .and_then(|key| match key {
                    Some(pemfile::Item::ECKey(key)) => Ok(PrivateKey(key)),
                    Some(pemfile::Item::PKCS8Key(key)) => Ok(PrivateKey(key)),
                    Some(pemfile::Item::RSAKey(key)) => Ok(PrivateKey(key)),
                    _ => Err(AcmeAcceptorBuilderError::InvalidAccountPrivateKey),
                })
                .map(SingleAccountStore::new)?
                .boxed()
        } else if let Some(ref contacts) = self.contacts {
            let account_store = self.account_store;
            let acme_directory = acme.directory_url();

            if account_store
                .get_account(acme_directory)
                .await
                .ok()
                .is_none()
            {
                let account = acme
                    .new_account()
                    .contacts(contacts.iter().map(|s| s.as_str()).collect::<Vec<_>>())
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
        } else {
            return Err(AcmeAcceptorBuilderError::NoAccountProvided);
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
