use papaleguas::AcmeClient;
use rustls::PrivateKey;
use tokio::{
    io,
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

use super::{AcmeAcceptor, DomainCheck};

#[derive(Debug)]
pub struct AcmeAcceptorBuilder<Auth, Cert, Acc, Domain> {
    acme: Option<AcmeClient>,
    account_pk: Option<PrivateKey>,
    contacts: Option<Vec<String>>,
    challenge_store: Auth,
    cert_store: Cert,
    account_store: Acc,
    domain_checker: Domain,
}

impl Default
    for AcmeAcceptorBuilder<MemoryAuthChallengeStore, MemoryCertStore, MemoryAccountStore, bool>
{
    fn default() -> Self {
        Self {
            acme: None,
            account_pk: None,
            contacts: None,
            challenge_store: MemoryAuthChallengeStore::default(),
            cert_store: MemoryCertStore::default(),
            account_store: MemoryAccountStore::default(),
            domain_checker: true,
        }
    }
}

impl<Auth, Cert, Acc, Domain> AcmeAcceptorBuilder<Auth, Cert, Acc, Domain>
where
    Cert: CertStore + 'static,
    Auth: AuthChallengeStore + 'static,
    Acc: AccountStore + 'static,
    Domain: DomainCheck + 'static,
{
    pub fn with_contact(self, contact: impl Into<String>) -> Self {
        let mut contacts = self.contacts.unwrap_or_default();
        contacts.push(contact.into());
        Self {
            contacts: Some(contacts),
            ..self
        }
    }

    pub fn allowed_domains<D>(self, domain_checker: D) -> AcmeAcceptorBuilder<Auth, Cert, Acc, D>
    where
        D: DomainCheck + 'static,
    {
        AcmeAcceptorBuilder {
            acme: self.acme,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store: self.cert_store,
            account_store: self.account_store,
            domain_checker,
        }
    }

    pub fn with_auth_challenge_store<A>(
        self,
        challenge_store: A,
    ) -> AcmeAcceptorBuilder<A, Cert, Acc, Domain>
    where
        Auth: AuthChallengeStore + 'static,
    {
        AcmeAcceptorBuilder {
            acme: self.acme,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store,
            cert_store: self.cert_store,
            account_store: self.account_store,
            domain_checker: self.domain_checker,
        }
    }

    pub fn with_cert_store<C>(self, cert_store: C) -> AcmeAcceptorBuilder<Auth, C, Acc, Domain>
    where
        C: CertStore + 'static,
    {
        AcmeAcceptorBuilder {
            acme: self.acme,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store,
            account_store: self.account_store,
            domain_checker: self.domain_checker,
        }
    }

    pub fn with_account_store<A>(
        self,
        account_store: A,
    ) -> AcmeAcceptorBuilder<Auth, Cert, A, Domain>
    where
        A: AccountStore + 'static,
    {
        AcmeAcceptorBuilder {
            acme: self.acme,
            account_pk: self.account_pk,
            contacts: self.contacts,
            challenge_store: self.challenge_store,
            cert_store: self.cert_store,
            account_store,
            domain_checker: self.domain_checker,
        }
    }

    pub fn acme_client(self, acme: crate::AcmeClient) -> Self {
        Self {
            acme: Some(acme),
            ..self
        }
    }

    pub async fn build_with_tcp_stream<L>(self, incoming: L) -> AcmeAcceptor<TcpStream>
    where
        L: Stream<Item = io::Result<TcpStream>>,
        L: Send + Unpin + 'static,
    {
        let acme = match self.acme {
            Some(acme) => acme,
            None => AcmeClient::builder()
                .build_lets_encrypt_staging()
                .await
                .unwrap(),
        };

        let account_store = if let Some(account_pk) = self.account_pk {
            SingleAccountStore::new(account_pk).boxed()
        } else if let Some(ref contacts) = self.contacts {
            let account_store = self.account_store;
            let acme_directory = acme.directory_url();

            if account_store.get_account(acme_directory).await.is_none() {
                let account = acme
                    .new_account()
                    .contacts(contacts.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                    .with_auto_generated_ec_key()
                    .terms_of_service_agreed(true)
                    .send()
                    .await
                    .unwrap();

                account_store
                    .put_account(acme_directory, PrivateKey(account.key().to_der().unwrap()))
                    .await;
            }

            account_store.boxed()
        } else {
            panic!("No account provided")
        };

        AcmeAcceptor::new(
            acme,
            incoming,
            self.cert_store,
            self.challenge_store,
            account_store,
            self.domain_checker,
        )
    }

    // TODO: return a result instead of panic
    pub async fn build_with_tcp_listener(self, listener: TcpListener) -> AcmeAcceptor<TcpStream> {
        self.build_with_tcp_stream(TcpListenerStream::new(listener))
            .await
    }

    // TODO: return a result instead of panic
    pub async fn build_with_unix_listener(
        self,
        listener: UnixListener,
    ) -> AcmeAcceptor<UnixStream> {
        let acme = match self.acme {
            Some(acme) => acme,
            None => AcmeClient::builder()
                .build_lets_encrypt_staging()
                .await
                .unwrap(),
        };

        let account_store = if let Some(account_pk) = self.account_pk {
            SingleAccountStore::new(account_pk).boxed()
        } else if let Some(ref contacts) = self.contacts {
            let account_store = self.account_store;
            let acme_directory = acme.directory_url();

            if account_store.get_account(acme_directory).await.is_none() {
                let account = acme
                    .new_account()
                    .contacts(contacts.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                    .with_auto_generated_ec_key()
                    .terms_of_service_agreed(true)
                    .send()
                    .await
                    .unwrap();

                account_store
                    .put_account(acme_directory, PrivateKey(account.key().to_der().unwrap()))
                    .await;
            }

            account_store.boxed()
        } else {
            panic!("No account provided")
        };

        AcmeAcceptor::new(
            acme,
            UnixListenerStream::new(listener),
            self.cert_store,
            self.challenge_store,
            account_store,
            self.domain_checker,
        )
    }
}
