use papaleguas::AcmeClient;
use rustls::PrivateKey;
use tokio::net::TcpListener;

use crate::store::{
    AccountStore, AuthChallengeStore, BoxedAccountStoreExt, CertStore, MemoryAccountStore,
    MemoryAuthChallengeStore, MemoryCertStore, SingleAccountStore,
};

use super::AcmeAcceptor;

#[derive(Debug)]
pub struct AcmeAcceptorBuilder<Auth, Cert, Acc> {
    acme: Option<AcmeClient>,
    account_pk: Option<PrivateKey>,
    contacts: Option<Vec<String>>,
    challenge_store: Auth,
    cert_store: Cert,
    account_store: Acc,
}

impl Default
    for AcmeAcceptorBuilder<MemoryAuthChallengeStore, MemoryCertStore, MemoryAccountStore>
{
    fn default() -> Self {
        Self {
            acme: None,
            account_pk: None,
            contacts: None,
            challenge_store: MemoryAuthChallengeStore::default(),
            cert_store: MemoryCertStore::default(),
            account_store: MemoryAccountStore::default(),
        }
    }
}

impl<Auth, Cert, Acc> AcmeAcceptorBuilder<Auth, Cert, Acc>
where
    Cert: CertStore + 'static,
    Auth: AuthChallengeStore + 'static,
    Acc: AccountStore + 'static,
{
    pub fn with_contact(self, contact: impl Into<String>) -> Self {
        let mut contacts = self.contacts.unwrap_or_default();
        contacts.push(contact.into());
        Self {
            contacts: Some(contacts),
            ..self
        }
    }

    pub fn with_auth_challenge_store<A>(
        self,
        challenge_store: A,
    ) -> AcmeAcceptorBuilder<A, Cert, Acc>
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
        }
    }

    pub fn with_cert_store<C>(self, cert_store: C) -> AcmeAcceptorBuilder<Auth, C, Acc>
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
        }
    }

    pub fn with_account_store<A>(self, account_store: A) -> AcmeAcceptorBuilder<Auth, Cert, A>
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
        }
    }

    pub fn acme_client(self, acme: crate::AcmeClient) -> Self {
        Self {
            acme: Some(acme),
            ..self
        }
    }

    // TODO: return a result instead of panic
    pub async fn build_with_tcp_listener(self, tcp: TcpListener) -> AcmeAcceptor {
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
            tcp,
            self.cert_store,
            self.challenge_store,
            account_store,
        )
    }
}
