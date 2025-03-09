use rustls::{server::WantsServerCert, ConfigBuilder, ServerConfig};

use crate::store::{Certificate, PrivateKey};

pub trait ConfigResolver: Send + Sync {
    fn rustls_config(
        &self,
        sni: &str,
        key: PrivateKey,
        certs: Vec<Certificate>,
    ) -> Result<ServerConfig, rustls::Error>;
}

impl<F> ConfigResolver for F
where
    F: Fn(&str, PrivateKey, Vec<Certificate>) -> Result<ServerConfig, rustls::Error>,
    F: Send + Sync,
{
    fn rustls_config(
        &self,
        sni: &str,
        key: PrivateKey,
        certs: Vec<Certificate>,
    ) -> Result<ServerConfig, rustls::Error> {
        self(sni, key, certs)
    }
}

impl ConfigResolver for ConfigBuilder<ServerConfig, WantsServerCert> {
    fn rustls_config(
        &self,
        _sni: &str,
        key: PrivateKey,
        certs: Vec<Certificate>,
    ) -> Result<ServerConfig, rustls::Error> {
        self.clone().with_single_cert(certs, key)
    }
}
