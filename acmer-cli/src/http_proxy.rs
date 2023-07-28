use std::{error::Error, sync::Arc};

use acmer::TlsStream;
use hyper::{
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, TRANSFER_ENCODING},
    http::{uri::Scheme, HeaderValue},
    server, service, Uri,
};
use tokio::io;
use tokio_stream::Stream;

pub async fn proxy<T>(
    proxy_uri: impl Into<String>,
    conns: impl Stream<Item = io::Result<TlsStream<T>>>,
) where
    T: 'static,
    T: Send + Unpin,
    T: io::AsyncRead + io::AsyncWrite,
{
    let proxy_uri: Uri = proxy_uri.into().parse().unwrap();
    let authority = proxy_uri.authority().cloned();

    hyper::Server::builder(server::accept::from_stream(conns))
        .serve(service::make_service_fn(move |conn: &TlsStream<_>| {
            let sni = conn.get_ref().1.server_name().unwrap_or_default();
            let sni = Arc::new(sni.to_owned());
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
