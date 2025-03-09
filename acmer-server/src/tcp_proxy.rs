use std::net::SocketAddr;

use tokio::{io, net::TcpStream};
use tokio_stream::{Stream, StreamExt};

pub async fn proxy<T>(addr: SocketAddr, mut connections: impl Stream<Item = io::Result<T>> + Unpin)
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
