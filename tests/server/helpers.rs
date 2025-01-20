use anyhow::Result;
use bytes::Bytes;
use dns::dns::DnsServer;
use std::sync::LazyLock;
use tokio::net::UdpSocket;

static TRACING: LazyLock<()> = LazyLock::new(|| {
    if std::env::var("TESTING_LOG").is_ok() {
        tracing_subscriber::fmt::init();
    }
});

pub async fn spawn_app() -> Result<String> {
    LazyLock::force(&TRACING);
    let server = DnsServer::build("127.0.0.1:0").await?;
    let address = server.address()?.to_string().clone();
    tokio::spawn(async move { server.run_until_stopped().await });
    Ok(address)
}

pub async fn send_request(addr: &str, buf: Bytes) -> Result<Bytes> {
    // connect to our server
    let current_sock = UdpSocket::bind("127.0.0.1:0").await?;
    current_sock.connect(addr).await?;

    // send data
    current_sock.send(buf.as_ref()).await?;

    // receive response
    let mut buf: [u8; 256] = [0; 256];
    let resp = current_sock.recv(&mut buf).await?;
    Ok(Bytes::copy_from_slice(&buf[..resp]))
}
