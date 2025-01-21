use anyhow::Result;
use dns::dns::DnsServer;
use std::sync::LazyLock;

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
