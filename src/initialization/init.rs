use crate::dns::DnsServer;
use anyhow::Result;
use tracing::info;

pub async fn run() -> Result<()> {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our server
    let server = DnsServer::build("127.0.0.1:2053").await?;
    info!("server: {:?}", server);

    // run
    server.run_until_stopped().await?;

    Ok(())
}
