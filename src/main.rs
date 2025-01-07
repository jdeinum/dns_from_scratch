use anyhow::Result;
use dns::initialization::run;

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}
