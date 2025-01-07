use crate::helpers::send_request;
use crate::helpers::spawn_app;
use anyhow::Result;
use bytes::Bytes;

#[tokio::test]
async fn test_basic_reply() -> Result<()> {
    let server_addr = spawn_app().await?;
    let message = Bytes::copy_from_slice("hello world".as_bytes());
    let resp = send_request(&server_addr, message).await?;
    assert!(resp.len() > 0);
    Ok(())
}
