use crate::helpers::send_request;
use crate::helpers::spawn_app;
use anyhow::Result;
use bytes::Bytes;

#[tokio::test]
async fn test_parse_header() -> Result<()> {
    let server_addr = spawn_app().await?;

    // we can just send 12 bytes of zeroes
    let req: [u8; 12] = [0; 12];
    let message = Bytes::copy_from_slice(&req);
    let resp = send_request(&server_addr, message).await?;
    assert!(resp.len() > 0);
    Ok(())
}
