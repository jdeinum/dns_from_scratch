use crate::helpers::spawn_app;
use bytes::BytesMut;
use dns::dns::DnsMessage;

#[tokio::test]
async fn test_parse_request_questions() -> Result<()> {
    let server_addr = spawn_app().await?;
    let mut buf: BytesMut = BytesMut::new();

    // build a DNS Request
}
