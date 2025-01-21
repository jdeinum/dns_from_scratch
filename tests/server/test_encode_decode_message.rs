use crate::helpers::spawn_app;
use anyhow::Result;
use dns::{
    dns::{DnsAnswer, DnsMessage, DnsQuestion, send_request},
    parse::DnsData,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_encode_decode_message() -> Result<()> {
    let server_addr = spawn_app().await?;

    // build a DNS Request
    let mut dns_request = DnsMessage::default();
    dns_request.questions.questions.push(DnsQuestion::default());
    dns_request.answers.answers.push(DnsAnswer::default());
    dns_request.header.question_count = 1;
    dns_request.header.answer_record_count = 1;

    let dns_bytes = dns_request.encode(0, &mut HashMap::new())?;

    // send the bytes to the server
    let reply = send_request(&server_addr, dns_bytes).await?;

    let _decoded_dns_request = DnsMessage::decode(&reply, 0, &mut HashMap::new())?;

    Ok(())
}
