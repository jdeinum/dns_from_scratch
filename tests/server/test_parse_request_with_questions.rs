use crate::helpers::send_request;
use crate::helpers::spawn_app;
use anyhow::Result;
use bytes::Bytes;
use bytes::BytesMut;
use dns::dns::DnsHeader;
use dns::dns::LabelSet;
use dns::dns::Question;
use dns::dns::QuestionType;

#[tokio::test]
async fn test_parse_request_questions() -> Result<()> {
    let server_addr = spawn_app().await?;

    let mut buf: BytesMut = BytesMut::new();

    // header
    let mut request_header = DnsHeader::default();
    request_header.question_count = 1;
    buf.extend_from_slice(&request_header.write_header());

    // questions
    let mut questions: Vec<Question> = Vec::new();
    questions.push(Question {
        name: LabelSet::from_domain("google.com"),
        class: 1,
        qtype: QuestionType::A,
    });

    for q in questions {
        buf.extend_from_slice(&q.to_bytes()?);
    }

    let resp = send_request(&server_addr, buf.into()).await?;
    assert!(resp.len() > 0);
    Ok(())
}
