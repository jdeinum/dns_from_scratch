use crate::helpers::spawn_app;
use anyhow::Result;
use dns::dns::*;
use dns::{dns::DnsMessage, parse::DnsData};
use std::collections::HashMap;

#[tokio::test]
async fn test_forwarding() -> Result<()> {
    let server_addr = spawn_app().await?;

    // build a DNS Request
    let mut dns_request = DnsMessage::default();
    dns_request.questions = DnsQuestionSet {
        questions: [DnsQuestion {
            name: LabelSet {
                labels: ["google", "com"].iter().map(|x| x.to_string()).collect(),
            },
            qtype: QuestionType::A,
            class: 1,
        }]
        .to_vec(),
    };

    dns_request.header.question_count = dns_request.questions.questions.len().try_into()?;
    let dns_bytes = dns_request.encode(0, &mut HashMap::new())?;
    let _reply = send_request(&server_addr, dns_bytes).await?;
    Ok(())
}
