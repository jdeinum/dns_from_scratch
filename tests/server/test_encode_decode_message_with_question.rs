use crate::helpers::{send_request, spawn_app};
use anyhow::Result;
use dns::dns::*;
use dns::{dns::DnsMessage, parse::DnsData};
use std::collections::HashMap;
use tracing::info;

#[tokio::test]
async fn test_encode_decode_message_with_question() -> Result<()> {
    let server_addr = spawn_app().await?;

    // build a DNS Request
    let mut dns_request = DnsMessage::default();
    dns_request.questions = DnsQuestionSet {
        questions: [
            DnsQuestion {
                name: LabelSet {
                    labels: ["7f", "171ef"].iter().map(|x| x.to_string()).collect(),
                },
                qtype: QuestionType::MX,
                class: 30784,
            },
            DnsQuestion {
                name: LabelSet {
                    labels: ["bd", "3"].iter().map(|x| x.to_string()).collect(),
                },
                qtype: QuestionType::SOA,
                class: 51141,
            },
            DnsQuestion {
                name: LabelSet {
                    labels: ["7", "a8", "80f9", "1", "3"]
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                },
                qtype: QuestionType::MR,
                class: 37020,
            },
            DnsQuestion {
                name: LabelSet {
                    labels: ["1168", "ad55b", "19", "e"]
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                },
                qtype: QuestionType::PTR,
                class: 11335,
            },
        ]
        .to_vec(),
    };
    dns_request.header.question_count = dns_request.questions.questions.len().try_into()?;

    let dns_bytes = dns_request.encode(0, &mut HashMap::new())?;

    // send the bytes to the server
    info!("sending request");
    let reply = send_request(&server_addr, dns_bytes).await?;
    info!("received reply");

    let (_, decoded_dns_request) = DnsMessage::decode(&reply, 0, &mut HashMap::new())?;

    assert_eq!(decoded_dns_request.questions, dns_request.questions);

    Ok(())
}
