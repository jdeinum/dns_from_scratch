use crate::helpers::spawn_app;
use anyhow::Result;
use dns::dns::*;
use dns::{dns::DnsMessage, parse::DnsData};
use std::collections::HashMap;
use tracing::info;

#[tokio::test]
async fn test_answer_label_fail_3() -> Result<()> {
    let server_addr = spawn_app().await?;

    // build a DNS Request
    let mut dns_request = DnsMessage::default();
    dns_request.questions = DnsQuestionSet {
        questions: [
            DnsQuestion {
                name: LabelSet {
                    labels: ["a50", "0", "13ab", "f"].map(|x| x.to_string()).to_vec(),
                },
                qtype: QuestionType::CNAME,
                class: 32542,
            },
            DnsQuestion {
                name: LabelSet {
                    labels: ["2", "f"].map(|x| x.to_string()).to_vec(),
                },
                qtype: QuestionType::SOA,
                class: 16770,
            },
            DnsQuestion {
                name: LabelSet {
                    labels: ["bf0", "f28", "c777e", "102", "92970", "8"]
                        .map(|x| x.to_string())
                        .to_vec(),
                },
                qtype: QuestionType::SOA,
                class: 45054,
            },
            DnsQuestion {
                name: LabelSet {
                    labels: ["9a", "a", "b8", "81d48", "2", "f"]
                        .map(|x| x.to_string())
                        .to_vec(),
                },
                qtype: QuestionType::MR,
                class: 46776,
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
