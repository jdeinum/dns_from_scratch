use crate::helpers::spawn_app;
use anyhow::Result;
use dns::dns::*;
use dns::{dns::DnsMessage, parse::DnsData};
use std::collections::HashMap;
use tracing::info;

#[tokio::test]
async fn test_answer_label_fail_2() -> Result<()> {
    let server_addr = spawn_app().await?;

    // build a DNS Request
    let mut dns_request = DnsMessage::default();
    dns_request.questions = DnsQuestionSet {
        questions: [
            DnsQuestion {
                name: Domain {
                    labels: ["60", "3", "375", "c8fd8", "1"]
                        .map(|x| Label(x.to_string()))
                        .to_vec(),
                },
                qtype: QuestionType::NULL,
                class: 15751,
            },
            DnsQuestion {
                name: Domain {
                    labels: ["841f5", "38", "3f", "e"]
                        .map(|x| Label(x.to_string()))
                        .to_vec(),
                },
                qtype: QuestionType::MD,
                class: 16954,
            },
            DnsQuestion {
                name: Domain {
                    labels: ["49", "b42", "0", "5", "1", "1"]
                        .map(|x| Label(x.to_string()))
                        .to_vec(),
                },
                qtype: QuestionType::MG,
                class: 5805,
            },
            DnsQuestion {
                name: Domain {
                    labels: ["0fb1b", "7fe", "68", "5f0d1", "8", "1"]
                        .map(|x| Label(x.to_string()))
                        .to_vec(),
                },
                qtype: QuestionType::A,
                class: 1142,
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
