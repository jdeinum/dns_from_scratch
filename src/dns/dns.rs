use crate::dns::DnsAnswerSet;
use crate::dns::DnsQuestionSet;
use crate::dns::header::{DnsHeader, DnsPacketType};
use crate::parse::DnsData;
use anyhow::{Result, ensure};
use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tracing::info;

#[derive(Debug)]
pub struct DnsServer {
    port: u16,
    sock: UdpSocket,
}

impl DnsServer {
    pub async fn build(address: &str) -> Result<Self> {
        let sock = UdpSocket::bind(address).await?;

        Ok(Self {
            port: sock.local_addr()?.port(),
            sock,
        })
    }

    pub async fn run_until_stopped(&self) -> Result<()> {
        let mut buf = [0; 1024];
        loop {
            let (len, addr) = self.sock.recv_from(&mut buf).await?;

            // parse the request
            let (_, req) = DnsMessage::decode(&Bytes::copy_from_slice(&buf[..len]), 0)?;
            info!("parsed request {req:?}");

            // convert the request into a response
            let answers: DnsAnswerSet = DnsAnswerSet::from_questions(req.questions.clone())?;
            let reply = req.as_reply().with_answers(answers)?;

            let _ = self.sock.send_to(&reply.encode()?, addr).await?;
            info!("send response {reply:?}");
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn address(&self) -> Result<String> {
        Ok(self.sock.local_addr()?.to_string())
    }
}

#[derive(Debug)]
struct DnsMessage {
    pub header: DnsHeader,
    pub questions: DnsQuestionSet,
    pub answers: DnsAnswerSet,
}

impl DnsData for DnsMessage {
    fn encode(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();
        buf.extend_from_slice(&self.header.encode()?);

        // encode questions
        buf.extend_from_slice(&self.questions.encode(self.header.question_count as usize)?);

        // encode answers
        buf.extend_from_slice(
            &self
                .answers
                .encode(self.header.answer_record_count as usize)?,
        );

        Ok(buf.into())
    }

    fn decode(buf: &Bytes, pos: usize) -> Result<(usize, Self)> {
        // first 12 bytes are the header
        ensure!(buf.len() >= 12, "request is less than 12 bytes long");

        // parse the header
        let (current, header) = DnsHeader::decode(buf, pos)?;

        // parse the questions
        let (current, questions) =
            DnsQuestionSet::decode(buf, current, header.question_count as usize)?;

        Ok((current, Self {
            header,
            questions,
            answers: DnsAnswerSet::default(),
        }))
    }
}

impl DnsMessage {
    pub fn as_reply(mut self) -> Self {
        self.header.query_type = DnsPacketType::Response;
        self
    }

    pub fn with_answers(mut self, answer: DnsAnswerSet) -> Result<Self> {
        self.header.answer_record_count = answer.answers.len().try_into()?;
        self.answers = answer;
        Ok(self)
    }
}
