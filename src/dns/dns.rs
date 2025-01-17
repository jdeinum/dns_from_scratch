use crate::dns::DnsAnswerSet;
use crate::dns::DnsQuestionSet;
use crate::dns::header::{DnsHeader, DnsPacketType};
use crate::parse::DnsData;
use crate::parse::LabelMap;
use anyhow::{Result, ensure};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tracing::info;
use tracing::instrument;

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

            // a hashmap use for decoding the request and encoding the response
            let mut label_map: HashMap<String, usize> = HashMap::new();

            // parse the request
            info!("bytes: {:?}", &buf[..len]);
            let (_, req) =
                DnsMessage::decode(&Bytes::copy_from_slice(&buf[..len]), 0, &mut label_map)?;
            info!("parsed request {req:?}");

            // convert the request into a response
            let answers: DnsAnswerSet = DnsAnswerSet::from_questions(req.questions.clone())?;
            let reply = req.as_reply().with_answers(answers)?;

            let _ = self
                .sock
                .send_to(&reply.encode(0, &mut label_map)?, addr)
                .await?;
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

#[derive(Debug, Default)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: DnsQuestionSet,
    pub answers: DnsAnswerSet,
}

impl DnsData for DnsMessage {
    #[instrument(name = "Encoding DNS Message", skip_all)]
    fn encode(&self, _: usize, label_map: LabelMap) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();
        buf.extend_from_slice(&self.header.encode(buf.len(), label_map)?);

        // encode questions
        buf.extend_from_slice(&self.questions.encode(
            self.header.question_count as usize,
            label_map,
            buf.len(),
        )?);

        // encode answers
        buf.extend_from_slice(&self.answers.encode(
            self.header.answer_record_count as usize,
            label_map,
            buf.len(),
        )?);

        Ok(buf.into())
    }

    #[instrument(name = "Decoding DNS Message", skip_all)]
    fn decode(buf: &Bytes, pos: usize, label_map: LabelMap) -> Result<(usize, Self)> {
        // first 12 bytes are the header
        ensure!(buf.len() >= 12, "request is less than 12 bytes long");

        // parse the header
        let (current, header) = DnsHeader::decode(buf, pos, label_map)?;

        // parse the questions
        let (current, questions) =
            DnsQuestionSet::decode(buf, current, header.question_count as usize, label_map)?;

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
