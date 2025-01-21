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
        let server_addr: String = std::env::args().collect::<Vec<String>>()[2].clone();
        info!("forwarding server is {server_addr}");
        loop {
            let (len, addr) = self.sock.recv_from(&mut buf).await?;
            info!("got request");

            // parse the request
            let (_, req) =
                DnsMessage::decode(&Bytes::copy_from_slice(&buf[..len]), 0, &mut HashMap::new())?;

            // convert the request into a response
            // let reply = forward_to_server(&server_addr, req).await?;
            info!("sending a response");

            let _ = self
                .sock
                .send_to(&req.encode(0, &mut HashMap::new())?, addr)
                .await?;

            // info!("send response {reply:?}");
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn address(&self) -> Result<String> {
        Ok(self.sock.local_addr()?.to_string())
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
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

pub async fn send_request(addr: &str, buf: Bytes) -> Result<Bytes> {
    // connect to our server
    let current_sock = UdpSocket::bind("127.0.0.1:0").await?;
    current_sock.connect(addr).await?;

    // send data
    current_sock.send(buf.as_ref()).await?;

    // receive response
    let mut buf: [u8; 256] = [0; 256];
    let resp = current_sock.recv(&mut buf).await?;
    Ok(Bytes::copy_from_slice(&buf[..resp]))
}

pub async fn forward_to_server(server: &str, request: DnsMessage) -> Result<DnsMessage> {
    // get the second env var, which is the server we are forwarding to
    info!("forwarding DNS request to {server}");

    let reply = send_request(server, request.encode(0, &mut HashMap::new())?).await?;

    let (_, dns_response) = DnsMessage::decode(&reply, 0, &mut HashMap::new())?;

    info!("received reply from {server}: {dns_response:?}");

    Ok(dns_response)
}
