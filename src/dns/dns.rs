use super::DnsAnswer;
use super::question::DnsQuestion;
use crate::dns::header::{DnsHeader, DnsPacketType, parse_header};
use crate::dns::question::parse_questions;
use anyhow::{Result, ensure};
use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tracing::{info, instrument};

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
            let mut req = parse_request(Bytes::copy_from_slice(&buf[..len]))?;
            info!("parsed request {req:?}");

            // change the request to a resp
            req.header.query_type = DnsPacketType::Response;

            let _ = self.sock.send_to(&buf[..len], addr).await?;
            info!("send response {req:?}");
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
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
}

impl DnsMessage {
    pub fn to_bytes(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();
        buf.extend_from_slice(&self.header.write_header());
        for q in self.questions.clone() {
            buf.extend_from_slice(&q.to_bytes()?);
        }

        Ok(buf.into())
    }
}

#[instrument(skip_all, ret, err)]
fn parse_request(buf: Bytes) -> Result<DnsMessage> {
    // first 12 bytes are the header
    ensure!(buf.len() >= 12, "request is less than 12 bytes long");

    // parse the header
    let dns_header = parse_header(&buf)?;

    // parse the questions
    let questions = parse_questions(
        &Bytes::copy_from_slice(&buf[12..]),
        dns_header.question_count.into(),
    )?;

    Ok(DnsMessage {
        header: dns_header,
        questions,
        answers: Vec::new(),
    })
}

#[cfg(test)]
mod tests {

    #[derive(Clone, Debug)]
    struct Header {
        pub v: Vec<u8>,
    }

    impl Arbitrary for Header {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let mut v = Vec::with_capacity(12);
            for _ in 0..12 {
                v.push(u8::arbitrary(g))
            }
            Header { v }
        }
    }

    use super::*;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;
    quickcheck! {
        fn decode_encode_header(h: Header) -> TestResult {
            if h.v.len() != 12 {
                return TestResult::discard()
            }
            let header = parse_header(&Bytes::copy_from_slice(&h.v[..12])).unwrap();
            let encoded_header = header.write_header();
            TestResult::from_bool(encoded_header == &h.v)
        }
    }
}
