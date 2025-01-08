use super::question::Question;
use crate::dns::question::parse_questions;
use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
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

#[derive(Debug, PartialEq, Eq, Default)]
pub enum DnsPacketType {
    #[default]
    Query = 0,
    Response = 1,
}

#[derive(Debug, Default)]
pub struct DnsHeader {
    pub packet_id: u16,
    pub query_type: DnsPacketType,
    pub opcode: u8,
    pub auth_answer: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub reserved: u8,
    pub response_code: u8,
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

impl DnsHeader {
    pub fn write_header(&self) -> Bytes {
        let mut buf = BytesMut::new();

        // Packet ID
        buf.extend_from_slice(&self.packet_id.to_be_bytes());

        // QR, Opcode, AA, TC, RD, RA, Reserved, RCODE
        let mut byte2 = 0u8;
        if self.query_type == DnsPacketType::Response {
            byte2 |= 1 << 7; // Set QR bit for response
        }
        byte2 |= (self.opcode & 0xf) << 3;
        if self.auth_answer {
            byte2 |= 1 << 2;
        }
        if self.truncation {
            byte2 |= 1 << 1;
        }
        if self.recursion_desired {
            byte2 |= 1 << 0;
        }
        let mut byte3 = 0u8;
        if self.recursion_available {
            byte3 |= 1 << 7;
        }
        byte3 |= (self.reserved & 0x7) << 4;
        byte3 |= self.response_code & 0xf;

        buf.put_u8(byte2);
        buf.put_u8(byte3);

        // Question count, answer record count, authority record count, additional record count
        buf.extend_from_slice(&self.question_count.to_be_bytes());
        buf.extend_from_slice(&self.answer_record_count.to_be_bytes());
        buf.extend_from_slice(&self.authority_record_count.to_be_bytes());
        buf.extend_from_slice(&self.additional_record_count.to_be_bytes());

        buf.into()
    }
}

// Field 	                            Size 	    Description
// Packet Identifier (ID) 	            16 bits 	A random ID assigned to query packets. Response packets must reply with the same ID.
// Query/Response Indicator (QR)    	1 bit 	    1 for a reply packet, 0 for a question packet.
// Operation Code (OPCODE) 	            4 bits 	    Specifies the kind of query in a message.
// Authoritative Answer (AA) 	        1 bit 	    1 if the responding server "owns" the domain queried, i.e., it's authoritative.
// Truncation (TC) 	                    1 bit 	    1 if the message is larger than 512 bytes. Always 0 in UDP responses.
// Recursion Desired (RD) 	            1 bit 	    Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
// Recursion Available (RA) 	        1 bit 	    Server sets this to 1 to indicate that recursion is available.
// Reserved (Z) 	                    3 bits 	    Used by DNSSEC queries. At inception, it was reserved for future use.
// Response Code (RCODE) 	            4 bits 	    Response code indicating the status of the response.
// Question Count (QDCOUNT) 	        16 bits 	Number of questions in the Question section.
// Answer Record Count (ANCOUNT) 	    16 bits 	Number of records in the Answer section.
// Authority Record Count (NSCOUNT) 	16 bits 	Number of records in the Authority section.
// Additional Record Count (ARCOUNT) 	16 bits 	Number of records in the Additional section.
fn parse_header(buf: &Bytes) -> Result<DnsHeader> {
    let packet_id = u16::from_be_bytes(buf[0..2].try_into()?);

    let query_type = match buf[2] >> 7 {
        0 => DnsPacketType::Query,
        1 => DnsPacketType::Response,
        x => {
            return Err(anyhow::Error::msg(format!(
                "Invalid DNS query indicator: {}",
                x
            )));
        }
    };

    let opcode: u8 = (buf[2] >> 3) & 0xf;

    let auth_answer: bool = match (buf[2] >> 2) & 0x1 {
        0 => false,
        1 => true,
        x => {
            return Err(anyhow::Error::msg(format!("Invalid DNS AA: {}", x)));
        }
    };

    let truncation: bool = match (buf[2] >> 1) & 0x1 {
        0 => false,
        1 => true,
        x => {
            return Err(anyhow::Error::msg(format!("Invalid DNS truncation: {}", x)));
        }
    };

    let recursion_desired: bool = match (buf[2] >> 0) & 0x1 {
        0 => false,
        1 => true,
        x => {
            return Err(anyhow::Error::msg(format!(
                "Invalid DNS recursion_desired: {}",
                x
            )));
        }
    };

    let recursion_available: bool = match (buf[3] >> 7) & 0x1 {
        0 => false,
        1 => true,
        x => {
            return Err(anyhow::Error::msg(format!(
                "Invalid DNS recursion available: {}",
                x
            )));
        }
    };

    let reserved: u8 = (buf[3] >> 4) & 0x7;

    let response_code: u8 = buf[3] & 0xf;

    let question_count: u16 = u16::from_be_bytes(buf[4..6].try_into()?);

    let answer_record_count: u16 = u16::from_be_bytes(buf[6..8].try_into()?);

    let authority_record_count: u16 = u16::from_be_bytes(buf[8..10].try_into()?);

    let additional_record_count: u16 = u16::from_be_bytes(buf[10..12].try_into()?);

    Ok(DnsHeader {
        packet_id,
        query_type,
        opcode,
        auth_answer,
        truncation,
        recursion_desired,
        recursion_available,
        reserved,
        response_code,
        question_count,
        answer_record_count,
        authority_record_count,
        additional_record_count,
    })
}

#[derive(Debug)]
struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<Question>,
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
