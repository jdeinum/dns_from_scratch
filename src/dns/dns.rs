use anyhow::Result;
use bytes::Bytes;
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
            info!("{:?} bytes received from {:?}", len, addr);

            let len = self.sock.send_to(&buf[..len], addr).await?;
            info!("{:?} bytes sent", len);
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn address(&self) -> Result<String> {
        Ok(self.sock.local_addr()?.to_string())
    }
}

pub enum DnsPacketType {
    Query = 0,
    Response = 1,
}

pub struct DnsRequest {
    packet_id: u16,
    query_type: DnsPacketType,
    opcode: u8,
    auth_answer: bool,
    truncation: bool,
    recursion_desired: bool,
    recursion_available: bool,
    reserved: u8,
    response_code: u8,
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

pub struct DnsResponse {}

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
async fn parse_request(buf: Bytes) -> Result<DnsRequest> {
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

    Ok(DnsRequest {
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
