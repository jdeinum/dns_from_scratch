use crate::parse::{DnsData, LabelMap};
use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use tracing::instrument;

#[derive(Debug, PartialEq, Eq, Default, Clone)]
pub enum DnsPacketType {
    #[default]
    Query = 0,
    Response = 1,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
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

impl DnsData for DnsHeader {
    #[instrument(name = "Encoding DNS Header", skip_all)]
    fn encode(&self, _: usize, _: LabelMap) -> Result<Bytes> {
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

        Ok(buf.into())
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
    #[instrument(name = "Decoding DNS Header", skip_all, ret)]
    fn decode(buf: &Bytes, pos: usize, _: LabelMap) -> Result<(usize, Self)> {
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

        Ok((pos + 12, Self {
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
        }))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::parse::DnsData;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;
    use std::collections::HashMap;

    impl From<bool> for DnsPacketType {
        fn from(value: bool) -> Self {
            match value {
                false => DnsPacketType::Query,
                true => DnsPacketType::Response,
            }
        }
    }

    impl Arbitrary for DnsHeader {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let packet_id = u16::arbitrary(g);
            let query_type: DnsPacketType = bool::arbitrary(g).into();
            let opcode = u8::arbitrary(g) & 0xf;
            let auth_answer = bool::arbitrary(g);
            let truncation = bool::arbitrary(g);
            let recursion_desired = bool::arbitrary(g);
            let recursion_available = bool::arbitrary(g);
            let reserved = u8::arbitrary(g) & 0x7;
            let response_code = u8::arbitrary(g) & 0xf;
            let question_count = u16::arbitrary(g);
            let answer_record_count = u16::arbitrary(g);
            let authority_record_count = u16::arbitrary(g);
            let additional_record_count = u16::arbitrary(g);

            Self {
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
                additional_record_count,
                authority_record_count,
            }
        }
    }

    quickcheck! {
        fn decode_encode_header(h: DnsHeader) -> TestResult {
            let mut m: HashMap<String, usize> = HashMap::new();
            let encoded_header = DnsHeader::encode(&h, 0, &mut m).unwrap();
            let (index, decoded_header) = DnsHeader::decode(&encoded_header, 0, &mut m).unwrap();
            assert_eq!(index, 12); // header is 12 bytes long, which means we should be at byte 12
            assert_eq!(decoded_header, h);
            TestResult::passed()
        }
    }
}
