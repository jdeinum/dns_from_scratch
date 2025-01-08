use anyhow::Error;
use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};

// TYPE            value and meaning
// A               1 a host address
// NS              2 an authoritative name server
// MD              3 a mail destination (Obsolete - use MX)
// MF              4 a mail forwarder (Obsolete - use MX)
// CNAME           5 the canonical name for an alias
// SOA             6 marks the start of a zone of authority
// MB              7 a mailbox domain name (EXPERIMENTAL)
// MG              8 a mail group member (EXPERIMENTAL)
// MR              9 a mail rename domain name (EXPERIMENTAL)
// NULL            10 a null RR (EXPERIMENTAL)
// WKS             11 a well known service description
// PTR             12 a domain name pointer
// HINFO           13 host information
// MINFO           14 mailbox or mail list information
// MX              15 mail exchange
// TXT             16 text strings
pub enum QuestionType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MINFO = 14,
    MX = 15,
    TXT = 16,
}

impl TryInto<QuestionType> for u16 {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<QuestionType, Self::Error> {
        Ok(match self {
            1 => QuestionType::A,
            2 => QuestionType::NS,
            3 => QuestionType::MD,
            4 => QuestionType::MF,
            5 => QuestionType::CNAME,
            6 => QuestionType::SOA,
            7 => QuestionType::MB,
            8 => QuestionType::MG,
            9 => QuestionType::MR,
            10 => QuestionType::NULL,
            11 => QuestionType::WKS,
            12 => QuestionType::PTR,
            13 => QuestionType::HINFO,
            14 => QuestionType::MINFO,
            15 => QuestionType::MX,
            16 => QuestionType::TXT,
            _ => return Err(Error::msg(format!("Invalid QuestionType: {}", self))),
        })
    }
}

pub struct LabelSet {
    labels: Vec<String>,
}

impl LabelSet {
    // domain here should be of the form google.com , or more generally a set of strings seperated
    // by '.'
    // Only one byte can be used to encode the length of the string, so each label has a max length
    // of 256
    pub fn from_domain(domain: &str) -> Self {
        let labels: Vec<String> = domain.split(".").map(|x| x.to_string()).collect();
        Self { labels }
    }

    pub fn encode(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();
        for label in self.labels.clone() {
            buf.put_u8(label.len().try_into()?);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.put(&b"\x00"[..]);
        Ok(buf.into())
    }
}

pub struct Question {
    name: LabelSet,
    qtype: QuestionType,
    class: u8,
}

pub struct Questions {
    questions: Vec<Question>,
}

pub fn parse_question(buf: Bytes) -> Result<Question> {}

// the question section starts at byte 12 (after the header section)
// while the number of questions are located in the header
pub fn parse_questions(buf: Bytes, num_questions: usize) -> Result<Questions> {}

#[cfg(test)]
mod tests {

    use super::*;
    use anyhow::Result;

    #[test]
    fn test_domain_to_labels() -> Result<()> {
        let domain = "google.com";
        let labels = LabelSet::from_domain(&domain);
        let expected_bytes: &[u8] = &[
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];
        assert_eq!(labels.encode()?, expected_bytes);
        Ok(())
    }
}
