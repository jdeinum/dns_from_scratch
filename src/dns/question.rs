use anyhow::Error;
use anyhow::Result;
use anyhow::ensure;
use bytes::{BufMut, Bytes, BytesMut};
use tracing::info;
use tracing::instrument;

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
#[derive(Clone, Debug, Default)]
pub enum QuestionType {
    #[default]
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

impl TryInto<QuestionType> for i16 {
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

impl TryInto<i16> for QuestionType {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<i16, Self::Error> {
        Ok(match self {
            QuestionType::A => 1,
            QuestionType::NS => 2,
            QuestionType::MD => 3,
            QuestionType::MF => 4,
            QuestionType::CNAME => 5,
            QuestionType::SOA => 6,
            QuestionType::MB => 7,
            QuestionType::MG => 8,
            QuestionType::MR => 9,
            QuestionType::NULL => 10,
            QuestionType::WKS => 11,
            QuestionType::PTR => 12,
            QuestionType::HINFO => 13,
            QuestionType::MINFO => 14,
            QuestionType::MX => 15,
            QuestionType::TXT => 16,
            _ => return Err(Error::msg(format!("Invalid QuestionType: {:?}", self))),
        })
    }
}

#[derive(Clone, Default, Debug)]
pub struct LabelSet {
    pub labels: Vec<String>,
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

    pub fn as_domain(&self) -> String {
        self.labels.join(".")
    }
}

#[derive(Default, Clone, Debug)]
pub struct DnsQuestion {
    pub name: LabelSet,
    pub qtype: QuestionType,
    pub class: i16,
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();

        // label set
        buf.extend_from_slice(&self.name.encode()?);

        // type
        buf.put_i16(self.qtype.clone().try_into()?);

        // class
        buf.put_i16(1);

        Ok(buf.into())
    }
}

#[instrument(ret, err)]
pub fn parse_question(buf: &Bytes, start: usize) -> Result<(DnsQuestion, usize)> {
    // check that a null byte exists
    let label_end = buf.iter().find(|x| **x == 0);
    ensure!(label_end.is_some(), "No null byte in label");
    ensure!(buf.len() > 0, "Buffer to parse question from is empty");

    let mut q: DnsQuestion = DnsQuestion::default();
    let mut current = start;
    while buf[current] != 0 {
        let length = buf[current]; // single byte is the length
        info!("parsing label of length {length}");
        current += 1;
        let label = &buf[current..current + length as usize];
        info!("found label {}", String::from_utf8(label.to_vec())?);
        q.name.labels.push(String::from_utf8(label.to_vec())?);
        current += length as usize;
    }

    // we are currently at the null byte, add 1 to move to the question type
    current += 1;
    let qtype = i16::from_be_bytes(buf[current..current + 2].try_into()?);
    q.qtype = qtype.try_into()?;

    // class is the last 2 bytes
    current += 2;
    let class = i16::from_be_bytes(buf[current..current + 2].try_into()?);
    q.class = class;

    current += 2;

    Ok((q, current))
}

// the question section starts at byte 12 (after the header section)
// while the number of questions are located in the header
#[instrument(skip_all, ret, err)]
pub fn parse_questions(buf: &Bytes, num_questions: usize) -> Result<Vec<DnsQuestion>> {
    info!("Parsing questions");
    let mut start: usize = 0;
    let mut questions: Vec<DnsQuestion> = Vec::new();
    for _ in 0..num_questions {
        info!("parsing question");
        let (q, i) = parse_question(&buf, start)?;
        start += i;
        questions.push(q);
    }

    Ok(questions)
}

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

    #[test]
    fn test_labels_to_domain() -> Result<()> {
        let b: &[u8] = &[
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
            0x00, 0x01,
        ];
        let expected_domain = "google.com";
        let questions = parse_questions(&Bytes::copy_from_slice(b), 1)?;
        assert_eq!(questions.len(), 1);
        assert_eq!(&questions[0].name.as_domain(), expected_domain);
        assert_eq!(questions[0].class, 1);
        assert_eq!(questions[0].qtype.clone() as i16, 1);
        Ok(())
    }
}
