use anyhow::{Error, Result};

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
#[derive(Clone, Debug, Default, Eq, PartialEq, Hash)]
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

impl TryInto<u16> for QuestionType {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<u16, Self::Error> {
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
        })
    }
}
