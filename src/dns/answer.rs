use super::{LabelSet, QuestionType, parse_question, parse_questions};
use anyhow::Result;
use bytes::{BufMut, Bytes, BytesMut};
use std::{iter::Cycle, net::Ipv4Addr};

#[derive(Clone, Debug, Default)]
pub struct DnsAnswer {
    pub name: LabelSet,
    pub qtype: QuestionType,
    pub class: i16,
    pub ttl: i32,
    pub data: Vec<Ipv4Addr>,
}

impl DnsAnswer {
    pub fn encode(&self) -> Result<Bytes> {
        println!("encoding the following: {:?}", &self);

        let mut buf = BytesMut::new();

        // label set
        buf.extend_from_slice(&self.name.encode()?);

        // qtype
        buf.put_i16(self.qtype.clone().try_into()?);

        // class
        buf.put_i16(self.class);

        // tll -- hardcoded for now
        buf.put_i32(self.ttl);

        // length -- each IP is 4 bytes
        buf.put_u16(self.data.len() as u16 * 4);

        // data
        // ipv4 has to_bits, but it returns them according to native endianess
        // so we just encode them manually
        for ip in self.data.clone() {
            let x = ip.octets();
            buf.put_u8(x[3]);
            buf.put_u8(x[2]);
            buf.put_u8(x[1]);
            buf.put_u8(x[0]);
        }

        Ok(buf.into())
    }

    // num_answers is located in the header of the DNS message
    pub fn decode(buf: Bytes, start: usize, num_answers: u16) -> Result<(Self, usize)> {
        // first, we parse the label sequence, which consists of one or more of the following
        // see the serialization of the LabelSet for details
        // TODO: Should separate the label logic from the question, since its used in the answer
        let (question, mut current) = parse_question(&buf, start)?;

        // qtype
        let qtype = i16::from_be_bytes(buf[current..current + 2].try_into()?);
        let qtype: QuestionType = qtype.try_into()?;
        current += 2;

        // class
        let class = i16::from_be_bytes(buf[current..current + 2].try_into()?);
        current += 2;

        // ttl
        let ttl = i32::from_be_bytes(buf[current..current + 4].try_into()?);
        current += 4;

        // currently we are only interested in parsing A messages
        // which maps domain names to IP addresses
        let mut a: Vec<Ipv4Addr> = Vec::new();
        for _ in 0..num_answers {
            // each entry is 4 bytes
            let first_byte = buf[current + 3];
            let second_byte = buf[current + 2];
            let third_byte = buf[current + 1];
            let fourth_byte = buf[current + 0];

            a.push(Ipv4Addr::new(
                first_byte,
                second_byte,
                third_byte,
                fourth_byte,
            ));
            current += 4;
        }

        Ok((
            DnsAnswer {
                name: question.name,
                qtype,
                class,
                ttl,
                data: a,
            },
            current,
        ))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_ip_encode_endianess() -> Result<()> {
        let mut test_answer = DnsAnswer::default();
        let test_ip: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
        test_answer.qtype = QuestionType::A;
        test_answer.data.push(test_ip);

        let encoded = test_answer.encode()?;
        println!("encoded: {:?}", encoded);
        let decoded = DnsAnswer::decode(encoded, 0, 1)?;
        println!("decoded: {:?}", decoded);

        assert_eq!(decoded.0.data[0], test_ip);
        Ok(())
    }
}
