use crate::dns::QuestionType;
use crate::dns::label::Domain;
use crate::parse::DnsData;
use crate::parse::LabelMap;
use crate::parse::parse_data;
use crate::parse::parse_u16;
use crate::parse::parse_u32;
use anyhow::Result;
use anyhow::ensure;
use bytes::{BufMut, Bytes, BytesMut};
use tracing::info;
use tracing::instrument;

#[derive(Clone, Debug, Default, Hash, Eq, PartialEq)]
pub struct DnsAnswer {
    pub name: Domain,
    pub qtype: QuestionType,
    pub class: u16,
    pub ttl: u32,
    pub data: Bytes,
}

impl DnsData for DnsAnswer {
    #[instrument(name = "Encoding DNS Answer", skip_all, parent = None)]
    fn encode(&self, pos: usize, label_map: LabelMap) -> Result<Bytes> {
        info!(position = pos, "Encoding Answer");
        let mut buf = BytesMut::new();

        // label set
        buf.extend_from_slice(&self.name.encode(pos, label_map)?);

        // qtype
        buf.put_u16(self.qtype.clone().try_into()?);

        // class
        buf.put_u16(self.class);

        // tll -- hardcoded for now
        buf.put_u32(self.ttl);

        // length -- each IP is 4 bytes
        buf.put_u16(self.data.len() as u16 * 4);

        // data
        buf.extend_from_slice(&self.data);

        Ok(buf.into())
    }

    #[instrument(name = "Decoding DNS Answer", skip_all, ret, parent = None)]
    fn decode(buf: &Bytes, pos: usize, label_map: LabelMap) -> Result<(usize, Self)> {
        // get the domain
        let (current, name) = Domain::decode(buf, pos, label_map)?;

        // qtype
        let (current, qtype) = {
            let (c, q) = parse_u16(&buf, current)?;
            let qtype: QuestionType = q.try_into()?;
            (c, qtype)
        };

        // class
        let (current, class) = parse_u16(&buf, current)?;

        // ttl
        let (current, ttl) = parse_u32(&buf, current)?;

        // parse the length
        let (current, data_length) = parse_u16(&buf, current)?;

        // parse the data according to the length and type
        let (current, data) = parse_data(buf, current, data_length as usize)?;

        Ok((current, Self {
            name,
            qtype,
            ttl,
            class,
            data,
        }))
    }
}

#[derive(Default, Debug, Clone, Hash, Eq, PartialEq)]
pub struct DnsAnswerSet {
    pub answers: Vec<DnsAnswer>,
}

impl DnsAnswerSet {
    pub fn encode(&self, num_answers: usize, label_map: LabelMap, pos: usize) -> Result<Bytes> {
        // quick check to make sure we always encode all of the questions
        ensure!(
            num_answers == self.answers.len(),
            "num answers doesn't match vec length"
        );

        let mut current = 0;

        // encode the questions
        let mut buf = BytesMut::new();
        for a in self.answers.clone() {
            buf.extend_from_slice(&a.encode(pos + current, label_map)?);
            current = buf.len();
        }

        Ok(buf.into())
    }

    pub fn decode(
        buf: &Bytes,
        pos: usize,
        num_answers: usize,
        label_map: LabelMap,
    ) -> Result<(usize, Self)> {
        let mut res = Self::default();
        let mut current = pos;

        for _ in 0..num_answers {
            let (c, a) = DnsAnswer::decode(buf, current, label_map)?;
            res.answers.push(a);
            current = c;
        }

        Ok((current, res))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::dns::Label;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;
    use std::collections::HashMap;

    impl Arbitrary for DnsAnswer {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let chars = [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
            ];

            // generate some number of labels
            let num_labels = (u8::arbitrary(g) % 5) + 2;

            // generate the labels
            // note that we have no way of knowing whether they are larger than 256 chars
            let mut name: Domain = Domain::default();
            for _ in 0..num_labels {
                let label_size = (u16::arbitrary(g) % 5) + 1;
                let mut label = Vec::new();

                for _ in 0..label_size {
                    label.push(u8::arbitrary(g) % 16);
                }

                let l = label
                    .iter()
                    .map(|x| chars.get(*x as usize).unwrap())
                    .collect::<String>();

                name.labels.push(Label(l));
            }

            let class = u16::arbitrary(g);
            let qtype = (u16::arbitrary(g) % 16) + 1;
            let qtype: QuestionType = qtype.try_into().unwrap();
            let ttl: u32 = (u32::arbitrary(g) % 256) + 5;
            let mut data: Vec<u8> = Vec::new();

            for _ in 0..4 {
                data.push(u8::arbitrary(g) + 1);
            }

            Self {
                name,
                class,
                qtype,
                ttl,
                data: data.into(),
            }
        }
    }

    impl Arbitrary for DnsAnswerSet {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            // generate the number of questions in this request
            let num_answers = u8::arbitrary(g) % 5;

            // generate that number of questions
            let mut answers = Vec::new();
            for _ in 0..num_answers {
                let q = DnsAnswer::arbitrary(g);
                answers.push(q);
            }

            Self { answers }
        }
    }

    // quickcheck! {
    //     fn encode_decode_answers(h: DnsAnswerSet) -> TestResult {
    //         let mut m: HashMap<String, usize> = HashMap::new();
    //         let buf = h.encode(h.answers.len(), &mut m, 0).unwrap();
    //         let (_, questions) = DnsAnswerSet::decode(&buf, 0, h.answers.len(), &mut m).unwrap();
    //         assert_eq!(questions, h);
    //         TestResult::passed()
    //     }
    // }
}
