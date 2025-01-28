use crate::dns::QuestionType;
use crate::dns::label::Domain;
use crate::parse::DnsData;
use crate::parse::LabelMap;
use crate::parse::parse_u16;
use anyhow::Result;
use anyhow::ensure;
use bytes::{BufMut, Bytes, BytesMut};
use tracing::info;
use tracing::instrument;

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    pub name: Domain,
    pub qtype: QuestionType,
    pub class: u16,
}

impl DnsData for DnsQuestion {
    #[instrument(name = "Encoding DNS Question", skip_all, parent = None)]
    fn encode(&self, pos: usize, label_map: LabelMap) -> Result<Bytes> {
        info!(position = pos, "Encoding Question");
        let mut buf: BytesMut = BytesMut::new();

        buf.extend_from_slice(&self.name.encode(pos, label_map)?);

        // type
        buf.put_u16(self.qtype.clone().try_into()?);

        // class
        buf.put_u16(self.class);

        Ok(buf.into())
    }

    #[instrument(name = "Decoding DNS Question", skip_all, ret, parent = None)]
    fn decode(buf: &Bytes, pos: usize, label_map: LabelMap) -> Result<(usize, Self)> {
        let (current, name) = Domain::decode(buf, pos, label_map)?;

        // question type
        let (current, qtype) = {
            let (c, q) = parse_u16(buf, current)?;
            (c, q.try_into()?)
        };

        // class type
        let (current, class) = parse_u16(buf, current)?;

        Ok((current, Self { name, qtype, class }))
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct DnsQuestionSet {
    pub questions: Vec<DnsQuestion>,
}

impl DnsQuestionSet {
    pub fn decode(
        buf: &Bytes,
        pos: usize,
        num_questions: usize,
        label_map: LabelMap,
    ) -> Result<(usize, Self)> {
        let mut res = Self::default();
        let mut current = pos;

        for _ in 0..num_questions {
            let (c, q) = DnsQuestion::decode(buf, current, label_map)?;
            res.questions.push(q);
            current = c;
        }

        Ok((current, res))
    }

    pub fn encode(&self, num_questions: usize, label_map: LabelMap, pos: usize) -> Result<Bytes> {
        // quick check to make sure we always encode all of the questions
        ensure!(
            num_questions == self.questions.len(),
            "num questions doesn't match vec length"
        );
        let mut current = 0;

        // encode the questions
        let mut buf = BytesMut::new();
        for q in self.questions.clone() {
            buf.extend_from_slice(&q.encode(pos + current, label_map)?);
            current = buf.len();
        }

        Ok(buf.into())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;
    use std::collections::HashMap;

    impl Arbitrary for DnsQuestion {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let name: Domain = Domain::arbitrary(g);
            let class = u16::arbitrary(g);
            let qtype = (u16::arbitrary(g) % 16) + 1;
            let qtype: QuestionType = qtype.try_into().unwrap();

            Self { name, class, qtype }
        }
    }

    impl Arbitrary for DnsQuestionSet {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            // generate the number of questions in this request
            let num_questions = u8::arbitrary(g) % 5;

            // generate that number of questions
            let mut questions = Vec::new();
            for _ in 0..num_questions {
                let q = DnsQuestion::arbitrary(g);
                questions.push(q);
            }

            Self { questions }
        }
    }

    quickcheck! {
        fn encode_decode_questions(h: DnsQuestionSet) -> TestResult {
            let mut m: HashMap<String, usize> = HashMap::new();
            let buf = h.encode(h.questions.len(), &mut m, 0).unwrap();
            let (_, questions) = DnsQuestionSet::decode(&buf, 0, h.questions.len(), &mut m).unwrap();
            assert_eq!(questions, h);
            TestResult::passed()
        }
    }
}
