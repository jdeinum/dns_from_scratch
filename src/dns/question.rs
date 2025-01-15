use crate::dns::QuestionType;
use crate::dns::label::LabelSet;
use crate::parse::DnsData;
use crate::parse::parse_u16;
use anyhow::Result;
use anyhow::ensure;
use bytes::{BufMut, Bytes, BytesMut};
use tracing::instrument;

#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct DnsQuestion {
    pub name: LabelSet,
    pub qtype: QuestionType,
    pub class: u16,
}

impl DnsData for DnsQuestion {
    #[instrument(name = "Encoding DNS Question", skip_all)]
    fn encode(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();

        // label set
        buf.extend_from_slice(&self.name.encode()?);

        // type
        buf.put_u16(self.qtype.clone().try_into()?);

        // class
        buf.put_u16(self.class);

        Ok(buf.into())
    }
    #[instrument(name = "Decoding DNS Question", skip_all, ret)]
    fn decode(buf: &Bytes, pos: usize) -> Result<(usize, Self)> {
        // decode the label
        let (current, name) = LabelSet::decode(buf, pos)?;

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
    pub fn decode(buf: &Bytes, pos: usize, num_questions: usize) -> Result<(usize, Self)> {
        let mut res = Self::default();
        let mut current = pos;

        for _ in 0..num_questions {
            let (c, q) = DnsQuestion::decode(buf, current)?;
            res.questions.push(q);
            current = c;
        }

        Ok((current, res))
    }

    pub fn encode(&self, num_questions: usize) -> Result<Bytes> {
        // quick check to make sure we always encode all of the questions
        ensure!(
            num_questions == self.questions.len(),
            "num questions doesn't match vec length"
        );

        // encode the questions
        let mut buf = BytesMut::new();
        for q in self.questions.clone() {
            buf.extend_from_slice(&q.encode()?)
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

    impl Arbitrary for DnsQuestion {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let chars = [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
            ];

            // generate some number of labels
            let num_labels = (u8::arbitrary(g) % 5) + 2;

            // generate the labels
            // note that we have no way of knowing whether they are larger than 256 chars
            let mut name: LabelSet = LabelSet::default();
            for _ in 0..num_labels {
                let label_size = (u8::arbitrary(g) % 5) + 1;
                let mut label = Vec::new();

                for _ in 0..label_size {
                    label.push(u8::arbitrary(g) % 16);
                }

                name.labels.push(
                    label
                        .iter()
                        .map(|x| chars.get(*x as usize).unwrap())
                        .collect::<String>(),
                );
            }

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
            let buf = h.encode(h.questions.len()).unwrap();
            let (_, questions) = DnsQuestionSet::decode(&buf, 0, h.questions.len()).unwrap();
            assert_eq!(questions, h);
            TestResult::passed()
        }
    }
}
