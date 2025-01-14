use super::DnsQuestionSet;
use crate::dns::DnsQuestion;
use crate::dns::QuestionType;
use crate::dns::label::LabelSet;
use crate::parse::DnsData;
use crate::parse::parse_data;
use crate::parse::parse_u16;
use crate::parse::parse_u32;
use anyhow::Result;
use anyhow::ensure;
use bytes::{BufMut, Bytes, BytesMut};

#[derive(Clone, Debug, Default)]
pub struct DnsAnswer {
    pub name: LabelSet,
    pub qtype: QuestionType,
    pub class: u16,
    pub ttl: u32,
    pub data: Bytes,
}

impl DnsData for DnsAnswer {
    fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::new();

        // label set
        buf.extend_from_slice(&self.name.encode()?);

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

    fn decode(buf: &Bytes, pos: usize) -> Result<(usize, Self)> {
        // get the domain
        let (current, name) = LabelSet::decode(buf, pos)?;

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

impl DnsAnswer {
    // TODO
    pub fn from_question(_q: DnsQuestion) -> Result<Self> {
        Ok(Self::default())
    }
}

#[derive(Default, Debug)]
pub struct DnsAnswerSet {
    pub answers: Vec<DnsAnswer>,
}

impl DnsAnswerSet {
    pub fn encode(&self, num_answers: usize) -> Result<Bytes> {
        // quick check to make sure we always encode all of the questions
        ensure!(
            num_answers == self.answers.len(),
            "num answers doesn't match vec length"
        );

        // encode the questions
        let mut buf = BytesMut::new();
        for a in self.answers.clone() {
            buf.extend_from_slice(&a.encode()?)
        }

        Ok(buf.into())
    }

    pub fn decode(buf: &Bytes, pos: usize, num_answers: usize) -> Result<(usize, Self)> {
        let mut res = Self::default();
        let mut current = pos;

        for _ in 0..num_answers {
            let (c, a) = DnsAnswer::decode(buf, current)?;
            res.answers.push(a);
            current = c;
        }

        Ok((current, res))
    }
}

impl DnsAnswerSet {
    pub fn from_questions(questions: DnsQuestionSet) -> Result<Self> {
        // TODO: Use rayon or something to make this concurrent
        let answers: Result<Vec<DnsAnswer>> = questions
            .questions
            .into_iter()
            .map(|q| DnsAnswer::from_question(q))
            .collect();
        let answers = answers?;
        Ok(Self { answers })
    }
}

#[cfg(test)]
mod tests {}
