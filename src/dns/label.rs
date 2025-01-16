use crate::parse::DnsData;
use crate::parse::parse_string;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tracing::instrument;

#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct LabelSet {
    pub labels: Vec<String>,
}

impl DnsData for LabelSet {
    #[instrument(name = "Encoding Label", skip_all)]
    fn encode(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();
        for label in self.labels.clone() {
            buf.put_u8(label.len().try_into()?);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.put(&b"\x00"[..]);
        Ok(buf.into())
    }

    #[instrument(name = "Decoding Label", skip_all, ret)]
    fn decode(buf: &Bytes, pos: usize) -> Result<(usize, Self)> {
        let mut res = Self::default();
        let mut current = pos;
        while buf[current] != 0 {
            let (c, label) = parse_string(buf, current)?;
            res.labels.push(label);
            current = c;
        }
        Ok((current + 1, res)) // + 1 to put us one past the null byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;

    impl Arbitrary for LabelSet {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            // our alphabet for domain names
            // would be better to use the acutal allowed domain of characters
            // TODO
            let chars = [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
            ];

            // use some reasonable number of labels
            let num_labels = (u8::arbitrary(g) % 5) + 2;
            let mut labels: Vec<String> = Vec::new();
            for _ in 0..num_labels {
                // keep them a resonable size to make testing easier
                let label_size = (u8::arbitrary(g) % 5) + 1;

                // our actual string
                let mut label = Vec::new();
                for _ in 0..label_size {
                    label.push(u8::arbitrary(g) % 16);
                }

                labels.push(
                    label
                        .iter()
                        .map(|x| chars.get(*x as usize).unwrap())
                        .collect::<String>(),
                );
            }

            Self { labels }
        }
    }

    quickcheck! {
        fn decode_encode_labels(h: LabelSet) -> TestResult {
            let encoded_label = LabelSet::encode(&h).unwrap();
            let (_, decoded_header) = LabelSet::decode(&encoded_label, 0).unwrap();
            assert_eq!(decoded_header, h);
            TestResult::passed()
        }
    }
}
