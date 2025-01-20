use crate::parse::DnsData;
use crate::parse::LabelMap;
use crate::parse::parse_string;
use crate::parse::parse_u8;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tracing::info;
use tracing::instrument;

#[derive(Clone, Default, Debug, Eq, PartialEq, Hash)]
pub struct LabelSet {
    pub labels: Vec<String>,
}

impl DnsData for LabelSet {
    #[instrument(name = "Encoding Label", skip_all)]
    fn encode(&self, pos: usize, label_map: LabelMap) -> Result<Bytes> {
        info!(position = pos, "Encoding label");
        let mut buf: BytesMut = BytesMut::new();
        let mut current = 0;
        for label_num in 0..self.labels.len() {
            // if the label exists in the map, we write a pointer to it instead
            let full_current_label = self.labels.clone().split_off(label_num).join(".");
            info!(label = full_current_label, "looking for label");
            match label_map.get(&full_current_label) {
                // its in the map, add a pointer to its offset in the buffer
                Some(offset) => {
                    info!(
                        label = full_current_label,
                        offset = offset,
                        "found label in label map"
                    );
                    let pointer: u8 = TryInto::<u8>::try_into(*offset)?;
                    info!(
                        offset = pointer,
                        pointer = pointer | 0xc0,
                        "storing pointer"
                    );
                    buf.put_u8(pointer | 0xc0);
                }
                None => {
                    let label: String = self
                        .labels
                        .get(label_num)
                        .ok_or(anyhow::Error::msg("Label index out of range"))?
                        .to_string();

                    // store the label with the offset before we write the length
                    // because the buffer currently points at where the length will be stored
                    info!(
                        label = full_current_label,
                        offset = pos + current,
                        "did not find label, storing in map",
                    );
                    label_map.insert(full_current_label, pos + current);
                    buf.put_u8(label.len().try_into()?);
                    buf.extend_from_slice(label.as_bytes());
                }
            }
            current = buf.len();
        }
        buf.put(&b"\x00"[..]);
        Ok(buf.into())
    }

    #[instrument(name = "Decoding Label", skip_all, ret)]
    fn decode(buf: &Bytes, pos: usize, label_map: LabelMap) -> Result<(usize, Self)> {
        let mut res = Self::default();
        let mut current = pos;
        while buf[current] != 0 {
            // check whether this is a pointer to an existing label set, or to a single label
            // if it is a pointer, we just append the entries of the HashMap key to the what we
            // have already and return it
            if is_pointer(buf, current)? {
                info!("found pointer");
                // find the entry in the label map that corresponds to the offset in the pointer
                let (c, offset) = parse_u8(buf, current)?;
                current = c;
                let offset = offset & 0x3f;
                info!("pointer points to offset {offset:?}");
                let mut labels = label_map
                    .iter()
                    .find(|(_, v)| **v == offset as usize)
                    .map(|(k, _)| k)
                    .ok_or(anyhow::Error::msg(
                        "No entry in label map even though its a pointer",
                    ))?
                    .split(".")
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>();

                // append the rest of the labels and return it
                res.labels.append(&mut labels);
                break;
            } else {
                let (c, label) = parse_string(buf, current)?;
                res.labels.push(label);
                // add the label to the map
                label_map.insert(res.labels.join("."), current);
                current = c;
            }
        }
        Ok((current + 1, res)) // + 1 to put us one past the null byte
    }
}

fn is_pointer(buf: &Bytes, pos: usize) -> Result<bool> {
    let (_, b) = parse_u8(buf, pos)?;
    info!(offset = pos, value = b, "checking if pointer");
    return Ok((b >> 6) & 0x3 == 3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;
    use std::collections::HashMap;

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
            let mut m: HashMap<String, usize> = HashMap::new();
            let encoded_label = LabelSet::encode(&h, 0, &mut m).unwrap();
            let (_, decoded_label) = LabelSet::decode(&encoded_label, 0, &mut m).unwrap();
            assert_eq!(decoded_label, h);
            TestResult::passed()
        }
    }
}
