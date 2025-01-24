use crate::parse::DnsData;
use crate::parse::LabelMap;
use crate::parse::parse_string;
use crate::parse::parse_u16;
use anyhow::Result;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tracing::debug;
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
            // if the remaining labels

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
                    let pointer: u16 = ((offset & 0xffff) as u16) | 0xc000; // chop anything bigger off, may not
                    // be the best choice
                    info!(offset = offset, pointer = pointer, "storing pointer");
                    buf.put_u16(pointer);
                    break;
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

        let mut local_label: Vec<(usize, String)> = Vec::new();

        while buf[current] != 0 {
            // check whether this is a pointer to an existing label set, or to a single label
            // if it is a pointer, we just append the entries of the HashMap key to the what we
            // have already and return it
            if is_pointer(buf, current)? {
                // find the entry in the label map that corresponds to the offset in the pointer
                let (c, pointer) = parse_u16(buf, current)?;
                current = c;
                let offset = pointer & 0x3fff;
                info!(offset = offset, pointer = pointer, "pointer found");
                debug!("label map: {label_map:?}");
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
                info!(offset = current, "not a pointer, parsing string");
                let (c, label) = parse_string(buf, current)?;
                res.labels.push(label.clone());
                local_label.push((current, label));
                info!(offset = current, "not a pointer, parsing string");
                current = c;
            }
        }
        // Update the label map with the current labels
        debug!(local_labels = ?local_label, "adding labels to map");
        for label_num in 0..local_label.len() {
            let offset = local_label[label_num].0;
            let label = local_label
                .iter()
                .skip(label_num)
                .map(|(_, x)| x.to_string())
                .collect::<Vec<String>>()
                .join(".");
            debug!(label = label, "looking for label in map");

            if label_map.get(&label).is_none() {
                info!(label = label, offset = offset, "adding label to map");
                label_map.insert(label, offset);
            } else {
                debug!(
                    label = label,
                    offset = offset,
                    "not adding label to map, already at {}",
                    label_map.get(&label).unwrap()
                );
            }
        }

        Ok((current + 1, res)) // + 1 to put us one past the null byte
    }
}

fn is_pointer(buf: &Bytes, pos: usize) -> Result<bool> {
    let (_, b) = parse_u16(buf, pos)?;
    info!(offset = pos, value = b, "checking if pointer");
    return Ok((b >> 14) & 0x3 == 3);
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
