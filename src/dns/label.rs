use crate::parse::DnsData;
use crate::parse::LabelMap;
use crate::parse::parse_string;
use crate::parse::parse_u16;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tracing::debug;
use tracing::instrument;

pub enum LabelByte {
    Pointer,
    Null,
    Length,
}

impl LabelByte {
    pub fn from_byte(buf: &Bytes, pos: usize) -> Result<Self> {
        let (_, b) = parse_u16(buf, pos)?;

        match b {
            x if x == 0x00 => Ok(Self::Null),
            x if (x >> 14) & 0x3 == 3 => Ok(Self::Pointer),
            _ => Ok(Self::Length),
        }
    }
}

// Domains (RFC 1035 S4.1.4)
// The compression scheme allows a domain name in a message to be
// represented as either:
//    - a sequence of labels ending in a zero octet
//    - a pointer
//    - a sequence of labels ending with a pointer
//
//  From what I understand, these pointers can be recursive, as in a pointer can point to a
//  location that also has a pointer, consider the following:
//
//  Map:
//  c -> 10
//  b.c -> 15 -- raw label b + pointer to c
//
//  Now if we wish to encode a.b.c , we add it to the map:
//
//  Map:
//  c -> 10
//  b.c -> 15 -- raw label b + pointer to c
//  a.b.c -> 20 -- raw label a + pointer to b.c which it itself contains a pointer to c
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Domain {
    pub labels: Vec<Label>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub struct Label(pub String);

impl DnsData for Domain {
    #[instrument(name = "Encoding Label", skip_all)]
    fn encode(&self, pos: usize, label_map: LabelMap) -> Result<Bytes> {
        let mut buf = BytesMut::new();

        // we iterate over the range so we can easily skip what we've already covered
        for label_num in 0..self.labels.len() {
            // check if the domain we are interested in has already been seen before
            let label: String = self
                .labels
                .iter()
                .skip(label_num)
                .map(|x| x.0.as_str())
                .collect::<Vec<&str>>()
                .join(".");

            match label_map.get(&label) {
                // cache hit
                Some(offset) => {
                    // add offset as pointer
                    debug!(label = label, offset = offset, "found label in map");
                    create_and_add_pointer(*offset, &mut buf)?;

                    // at this point, if a.b.c is present in the label map, b.c should already be
                    // in the map as well, therefore we don't need to add anything else to the set
                    break;
                }
                // cache miss
                None => {
                    // on a miss, we only want to write the first part of the domain, because the
                    // later part of the domain might have already been seen
                    let l = self
                        .labels
                        .get(label_num)
                        .ok_or(anyhow::Error::msg("Label num too large"))?;

                    // before we insert anything inside of the buffer, we want to store our
                    // location in the domain map
                    let loc = pos + buf.len();
                    debug!(
                        label = label,
                        offset = loc,
                        "label not found in map, inserting"
                    );
                    label_map.insert(label, loc);

                    // first, we put the length of the string
                    let len = {
                        let len = l.0.len();
                        ensure!(len < 0xcfff as usize, "label should be smaller than 0xcfff");
                        let len = u16::try_from(len).with_context(
                            || "couldn't convert length into u16 while encoding label",
                        )? & 0xcfff as u16;
                        len
                    };

                    debug!(
                        position = buf.len() + pos,
                        "encoding {l:?} with length {len}"
                    );
                    buf.put_u16(len);

                    // then we put the string
                    buf.extend_from_slice(l.0.as_bytes());

                    // finally, if this is the last label in the series, we need to add a null byte
                    // to signal the end of the label
                    if label_num == self.labels.len() - 1 {
                        debug!(
                            label = "0x0000",
                            offset = pos + buf.len(),
                            "last label, inserting null byte"
                        );
                        buf.put_u16(0x0000);
                    }
                }
            }
        }

        Ok(buf.into())
    }

    #[instrument(name = "Decoding Label", skip_all, ret)]
    fn decode(buf: &Bytes, pos: usize, label_map: LabelMap) -> Result<(usize, Self)> {
        // where relative to pos are we in the buffer
        let mut current = pos;

        let mut res = Domain::default();

        // we want to keep track of where different domains are encoded, but at decoding time, we
        // can't tell where the domain ends until after we have either a pointer, or a null byte
        let mut offsets: Vec<(String, usize)> = Vec::new();

        // the domain ends when we reach either a pointer, or a null byte
        loop {
            debug!(offset = pos + current, "checking type");
            match LabelByte::from_byte(buf, current)? {
                // if we've hit the null, return the label set so far and move the cursor 1 past
                // the null byte
                LabelByte::Null => {
                    // update the map with the labels
                    for i in 0..offsets.len() {
                        let offset = offsets[i].1;

                        let x = offsets
                            .iter()
                            .skip(i)
                            .map(|(s, _)| s.as_str())
                            .collect::<Vec<&str>>()
                            .join(".");

                        if label_map.get(&x).is_none() {
                            debug!("inserting entry {x} with offset {offset}");
                            label_map.insert(x, offset);
                        }
                    }

                    break Ok((current + 2, res));
                }

                // if we hit a pointer, we'll add the labels to our result set
                // and return that
                LabelByte::Pointer => {
                    let (c, offset) = {
                        let (c, pointer) = parse_u16(buf, current)?;
                        let offset = pointer & 0x3fff;
                        debug!(offset = offset, pointer = pointer, "pointer found");
                        (c, offset)
                    };

                    // get the domain
                    let domain = {
                        let d = label_map
                            .iter()
                            .find(|(_, o)| **o == offset as usize)
                            .ok_or(anyhow::Error::msg(
                                "Encountered a label with an offset not located in the map",
                            ))?;
                        d.0.to_string()
                    };

                    // update our label map
                    for i in 0..offsets.len() {
                        let offset = offsets[i].1;

                        let mut x = offsets
                            .iter()
                            .skip(i)
                            .map(|(s, _)| s.as_str())
                            .collect::<Vec<&str>>()
                            .join(".");

                        x.push_str(&format!(".{}", domain.as_str()));

                        if label_map.get(&x).is_none() {
                            debug!("inserting entry {x} with offset {offset}");
                            label_map.insert(x, offset);
                        }
                    }

                    // add them to our set
                    res.labels
                        .extend(domain.clone().split(".").map(|x| Label(x.to_string())));

                    // a pointer ends the domain decoding
                    // no need to add +1 because there is no null byte
                    current = c;
                    break Ok((current, res));
                }

                // if its a length, we'll decode this label
                LabelByte::Length => {
                    // parse the label
                    let (c, s) = parse_string(buf, current)?;

                    // keep track of this label location within the buffer,
                    // it will later be used to update the label map
                    offsets.push((s.clone(), current));

                    // add the label to our results
                    res.labels.push(Label(s));

                    // update the current pointer
                    current = c;
                }
            }
        }

        // update the
    }
}

fn create_and_add_pointer(offset: usize, buf: &mut BytesMut) -> Result<()> {
    let pointer: u16 = ((offset & 0xffff) as u16) | 0xc000;
    debug!(offset = offset, pointer = pointer, "storing pointer");
    buf.put_u16(pointer);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::Arbitrary;
    use quickcheck::TestResult;
    use quickcheck::quickcheck;
    use std::collections::HashMap;

    impl Arbitrary for Domain {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            // our alphabet for domain names
            // would be better to use the acutal allowed domain of characters
            // TODO
            let chars = [
                '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
            ];

            // use some reasonable number of labels
            let num_labels = (u8::arbitrary(g) % 5) + 2;
            let mut labels: Vec<Label> = Vec::new();
            for _ in 0..num_labels {
                // keep them a resonable size to make testing easier
                let label_size = (u8::arbitrary(g) % 5) + 1;

                // our actual string
                let mut label = Vec::new();
                for _ in 0..label_size {
                    label.push(u8::arbitrary(g) % 16);
                }

                let l = label
                    .iter()
                    .map(|x| chars.get(*x as usize).unwrap())
                    .collect::<String>();

                labels.push(Label(l));
            }

            Self { labels }
        }
    }

    quickcheck! {
        fn encode_decode_labels(h: Domain) -> TestResult {
            let mut m: HashMap<String, usize> = HashMap::new();
            let encoded_domain = Domain::encode(&h, 0, &mut m).unwrap();
            let (_, decoded_domain) = Domain::decode(&encoded_domain, 0, &mut m).unwrap();
            assert_eq!(decoded_domain, h);
            TestResult::passed()
        }
    }
}
