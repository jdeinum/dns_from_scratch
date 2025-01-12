use anyhow::Result;
use anyhow::ensure;
use bytes::BufMut;
use bytes::Bytes;
use bytes::BytesMut;
use tracing::info;

#[derive(Clone, Default, Debug)]
pub struct LabelSet {
    pub labels: Vec<String>,
}

impl LabelSet {
    pub fn from_domain(domain: &str) -> Result<Self> {
        let labels: Vec<String> = domain.split(".").map(|x| x.to_string()).collect();

        // domain here should be of the form google.com , or more generally a set of strings seperated
        // by '.'
        // Only one byte can be used to encode the length of the string, so each label has a max length
        // of 256
        let too_long: Vec<&str> = labels
            .iter()
            .filter(|x| x.len() > 256)
            .map(|x| x.as_str())
            .collect();
        ensure!(
            too_long.is_empty(),
            format!("labels have a max length of 256: {too_long:?}")
        );
        Ok(Self { labels })
    }

    pub fn as_domain(&self) -> String {
        self.labels.join(".")
    }

    pub fn encode(&self) -> Result<Bytes> {
        let mut buf: BytesMut = BytesMut::new();
        for label in self.labels.clone() {
            buf.put_u8(label.len().try_into()?);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.put(&b"\x00"[..]);
        Ok(buf.into())
    }

    pub fn decode(buf: Bytes) -> Result<Self> {
        let mut current = 0;
        let mut res = Self::default();

        while buf[current] != 0 {
            let length = buf[current]; // single byte is the length
            info!("parsing label of length {length}");
            current += 1;
            let label = &buf[current..current + length as usize];
            info!("found label {}", String::from_utf8(label.to_vec())?);
            res.labels.push(String::from_utf8(label.to_vec())?);
            current += length as usize;
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_domain_to_labels() -> Result<()> {
        let domain = "google.com";
        let labels = LabelSet::from_domain(&domain)?;
        let expected_bytes: &[u8] = &[
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        ];
        assert_eq!(labels.encode()?, expected_bytes);
        Ok(())
    }
}
