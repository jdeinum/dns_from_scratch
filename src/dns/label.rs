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
mod tests {}
