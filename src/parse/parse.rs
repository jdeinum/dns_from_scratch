use anyhow::{Result, ensure};
use bytes::Bytes;
use std::collections::HashMap;
use tracing::{debug, instrument};

pub type LabelMap<'a> = &'a mut HashMap<String, usize>;

pub trait DnsData: Sized {
    // encoding requires the item being encoded, the position in the complete buffer that is being
    // sent to the client (for compression purposes, like needing to know where you are in the full
    // buffer so that you can store offsets), and the label map, which stores the offset for
    // particular labels.
    fn encode(&self, pos: usize, label_map: LabelMap) -> Result<Bytes>;

    // decoding requires the full byte buffer, the position in that buffer where we should start
    // decoding, and the label map, which we build up over time while decoding.
    fn decode(buf: &Bytes, pos: usize, label_map: LabelMap) -> Result<(usize, Self)>;
}

pub fn parse_u8(buf: &Bytes, pos: usize) -> Result<(usize, u8)> {
    Ok((
        pos + 1,
        u8::from_be_bytes(buf.slice(pos..pos + 1).as_ref().try_into()?),
    ))
}

#[instrument(skip_all, ret)]
pub fn parse_u16(buf: &Bytes, pos: usize) -> Result<(usize, u16)> {
    Ok((
        pos + 2,
        u16::from_be_bytes(buf.slice(pos..pos + 2).as_ref().try_into()?),
    ))
}

pub fn parse_u32(buf: &Bytes, pos: usize) -> Result<(usize, u32)> {
    Ok((
        pos + 4,
        u32::from_be_bytes(buf.slice(pos..pos + 4).as_ref().try_into()?),
    ))
}

#[instrument(skip_all, ret)]
pub fn parse_string(buf: &Bytes, pos: usize) -> Result<(usize, String)> {
    // first we'll read the length of the string
    let (current, length) = parse_u16(buf, pos)?;
    debug!("Parsing string of length {length}");
    ensure!(length <= 0x3fff, "String too large");

    Ok((
        current + length as usize,
        String::from_utf8(buf.slice(current..current + length as usize).to_vec())?,
    ))
}

pub fn parse_data(buf: &Bytes, pos: usize, len: usize) -> Result<(usize, Bytes)> {
    Ok((pos + len, buf.slice(pos..pos + len).clone()))
}
