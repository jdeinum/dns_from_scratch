use anyhow::{Result, ensure};
use bytes::Bytes;

pub trait DnsData: Sized {
    fn encode(&self) -> Result<Bytes>;
    fn decode(buf: &Bytes, pos: usize) -> Result<(usize, Self)>;
}

pub fn parse_u8(buf: &Bytes, pos: usize) -> Result<(usize, u8)> {
    Ok((
        pos + 1,
        u8::from_be_bytes(buf.slice(pos..pos + 1).as_ref().try_into()?),
    ))
}

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

pub fn parse_string(buf: &Bytes, pos: usize) -> Result<(usize, String)> {
    // first we'll read the length of the string
    let length = usize::from_be_bytes(buf.slice(pos..pos + 1).as_ref().try_into()?);
    ensure!(length < u8::MAX as usize, "String too large");

    Ok((
        pos + 1 + length,
        String::from_utf8(buf.slice(pos + 1..pos + 1 + length).to_vec())?,
    ))
}

pub fn parse_data(buf: &Bytes, pos: usize, len: usize) -> Result<(usize, Bytes)> {
    Ok((pos + len, buf.slice(pos..pos + len).clone()))
}
