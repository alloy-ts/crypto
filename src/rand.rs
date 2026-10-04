use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::rand::{SecureRandom, SystemRandom};

#[napi(js_name = "randomBytes")]
pub fn random_bytes(size: u32) -> Result<Buffer> {
  let mut buf = vec![0u8; size as usize];
  let rng = SystemRandom::new();
  rng
    .fill(&mut buf)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
  Ok(Buffer::from(buf))
}

#[napi(js_name = "randomFillSync")]
pub fn random_fill_sync(
  buffer: Uint8Array,
  offset: Option<u32>,
  size: Option<u32>,
) -> Result<Uint8Array> {
  let off = offset.unwrap_or(0) as usize;
  let len = size.unwrap_or((buffer.len() - off) as u32) as usize;
  if off + len > buffer.len() {
    return Err(Error::new(Status::InvalidArg, "Offset out of bounds"));
  }
  let mut vec = buffer.to_vec();
  let rng = SystemRandom::new();
  rng
    .fill(&mut vec[off..off + len])
    .map_err(|_| Error::new(Status::GenericFailure, "Random fill failed"))?;
  Ok(Uint8Array::from(vec))
}

#[napi(js_name = "randomInt")]
pub fn random_int(min: i64, max: Option<i64>) -> Result<i64> {
  let (low, high) = match max {
    Some(m) => (min, m),
    None => (0, min),
  };
  if low >= high {
    return Err(Error::new(Status::InvalidArg, "min must be less than max"));
  }
  let range = (high - low) as u64;
  let mut bytes = [0u8; 8];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
  let val = u64::from_le_bytes(bytes) % range;
  Ok(low + (val as i64))
}

#[napi(js_name = "randomUUID")]
pub fn random_uuid() -> Result<String> {
  let mut bytes = [0u8; 16];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
  // Set version 4
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant RFC 4122
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  Ok(format!(
    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
    u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
    u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
    u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
    u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
    u64::from_be_bytes([
      0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ])
  ))
}
