use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{SystemTime, UNIX_EPOCH};

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

pub struct RandomFillTask {
  buffer: Vec<u8>,
  offset: usize,
  length: usize,
}

#[napi]
impl Task for RandomFillTask {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> Result<Self::Output> {
    let rng = SystemRandom::new();
    rng
      .fill(&mut self.buffer[self.offset..self.offset + self.length])
      .map_err(|_| Error::new(Status::GenericFailure, "Random fill failed"))?;
    Ok(std::mem::take(&mut self.buffer))
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

#[napi(js_name = "randomFill")]
pub fn random_fill(
  buffer: Uint8Array,
  offset: Option<u32>,
  size: Option<u32>,
) -> Result<AsyncTask<RandomFillTask>> {
  let off = offset.unwrap_or(0) as usize;
  let len = size.unwrap_or((buffer.len() - off) as u32) as usize;
  if off + len > buffer.len() {
    return Err(Error::new(Status::InvalidArg, "Offset out of bounds"));
  }
  Ok(AsyncTask::new(RandomFillTask {
    buffer: buffer.to_vec(),
    offset: off,
    length: len,
  }))
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

#[napi(js_name = "randomUUIDv7")]
pub fn random_uuid_v7() -> Result<String> {
  let now_ms = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| Error::new(Status::GenericFailure, "Clock error"))?
    .as_millis() as u64;

  let mut rand_bytes = [0u8; 10];
  let rng = SystemRandom::new();
  rng
    .fill(&mut rand_bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  let mut bytes = [0u8; 16];
  // 48-bit timestamp in big endian
  bytes[0] = ((now_ms >> 40) & 0xff) as u8;
  bytes[1] = ((now_ms >> 32) & 0xff) as u8;
  bytes[2] = ((now_ms >> 24) & 0xff) as u8;
  bytes[3] = ((now_ms >> 16) & 0xff) as u8;
  bytes[4] = ((now_ms >> 8) & 0xff) as u8;
  bytes[5] = (now_ms & 0xff) as u8;

  // Version 7 (0b0111) in top 4 bits of bytes[6]
  bytes[6] = 0x70 | (rand_bytes[0] & 0x0f);
  bytes[7] = rand_bytes[1];

  // Variant RFC 9562 (0b10) in top 2 bits of bytes[8]
  bytes[8] = 0x80 | (rand_bytes[2] & 0x3f);
  bytes[9..16].copy_from_slice(&rand_bytes[3..10]);

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
