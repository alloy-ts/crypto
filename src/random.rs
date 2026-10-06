use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{SystemTime, UNIX_EPOCH};

fn fill_random_bytes(buf: &mut [u8]) -> Result<()> {
  let rng = SystemRandom::new();
  rng
    .fill(buf)
    .map_err(|_| Error::new(Status::GenericFailure, "Failed to generate random bytes"))
}

#[napi(js_name = "randomBytes")]
pub fn random_bytes(size: u32) -> Result<Buffer> {
  if size > (i32::MAX as u32) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: size must not be larger than 2**31 - 1",
    ));
  }
  let mut buf = vec![0u8; size as usize];
  fill_random_bytes(&mut buf)?;
  Ok(Buffer::from(buf))
}

pub struct RandomBytesTask {
  size: usize,
}

#[napi]
impl Task for RandomBytesTask {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> Result<Self::Output> {
    let mut buf = vec![0u8; self.size];
    fill_random_bytes(&mut buf)?;
    Ok(buf)
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

#[napi(js_name = "randomBytesAsync")]
pub fn random_bytes_async(size: u32) -> Result<AsyncTask<RandomBytesTask>> {
  if size > (i32::MAX as u32) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: size must not be larger than 2**31 - 1",
    ));
  }
  Ok(AsyncTask::new(RandomBytesTask {
    size: size as usize,
  }))
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
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: offset or size out of bounds",
    ));
  }
  let mut vec = buffer.to_vec();
  fill_random_bytes(&mut vec[off..off + len])?;
  Ok(Uint8Array::from(vec))
}

pub struct RandomFillTask {
  buffer: Vec<u8>,
  offset: usize,
  size: usize,
}

#[napi]
impl Task for RandomFillTask {
  type Output = Vec<u8>;
  type JsValue = Uint8Array;

  fn compute(&mut self) -> Result<Self::Output> {
    fill_random_bytes(&mut self.buffer[self.offset..self.offset + self.size])?;
    Ok(std::mem::take(&mut self.buffer))
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Uint8Array::from(output))
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
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: offset or size out of bounds",
    ));
  }
  Ok(AsyncTask::new(RandomFillTask {
    buffer: buffer.to_vec(),
    offset: off,
    size: len,
  }))
}

#[napi(js_name = "randomInt")]
pub fn random_int(min: i64, max: Option<i64>) -> Result<i64> {
  let (low, high) = match max {
    Some(m) => (min, m),
    None => (0, min),
  };
  if low >= high {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_INVALID_ARG_VALUE: min must be less than max",
    ));
  }
  let range = (high - low) as u64;
  let max_range = 1u64 << 48;
  if range > max_range {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: range (max - min) must be less than 2**48",
    ));
  }

  // Modulo bias elimination
  let limit = u64::MAX - (u64::MAX % range);
  loop {
    let mut bytes = [0u8; 8];
    fill_random_bytes(&mut bytes)?;
    let val = u64::from_be_bytes(bytes);
    if val < limit {
      return Ok(low + ((val % range) as i64));
    }
  }
}

#[napi(js_name = "randomUUID")]
pub fn random_uuid() -> Result<String> {
  let mut bytes = [0u8; 16];
  fill_random_bytes(&mut bytes)?;

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
  let mut bytes = [0u8; 16];
  fill_random_bytes(&mut bytes)?;

  let now_ms = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| Error::new(Status::GenericFailure, "System time before epoch"))?
    .as_millis() as u64;

  // 48-bit timestamp
  bytes[0] = ((now_ms >> 40) & 0xff) as u8;
  bytes[1] = ((now_ms >> 32) & 0xff) as u8;
  bytes[2] = ((now_ms >> 24) & 0xff) as u8;
  bytes[3] = ((now_ms >> 16) & 0xff) as u8;
  bytes[4] = ((now_ms >> 8) & 0xff) as u8;
  bytes[5] = (now_ms & 0xff) as u8;

  // Version 7: 0b0111
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  // Variant RFC 9562: 0b10
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
