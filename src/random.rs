use std::time::{SystemTime, UNIX_EPOCH};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::rand::{SecureRandom, SystemRandom};

const MAX_SIZE: f64 = 2147483647.0; // 2**31 - 1
const MAX_SAFE_INT: i64 = 9007199254740991; // 2**53 - 1
const MIN_SAFE_INT: i64 = -9007199254740991;
const MAX_RANGE: i64 = 281474976710656; // 2**48

fn get_random_bytes(len: usize) -> Result<Vec<u8>> {
  let mut buf = vec![0u8; len];
  if len > 0 {
    let rng = SystemRandom::new();
    rng
      .fill(&mut buf)
      .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
  }
  Ok(buf)
}

fn fill_bytes(slice: &mut [u8]) -> Result<()> {
  if !slice.is_empty() {
    let rng = SystemRandom::new();
    rng
      .fill(slice)
      .map_err(|_| Error::new(Status::GenericFailure, "Random fill failed"))?;
  }
  Ok(())
}

fn generate_unbiased_int(min: i64, max: i64) -> Result<i64> {
  let range = (max - min) as u64;
  if range == 0 {
    return Ok(min);
  }
  let zone = u64::MAX - (u64::MAX % range);
  let rng = SystemRandom::new();
  loop {
    let mut bytes = [0u8; 8];
    rng
      .fill(&mut bytes)
      .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
    let val = u64::from_le_bytes(bytes);
    if val < zone {
      return Ok(min + ((val % range) as i64));
    }
  }
}

#[napi(js_name = "randomBytes")]
pub fn random_bytes(size: f64) -> Result<Buffer> {
  if size.is_nan() || size < 0.0 || size > MAX_SIZE {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: The value of \"size\" is out of range.",
    ));
  }
  let sz = size as usize;
  let bytes = get_random_bytes(sz)?;
  Ok(Buffer::from(bytes))
}

#[napi(js_name = "randomBytesAsync")]
pub fn random_bytes_async(size: f64) -> Result<Buffer> {
  random_bytes(size)
}

#[napi(js_name = "randomFillSync")]
pub fn random_fill_sync(
  mut buffer: Uint8Array,
  offset: Option<f64>,
  size: Option<f64>,
) -> Result<Uint8Array> {
  let total_len = buffer.len();

  let off = offset.unwrap_or(0.0);
  if off.is_nan() || off < 0.0 || off > MAX_SIZE || off > total_len as f64 {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: offset is out of range",
    ));
  }
  let off_idx = off as usize;

  let default_sz = (total_len - off_idx) as f64;
  let sz = size.unwrap_or(default_sz);
  if sz.is_nan() || sz < 0.0 || sz > MAX_SIZE || (off_idx + sz as usize) > total_len {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: size is out of range",
    ));
  }
  let sz_len = sz as usize;

  let slice = unsafe { &mut buffer.as_mut()[off_idx..off_idx + sz_len] };
  fill_bytes(slice)?;
  Ok(buffer)
}

#[napi(js_name = "randomFill")]
pub fn random_fill(
  buffer: Uint8Array,
  offset: Option<f64>,
  size: Option<f64>,
) -> Result<Uint8Array> {
  random_fill_sync(buffer, offset, size)
}

#[napi(js_name = "randomInt")]
pub fn random_int(arg1: f64, arg2: Option<f64>) -> Result<i64> {
  let (min_val, max_val) = match arg2 {
    Some(m) => (arg1, m),
    None => (0.0, arg1),
  };

  if min_val.is_nan() || min_val < (MIN_SAFE_INT as f64) || min_val > (MAX_SAFE_INT as f64) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: min is not a safe integer",
    ));
  }
  if max_val.is_nan() || max_val < (MIN_SAFE_INT as f64) || max_val > (MAX_SAFE_INT as f64) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: max is not a safe integer",
    ));
  }

  let min_i = min_val as i64;
  let max_i = max_val as i64;

  if min_i >= max_i {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: min must be less than max",
    ));
  }

  let range = max_i - min_i;
  if range >= MAX_RANGE {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: range must be less than 2**48",
    ));
  }

  generate_unbiased_int(min_i, max_i)
}

#[napi(object)]
#[derive(Default)]
pub struct RandomUuidOptions {
  pub disable_entropy_cache: Option<bool>,
}

#[napi(js_name = "randomUUID")]
pub fn random_uuid(_options: Option<RandomUuidOptions>) -> Result<String> {
  let mut bytes = [0u8; 16];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  bytes[6] = (bytes[6] & 0x0f) | 0x40;
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
pub fn random_uuid_v7(_options: Option<RandomUuidOptions>) -> Result<String> {
  let mut bytes = [0u8; 16];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  let now_ms = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| Error::new(Status::GenericFailure, "System time error"))?
    .as_millis() as u64;

  bytes[0] = ((now_ms >> 40) & 0xff) as u8;
  bytes[1] = ((now_ms >> 32) & 0xff) as u8;
  bytes[2] = ((now_ms >> 24) & 0xff) as u8;
  bytes[3] = ((now_ms >> 16) & 0xff) as u8;
  bytes[4] = ((now_ms >> 8) & 0xff) as u8;
  bytes[5] = (now_ms & 0xff) as u8;

  bytes[6] = (bytes[6] & 0x0f) | 0x70;
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
