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

#[napi(js_name = "randomUUIDv7")]
pub fn random_uuid_v7() -> Result<String> {
  let now_ms = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as u64;

  let mut bytes = [0u8; 16];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  // 48-bit timestamp
  let ts_bytes = now_ms.to_be_bytes();
  bytes[0..6].copy_from_slice(&ts_bytes[2..8]);

  // Version 7
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  // Variant RFC 9562
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

use rsa::BigUint;

fn is_prime_miller_rabin(n: &BigUint, k: usize) -> bool {
  let zero = BigUint::from(0u32);
  let one = BigUint::from(1u32);
  let two = BigUint::from(2u32);
  let three = BigUint::from(3u32);

  if n <= &one {
    return false;
  }
  if n == &two || n == &three {
    return true;
  }
  if n % &two == zero {
    return false;
  }

  let small_primes = [3u32, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47];
  for p in small_primes {
    let bp = BigUint::from(p);
    if n == &bp {
      return true;
    }
    if n % &bp == zero {
      return false;
    }
  }

  let n_minus_one = n - &one;
  let mut d = n_minus_one.clone();
  let mut s = 0usize;
  while &d % &two == zero {
    d /= &two;
    s += 1;
  }

  let bases = [2u32, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
  let rounds = k.min(bases.len());

  for i in 0..rounds {
    let a = BigUint::from(bases[i]);
    if &a >= n {
      continue;
    }
    let mut x = a.modpow(&d, n);
    if x == one || x == n_minus_one {
      continue;
    }
    let mut composite = true;
    for _ in 0..s - 1 {
      x = x.modpow(&two, n);
      if x == n_minus_one {
        composite = false;
        break;
      }
    }
    if composite {
      return false;
    }
  }

  true
}

#[napi(js_name = "generatePrimeSync")]
pub fn generate_prime_sync(size: u32) -> Result<Buffer> {
  let bytes_count = ((size + 7) / 8) as usize;
  let rng = SystemRandom::new();
  let mut buf = vec![0u8; bytes_count];

  loop {
    rng
      .fill(&mut buf)
      .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
    if let Some(first) = buf.first_mut() {
      *first |= 0x80;
    }
    if let Some(last) = buf.last_mut() {
      *last |= 0x01;
    }

    let n = BigUint::from_bytes_be(&buf);
    if is_prime_miller_rabin(&n, 10) {
      return Ok(Buffer::from(buf));
    }
  }
}
