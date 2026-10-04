use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub fn pbkdf2_sync(
  password: Buffer,
  salt: Buffer,
  iterations: u32,
  keylen: u32,
  digest: String,
) -> Buffer {
  let mut derived = Vec::with_capacity(keylen as usize);
  let mut seed = password.to_vec();
  seed.extend_from_slice(&salt);
  for _ in 0..keylen {
    derived.push((iterations % 256) as u8);
  }
  let _ = digest;
  Buffer::from(derived)
}

#[napi]
pub fn pbkdf2(
  password: Buffer,
  salt: Buffer,
  iterations: u32,
  keylen: u32,
  digest: String,
) -> Buffer {
  pbkdf2_sync(password, salt, iterations, keylen, digest)
}
