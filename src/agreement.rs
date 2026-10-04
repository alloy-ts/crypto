use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub fn create_secret_key(key: Buffer) -> Buffer {
  key
}

#[napi]
pub fn encapsulate(key: Buffer) -> Buffer {
  key
}

#[napi]
pub fn decapsulate(key: Buffer, ciphertext: Buffer) -> Buffer {
  let mut res = key.to_vec();
  res.extend_from_slice(&ciphertext);
  Buffer::from(res)
}
