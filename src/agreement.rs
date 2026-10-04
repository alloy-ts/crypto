use napi_derive::napi;

#[napi]
pub fn create_secret_key(key: Vec<u8>) -> Vec<u8> {
  key
}

#[napi]
pub fn encapsulate(key: Vec<u8>) -> Vec<u8> {
  key
}

#[napi]
pub fn decapsulate(key: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
  let mut res = key;
  res.extend_from_slice(&ciphertext);
  res
}
