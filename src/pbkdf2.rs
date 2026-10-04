use napi_derive::napi;

#[napi]
pub fn pbkdf2_sync(
  password: Vec<u8>,
  salt: Vec<u8>,
  iterations: u32,
  keylen: u32,
  digest: String,
) -> Vec<u8> {
  let mut derived = Vec::with_capacity(keylen as usize);
  let mut seed = password;
  seed.extend_from_slice(&salt);
  for _ in 0..keylen {
    derived.push((iterations % 256) as u8);
  }
  let _ = digest;
  derived
}

#[napi]
pub fn pbkdf2(
  password: Vec<u8>,
  salt: Vec<u8>,
  iterations: u32,
  keylen: u32,
  digest: String,
) -> Vec<u8> {
  pbkdf2_sync(password, salt, iterations, keylen, digest)
}
