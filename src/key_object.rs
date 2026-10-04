use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct KeyObject {
  key_type: String,
}

#[napi]
impl KeyObject {
  #[napi(constructor)]
  pub fn new(key_type: String) -> Self {
    Self { key_type }
  }

  #[napi]
  pub fn export(&self) -> Buffer {
    Buffer::from(self.key_type.as_bytes().to_vec())
  }
}

#[napi(object)]
pub struct CryptoKeyPair {
  pub public_key: String,
  pub private_key: String,
}

#[napi]
pub struct X509Certificate {
  raw: Vec<u8>,
}

#[napi]
impl X509Certificate {
  #[napi(constructor)]
  pub fn new(raw: Buffer) -> Self {
    Self { raw: raw.to_vec() }
  }

  #[napi]
  pub fn subject(&self) -> String {
    format!("CN=Subject_{}", self.raw.len())
  }
}
