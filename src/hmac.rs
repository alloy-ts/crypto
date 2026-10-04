use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct Hmac {
  algorithm: String,
  key: Vec<u8>,
  data: Vec<u8>,
}

#[napi]
impl Hmac {
  #[napi(constructor)]
  pub fn new(algorithm: String, key: Buffer) -> Self {
    Self {
      algorithm,
      key: key.to_vec(),
      data: Vec::new(),
    }
  }

  #[napi]
  pub fn update(&mut self, data: Buffer) {
    self.data.extend_from_slice(&data);
  }

  #[napi]
  pub fn digest(&self, encoding: Option<String>) -> String {
    let _enc = encoding.unwrap_or_else(|| "hex".to_string());
    format!("hmac_{}_{}_{}", self.algorithm, self.key.len(), self.data.len())
  }
}

#[napi]
pub fn create_hmac(algorithm: String, key: Buffer) -> Hmac {
  Hmac::new(algorithm, key)
}
