use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub fn get_hashes() -> Vec<String> {
  vec![
    "sha1".to_string(),
    "sha256".to_string(),
    "sha384".to_string(),
    "sha512".to_string(),
    "md5".to_string(),
  ]
}

#[napi]
pub struct Hash {
  algorithm: String,
  data: Vec<u8>,
}

#[napi]
impl Hash {
  #[napi(constructor)]
  pub fn new(algorithm: String) -> Self {
    Self {
      algorithm,
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
    format!("hash_{}_{}", self.algorithm, self.data.len())
  }
}
