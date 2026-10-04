use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct Cipher {
  algorithm: String,
}

#[napi]
impl Cipher {
  #[napi(constructor)]
  pub fn new(algorithm: String) -> Self {
    Self { algorithm }
  }

  #[napi]
  pub fn update(&self, data: Buffer) -> Buffer {
    data
  }

  #[napi]
  pub fn final_cipher(&self) -> Buffer {
    Buffer::from(vec![])
  }
}

#[napi]
pub fn create_cipheriv(algorithm: String, key: Buffer, iv: Buffer) -> Cipher {
  let _ = (key, iv);
  Cipher::new(algorithm)
}
