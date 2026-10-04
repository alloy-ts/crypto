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
  pub fn update(&self, data: Vec<u8>) -> Vec<u8> {
    data
  }

  #[napi]
  pub fn final_cipher(&self) -> Vec<u8> {
    Vec::new()
  }
}

#[napi]
pub fn create_cipheriv(algorithm: String, key: Vec<u8>, iv: Vec<u8>) -> Cipher {
  let _ = (key, iv);
  Cipher::new(algorithm)
}
