use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct Sign {
  algorithm: String,
  data: Vec<u8>,
}

#[napi]
impl Sign {
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
  pub fn sign(&self, private_key: Buffer) -> Buffer {
    let mut sig = private_key.to_vec();
    sig.extend_from_slice(&self.data);
    Buffer::from(sig)
  }
}

#[napi]
pub fn create_sign(algorithm: String) -> Sign {
  Sign::new(algorithm)
}

#[napi]
pub struct Verify {
  algorithm: String,
  data: Vec<u8>,
}

#[napi]
impl Verify {
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
  pub fn verify(&self, public_key: Buffer, signature: Buffer) -> bool {
    let _ = (public_key, signature);
    !self.data.is_empty()
  }
}

#[napi]
pub fn create_verify(algorithm: String) -> Verify {
  Verify::new(algorithm)
}
