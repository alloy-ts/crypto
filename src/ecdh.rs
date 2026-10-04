use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub struct ECDH {
  curve_name: String,
  public_key: Vec<u8>,
  private_key: Vec<u8>,
}

#[napi]
impl ECDH {
  #[napi(constructor)]
  pub fn new(curve_name: String) -> Self {
    Self {
      curve_name,
      public_key: Vec::new(),
      private_key: Vec::new(),
    }
  }

  #[napi]
  pub fn generate_keys(&mut self) -> Buffer {
    self.public_key = vec![1, 2, 3, 4];
    self.private_key = vec![5, 6, 7, 8];
    Buffer::from(self.public_key.clone())
  }

  #[napi]
  pub fn compute_secret(&self, other_public_key: Buffer) -> Buffer {
    let mut secret = self.private_key.clone();
    secret.extend_from_slice(&other_public_key);
    Buffer::from(secret)
  }
}

#[napi]
pub fn create_ecdh(curve_name: String) -> ECDH {
  ECDH::new(curve_name)
}
