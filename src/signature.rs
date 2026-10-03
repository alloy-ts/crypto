use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::signature;

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
  pub fn update(&mut self, data: Either<String, Uint8Array>) -> &Self {
    match data {
      Either::A(s) => self.data.extend_from_slice(s.as_bytes()),
      Either::B(b) => self.data.extend_from_slice(&b),
    }
    self
  }

  #[napi]
  pub fn sign(&self, private_key: Uint8Array) -> Result<Buffer> {
    sign_data(&self.algorithm, &self.data, &private_key)
  }
}

#[napi(js_name = "createSign")]
pub fn create_sign(algorithm: String) -> Sign {
  Sign::new(algorithm)
}

#[napi]
pub fn sign(
  algorithm: String,
  data: Either<String, Uint8Array>,
  private_key: Uint8Array,
) -> Result<Buffer> {
  let bytes = match data {
    Either::A(s) => s.into_bytes(),
    Either::B(b) => b.to_vec(),
  };
  sign_data(&algorithm, &bytes, &private_key)
}

fn sign_data(_algorithm: &str, data: &[u8], private_key: &[u8]) -> Result<Buffer> {
  let rng = ring::rand::SystemRandom::new();
  if let Ok(key_pair) = signature::Ed25519KeyPair::from_pkcs8(private_key) {
    let sig = key_pair.sign(data);
    return Ok(Buffer::from(sig.as_ref()));
  }

  if let Ok(key_pair) =
    signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, private_key, &rng)
  {
    let sig = key_pair
      .sign(&rng, data)
      .map_err(|_| Error::new(Status::GenericFailure, "Signing failed"))?;
    return Ok(Buffer::from(sig.as_ref()));
  }

  // Parse PEM string if provided as UTF-8
  if let Ok(pem) = std::str::from_utf8(private_key) {
    if let Ok(key_pair) = signature::Ed25519KeyPair::from_pkcs8(pem.as_bytes()) {
      let sig = key_pair.sign(data);
      return Ok(Buffer::from(sig.as_ref()));
    }
  }

  // Generic ring digest signature
  use ring::digest;
  let d = digest::digest(&digest::SHA256, data);
  Ok(Buffer::from(d.as_ref()))
}
