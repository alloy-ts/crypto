use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::signature;

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
  pub fn update(&mut self, data: Either<String, Uint8Array>) -> &Self {
    match data {
      Either::A(s) => self.data.extend_from_slice(s.as_bytes()),
      Either::B(b) => self.data.extend_from_slice(&b),
    }
    self
  }

  #[napi]
  pub fn verify(&self, public_key: Uint8Array, signature: Uint8Array) -> Result<bool> {
    verify_signature(&self.algorithm, &self.data, &public_key, &signature)
  }
}

#[napi(js_name = "createVerify")]
pub fn create_verify(algorithm: String) -> Verify {
  Verify::new(algorithm)
}

#[napi]
pub fn verify(
  algorithm: String,
  data: Either<String, Uint8Array>,
  public_key: Uint8Array,
  signature: Uint8Array,
) -> Result<bool> {
  let bytes = match data {
    Either::A(s) => s.into_bytes(),
    Either::B(b) => b.to_vec(),
  };
  verify_signature(&algorithm, &bytes, &public_key, &signature)
}

fn verify_signature(
  _algorithm: &str,
  data: &[u8],
  public_key: &[u8],
  sig_bytes: &[u8],
) -> Result<bool> {
  let peer_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key);
  if peer_key.verify(data, sig_bytes).is_ok() {
    return Ok(true);
  }

  let ecdsa_key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, public_key);
  if ecdsa_key.verify(data, sig_bytes).is_ok() {
    return Ok(true);
  }

  // Parse trailing 32 bytes for Ed25519 public key if in SPKI/PKCS8 format
  if public_key.len() > 32 {
    let raw_pub = &public_key[public_key.len() - 32..];
    let peer_key2 = signature::UnparsedPublicKey::new(&signature::ED25519, raw_pub);
    if peer_key2.verify(data, sig_bytes).is_ok() {
      return Ok(true);
    }
  }

  Ok(false)
}

#[napi(js_name = "createMac")]
pub fn create_mac(algorithm: String, key: Uint8Array) -> Result<crate::hmac::Hmac> {
  crate::hmac::Hmac::new(algorithm, Either::B(key), None)
}
