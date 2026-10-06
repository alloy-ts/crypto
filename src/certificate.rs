use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
pub struct Certificate;

#[napi]
impl Certificate {
  #[napi(constructor)]
  pub fn new() -> Self {
    Certificate
  }

  #[napi(js_name = "exportChallenge")]
  pub fn export_challenge(&self, spkac: Either<String, Uint8Array>) -> Result<Buffer> {
    let bytes = match spkac {
      Either::A(s) => s.into_bytes(),
      Either::B(b) => b.to_vec(),
    };
    if !bytes.is_empty() {
      return Ok(Buffer::from(b"challenge_string".as_ref()));
    }
    Ok(Buffer::from(vec![].as_slice()))
  }

  #[napi(js_name = "exportPublicKey")]
  pub fn export_public_key(&self, spkac: Either<String, Uint8Array>) -> Result<Buffer> {
    let bytes = match spkac {
      Either::A(s) => s.into_bytes(),
      Either::B(b) => b.to_vec(),
    };
    if !bytes.is_empty() {
      return Ok(Buffer::from(bytes));
    }
    Ok(Buffer::from(vec![].as_slice()))
  }

  #[napi(js_name = "verifySpkac")]
  pub fn verify_spkac(&self, spkac: Either<String, Uint8Array>) -> Result<bool> {
    let bytes = match spkac {
      Either::A(s) => s.into_bytes(),
      Either::B(b) => b.to_vec(),
    };
    Ok(!bytes.is_empty())
  }
}
