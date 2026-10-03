use std::num::NonZeroU32;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::pbkdf2;

fn parse_digest(digest: &str) -> Result<pbkdf2::Algorithm> {
  match digest.to_lowercase().replace("-", "").as_str() {
    "sha1" => Ok(pbkdf2::PBKDF2_HMAC_SHA1),
    "sha256" => Ok(pbkdf2::PBKDF2_HMAC_SHA256),
    "sha384" => Ok(pbkdf2::PBKDF2_HMAC_SHA384),
    "sha512" => Ok(pbkdf2::PBKDF2_HMAC_SHA512),
    _ => Err(Error::new(
      Status::InvalidArg,
      format!("Unsupported PBKDF2 digest algorithm: {digest}"),
    )),
  }
}

fn input_bytes(input: Either<String, Uint8Array>) -> Vec<u8> {
  match input {
    Either::A(s) => s.into_bytes(),
    Either::B(b) => b.to_vec(),
  }
}

fn derive_key(
  password: &[u8],
  salt: &[u8],
  iterations: u32,
  keylen: usize,
  digest: &str,
) -> Result<Vec<u8>> {
  let alg = parse_digest(digest)?;
  let iterations_nonzero = NonZeroU32::new(iterations).ok_or_else(|| {
    Error::new(
      Status::InvalidArg,
      "PBKDF2 iterations must be greater than 0",
    )
  })?;

  let mut out = vec![0u8; keylen];
  pbkdf2::derive(alg, iterations_nonzero, salt, password, &mut out);
  Ok(out)
}

#[napi(js_name = "pbkdf2Sync")]
pub fn pbkdf2_sync(
  password: Either<String, Uint8Array>,
  salt: Either<String, Uint8Array>,
  iterations: u32,
  keylen: u32,
  digest: String,
) -> Result<Buffer> {
  let pass_b = input_bytes(password);
  let salt_b = input_bytes(salt);
  let derived = derive_key(&pass_b, &salt_b, iterations, keylen as usize, &digest)?;
  Ok(derived.into())
}

pub struct Pbkdf2Task {
  password: Vec<u8>,
  salt: Vec<u8>,
  iterations: u32,
  keylen: usize,
  digest: String,
}

#[napi]
impl Task for Pbkdf2Task {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> Result<Self::Output> {
    derive_key(
      &self.password,
      &self.salt,
      self.iterations,
      self.keylen,
      &self.digest,
    )
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output.into())
  }
}

#[napi]
pub fn pbkdf2(
  password: Either<String, Uint8Array>,
  salt: Either<String, Uint8Array>,
  iterations: u32,
  keylen: u32,
  digest: String,
  abort_signal: Option<AbortSignal>,
) -> AsyncTask<Pbkdf2Task> {
  AsyncTask::with_optional_signal(
    Pbkdf2Task {
      password: input_bytes(password),
      salt: input_bytes(salt),
      iterations,
      keylen: keylen as usize,
      digest,
    },
    abort_signal,
  )
}
