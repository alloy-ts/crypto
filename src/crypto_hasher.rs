use base64::Engine;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::digest;

enum HasherImpl {
  Ring(digest::Context),
}

fn parse_algorithm(algorithm: &str) -> Result<&'static digest::Algorithm> {
  let cleaned = algorithm.to_lowercase().replace("-", "").replace("_", "");
  match cleaned.as_str() {
    "sha1" => Ok(&digest::SHA1_FOR_LEGACY_USE_ONLY),
    "sha256" => Ok(&digest::SHA256),
    "sha384" => Ok(&digest::SHA384),
    "sha512" => Ok(&digest::SHA512),
    "sha512256" => Ok(&digest::SHA512_256),
    _ => Err(Error::new(
      Status::InvalidArg,
      format!("Unsupported hash algorithm: {algorithm}"),
    )),
  }
}

fn decode_input_bytes(
  data: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Result<Vec<u8>> {
  match data {
    Either::A(s) => match encoding.as_deref() {
      Some("hex") => {
        hex::decode(&s).map_err(|e| Error::new(Status::InvalidArg, format!("Invalid hex: {e}")))
      }
      Some("base64") => base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid base64: {e}"))),
      _ => Ok(s.into_bytes()),
    },
    Either::B(b) => Ok(b.to_vec()),
  }
}

#[napi]
pub struct Hash {
  hasher: Option<HasherImpl>,
}

#[napi]
impl Hash {
  #[napi(constructor)]
  pub fn new(algorithm: String) -> Result<Self> {
    let alg = parse_algorithm(&algorithm)?;
    let ctx = digest::Context::new(alg);
    Ok(Self {
      hasher: Some(HasherImpl::Ring(ctx)),
    })
  }

  #[napi]
  pub fn update(
    &mut self,
    data: Either<String, Uint8Array>,
    input_encoding: Option<String>,
  ) -> Result<&Self> {
    let hasher = self
      .hasher
      .as_mut()
      .ok_or_else(|| Error::new(Status::GenericFailure, "Digest already called"))?;
    let bytes = decode_input_bytes(data, input_encoding)?;
    match hasher {
      HasherImpl::Ring(ctx) => ctx.update(&bytes),
    }
    Ok(self)
  }

  #[napi]
  pub fn digest(&mut self, output_encoding: Option<String>) -> Result<Either<String, Buffer>> {
    let hasher = self
      .hasher
      .take()
      .ok_or_else(|| Error::new(Status::GenericFailure, "Digest already called"))?;

    let bytes = match hasher {
      HasherImpl::Ring(ctx) => {
        let d = ctx.finish();
        d.as_ref().to_vec()
      }
    };

    match output_encoding.as_deref() {
      Some("hex") => Ok(Either::A(hex::encode(&bytes))),
      Some("base64") => Ok(Either::A(
        base64::engine::general_purpose::STANDARD.encode(&bytes),
      )),
      Some("latin1") | Some("binary") => {
        let s: String = bytes.iter().map(|&b| b as char).collect();
        Ok(Either::A(s))
      }
      _ => Ok(Either::B(Buffer::from(bytes))),
    }
  }
}

#[napi(js_name = "createHash")]
pub fn create_hash(algorithm: String) -> Result<Hash> {
  Hash::new(algorithm)
}

#[napi]
pub fn hash(
  algorithm: String,
  data: Either<String, Uint8Array>,
  output_encoding: Option<String>,
) -> Result<Either<String, Buffer>> {
  let mut h = Hash::new(algorithm)?;
  h.update(data, None)?;
  h.digest(output_encoding)
}

#[napi(js_name = "getHashes")]
pub fn get_hashes() -> Vec<String> {
  vec![
    "sha1".to_string(),
    "sha256".to_string(),
    "sha384".to_string(),
    "sha512".to_string(),
    "sha512-256".to_string(),
  ]
}
