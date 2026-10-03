use base64::Engine;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::hmac;

fn parse_algorithm(algorithm: &str) -> Result<hmac::Algorithm> {
  match algorithm.to_lowercase().replace("-", "").as_str() {
    "sha1" => Ok(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY),
    "sha256" => Ok(hmac::HMAC_SHA256),
    "sha384" => Ok(hmac::HMAC_SHA384),
    "sha512" => Ok(hmac::HMAC_SHA512),
    _ => Err(Error::new(
      Status::InvalidArg,
      format!("Unsupported HMAC algorithm: {algorithm}"),
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

fn key_bytes(key: Either<String, Uint8Array>, encoding: Option<String>) -> Result<Vec<u8>> {
  decode_input_bytes(key, encoding)
}

#[napi]
pub struct Hmac {
  _key: hmac::Key,
  ctx: Option<hmac::Context>,
}

#[napi]
impl Hmac {
  #[napi(constructor)]
  pub fn new(
    algorithm: String,
    key: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<Self> {
    let alg = parse_algorithm(&algorithm)?;
    let k_bytes = key_bytes(key, encoding)?;
    let hmac_key = hmac::Key::new(alg, &k_bytes);
    let ctx = hmac::Context::with_key(&hmac_key);
    Ok(Self {
      _key: hmac_key,
      ctx: Some(ctx),
    })
  }

  #[napi]
  pub fn update(
    &mut self,
    data: Either<String, Uint8Array>,
    input_encoding: Option<String>,
  ) -> Result<&Self> {
    let ctx = self
      .ctx
      .as_mut()
      .ok_or_else(|| Error::new(Status::GenericFailure, "Digest already called"))?;
    let bytes = decode_input_bytes(data, input_encoding)?;
    ctx.update(&bytes);
    Ok(self)
  }

  #[napi]
  pub fn digest(&mut self, output_encoding: Option<String>) -> Result<Either<String, Buffer>> {
    let ctx = self
      .ctx
      .take()
      .ok_or_else(|| Error::new(Status::GenericFailure, "Digest already called"))?;
    let tag = ctx.sign();
    let bytes = tag.as_ref();

    match output_encoding.as_deref() {
      Some("hex") => Ok(Either::A(hex::encode(bytes))),
      Some("base64") => Ok(Either::A(
        base64::engine::general_purpose::STANDARD.encode(bytes),
      )),
      Some("latin1") | Some("binary") => {
        let s: String = bytes.iter().map(|&b| b as char).collect();
        Ok(Either::A(s))
      }
      _ => Ok(Either::B(Buffer::from(bytes))),
    }
  }
}

#[napi(js_name = "createHmac")]
pub fn create_hmac(
  algorithm: String,
  key: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Result<Hmac> {
  Hmac::new(algorithm, key, encoding)
}
