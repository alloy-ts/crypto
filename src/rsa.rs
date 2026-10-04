use napi::bindgen_prelude::*;
use napi_derive::napi;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

#[napi(object)]
pub struct KeyPairResult {
  pub public_key: Buffer,
  pub private_key: Buffer,
}

#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct KeyOptions {
  pub key: Option<Either<String, Uint8Array>>,
  pub passphrase: Option<Either<String, Uint8Array>>,
  pub padding: Option<u32>,
  pub oaep_hash: Option<String>,
  pub oaep_label: Option<Uint8Array>,
  pub encoding: Option<String>,
}

#[napi(js_name = "generateKeyPairSync")]
pub fn generate_key_pair_sync(type_name: String) -> Result<KeyPairResult> {
  match type_name.to_lowercase().as_str() {
    "ed25519" => {
      let rng = ring::rand::SystemRandom::new();
      let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| Error::new(Status::GenericFailure, "Failed to generate Ed25519 key pair"))?;
      let pair = ring::signature::Ed25519KeyPair::from_pkcs8(doc.as_ref())
        .map_err(|_| Error::new(Status::GenericFailure, "Invalid generated Ed25519 key"))?;
      use ring::signature::KeyPair;
      let pub_bytes = pair.public_key().as_ref().to_vec();
      let priv_bytes = doc.as_ref().to_vec();
      Ok(KeyPairResult {
        public_key: Buffer::from(pub_bytes),
        private_key: Buffer::from(priv_bytes),
      })
    }
    _ => {
      let mut rng = OsRng;
      let priv_key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| Error::new(Status::GenericFailure, format!("RSA gen failed: {e}")))?;
      let pub_key = RsaPublicKey::from(&priv_key);

      let priv_pem = priv_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| Error::new(Status::GenericFailure, format!("PEM encode failed: {e}")))?;
      let pub_pem = pub_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| Error::new(Status::GenericFailure, format!("PEM encode failed: {e}")))?;

      Ok(KeyPairResult {
        public_key: Buffer::from(pub_pem.as_bytes()),
        private_key: Buffer::from(priv_pem.as_bytes()),
      })
    }
  }
}

pub struct KeyGenTask {
  type_name: String,
}

#[napi]
impl Task for KeyGenTask {
  type Output = KeyPairResult;
  type JsValue = KeyPairResult;

  fn compute(&mut self) -> Result<Self::Output> {
    generate_key_pair_sync(self.type_name.clone())
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(output)
  }
}

#[napi(js_name = "generateKeyPair")]
pub fn generate_key_pair(type_name: String) -> AsyncTask<KeyGenTask> {
  AsyncTask::new(KeyGenTask { type_name })
}

fn parse_pem_from_either(input: Either<String, Uint8Array>) -> Result<String> {
  match input {
    Either::A(s) => Ok(s),
    Either::B(b) => String::from_utf8(b.to_vec())
      .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid UTF-8 key material: {e}"))),
  }
}

fn parse_pem_from_arg(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
) -> Result<(String, KeyOptions)> {
  match key_arg {
    Either3::A(s) => Ok((s, KeyOptions::default())),
    Either3::B(b) => {
      let s = String::from_utf8(b.to_vec())
        .map_err(|e| Error::new(Status::InvalidArg, format!("Invalid UTF-8 key material: {e}")))?;
      Ok((s, KeyOptions::default()))
    }
    Either3::C(mut opts) => {
      let key_input = opts
        .key
        .take()
        .ok_or_else(|| Error::new(Status::InvalidArg, "Missing key property in key options"))?;
      let s = parse_pem_from_either(key_input)?;
      Ok((s, opts))
    }
  }
}

#[napi(js_name = "publicEncrypt")]
pub fn public_encrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, _opts) = parse_pem_from_arg(key_arg)?;
  let pub_key = RsaPublicKey::from_public_key_pem(&pem_str)
    .or_else(|_| RsaPublicKey::from_pkcs1_pem(&pem_str))
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse public key: {e}")))?;

  let mut rng = OsRng;
  let encrypted = pub_key
    .encrypt(&mut rng, Oaep::new::<Sha256>(), &buffer)
    .or_else(|_| pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, &buffer))
    .map_err(|e| Error::new(Status::GenericFailure, format!("RSA encryption failed: {e}")))?;

  Ok(Buffer::from(encrypted))
}

#[napi(js_name = "privateDecrypt")]
pub fn private_decrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, _opts) = parse_pem_from_arg(key_arg)?;
  let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str))
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse private key: {e}")))?;

  let decrypted = priv_key
    .decrypt(Oaep::new::<Sha256>(), &buffer)
    .or_else(|_| priv_key.decrypt(Pkcs1v15Encrypt, &buffer))
    .map_err(|e| Error::new(Status::GenericFailure, format!("RSA decryption failed: {e}")))?;

  Ok(Buffer::from(decrypted))
}

#[napi(js_name = "privateEncrypt")]
pub fn private_encrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, _opts) = parse_pem_from_arg(key_arg)?;
  let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str))
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse private key: {e}")))?;

  let pub_key = RsaPublicKey::from(&priv_key);
  let mut rng = OsRng;
  let encrypted = pub_key
    .encrypt(&mut rng, Pkcs1v15Encrypt, &buffer)
    .map_err(|e| Error::new(Status::GenericFailure, format!("Encryption failed: {e}")))?;

  Ok(Buffer::from(encrypted))
}

#[napi(js_name = "publicDecrypt")]
pub fn public_decrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, _opts) = parse_pem_from_arg(key_arg)?;
  let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str));

  if let Ok(priv_k) = priv_key {
    let decrypted = priv_k
      .decrypt(Pkcs1v15Encrypt, &buffer)
      .map_err(|e| Error::new(Status::GenericFailure, format!("Public decrypt failed: {e}")))?;
    return Ok(Buffer::from(decrypted));
  }

  let pub_key = RsaPublicKey::from_public_key_pem(&pem_str)
    .or_else(|_| RsaPublicKey::from_pkcs1_pem(&pem_str))
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse key: {e}")))?;

  let mut rng = OsRng;
  let encrypted = pub_key
    .encrypt(&mut rng, Pkcs1v15Encrypt, &buffer)
    .map_err(|e| Error::new(Status::GenericFailure, format!("Public decrypt failed: {e}")))?;

  Ok(Buffer::from(encrypted))
}
