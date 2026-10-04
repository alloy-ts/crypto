use napi::bindgen_prelude::*;
use napi_derive::napi;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::rand_core::OsRng;
use rsa::sha2::digest::{Digest, DynDigest, FixedOutputReset};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{BigUint, Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

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

enum PaddingMode {
  Pkcs1v15,
  NoPadding,
  Oaep(Option<String>, Option<Vec<u8>>),
}

fn get_padding_mode(opts: &KeyOptions) -> Result<PaddingMode> {
  if let Some(p) = opts.padding {
    if p == 3 {
      return Ok(PaddingMode::NoPadding);
    }
    if p == 1 {
      if opts.oaep_hash.is_some() {
        return Err(Error::new(
          Status::InvalidArg,
          "ERR_INVALID_ARG_VALUE",
        ));
      }
      return Ok(PaddingMode::Pkcs1v15);
    }
    if p == 4 {
      let label = opts.oaep_label.as_ref().map(|l| l.to_vec());
      return Ok(PaddingMode::Oaep(opts.oaep_hash.clone(), label));
    }
  }
  if opts.oaep_hash.is_some() || opts.oaep_label.is_some() {
    let label = opts.oaep_label.as_ref().map(|l| l.to_vec());
    return Ok(PaddingMode::Oaep(opts.oaep_hash.clone(), label));
  }
  Ok(PaddingMode::Pkcs1v15)
}

fn validate_oaep_digest(hash: Option<&str>) -> Result<()> {
  if let Some(h) = hash {
    match h.to_lowercase().as_str() {
      "sha1" | "sha256" | "sha384" | "sha512" => Ok(()),
      _ => Err(Error::new(Status::InvalidArg, "ERR_OSSL_EVP_INVALID_DIGEST")),
    }
  } else {
    Ok(())
  }
}

fn create_oaep_encrypt_and_encrypt<D: Digest + DynDigest + FixedOutputReset + Send + Sync + 'static>(
  pub_key: &RsaPublicKey,
  label: Option<&[u8]>,
  buffer: &[u8],
) -> Result<Vec<u8>> {
  let mut rng = OsRng;
  let label_str = label.and_then(|l| std::str::from_utf8(l).ok()).unwrap_or("");
  let oaep = Oaep::new_with_label::<D, _>(label_str);
  pub_key
    .encrypt(&mut rng, oaep, buffer)
    .map_err(|e| Error::new(Status::GenericFailure, format!("RSA encryption failed: {e}")))
}

fn create_oaep_decrypt_and_decrypt<D: Digest + DynDigest + FixedOutputReset + Send + Sync + 'static>(
  priv_key: &RsaPrivateKey,
  label: Option<&[u8]>,
  buffer: &[u8],
) -> Result<Vec<u8>> {
  let label_str = label.and_then(|l| std::str::from_utf8(l).ok()).unwrap_or("");
  let oaep = Oaep::new_with_label::<D, _>(label_str);
  priv_key
    .decrypt(oaep, buffer)
    .map_err(|e| Error::new(Status::GenericFailure, format!("RSA decryption failed: {e}")))
}

fn rsa_no_padding_encrypt(pub_key: &RsaPublicKey, buffer: &[u8]) -> Result<Vec<u8>> {
  let key_size = pub_key.size();
  if buffer.len() > key_size {
    return Err(Error::new(Status::GenericFailure, "RSA encryption failed: message too long"));
  }
  let m = BigUint::from_bytes_be(buffer);
  let n = pub_key.n();
  let e = pub_key.e();
  if m >= *n {
    return Err(Error::new(Status::GenericFailure, "RSA encryption failed: data too large for key size"));
  }
  let c = m.modpow(e, n);
  let mut bytes = c.to_bytes_be();
  if bytes.len() < key_size {
    let mut padded = vec![0u8; key_size - bytes.len()];
    padded.extend_from_slice(&bytes);
    bytes = padded;
  }
  Ok(bytes)
}

fn rsa_no_padding_decrypt(priv_key: &RsaPrivateKey, buffer: &[u8]) -> Result<Vec<u8>> {
  let key_size = priv_key.size();
  let c = BigUint::from_bytes_be(buffer);
  let n = priv_key.n();
  let d = priv_key.d();
  let m = c.modpow(d, n);
  let mut bytes = m.to_bytes_be();
  if bytes.len() < key_size {
    let mut padded = vec![0u8; key_size - bytes.len()];
    padded.extend_from_slice(&bytes);
    bytes = padded;
  }
  Ok(bytes)
}

fn parse_public_key(pem_str: &str) -> Result<RsaPublicKey> {
  RsaPublicKey::from_public_key_pem(pem_str)
    .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem_str))
    .or_else(|_| {
      RsaPrivateKey::from_pkcs8_pem(pem_str)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem_str))
        .map(|priv_k| RsaPublicKey::from(&priv_k))
    })
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse public key: {e}")))
}

fn encrypt_rsa(pub_key: &RsaPublicKey, mode: PaddingMode, buffer: &[u8]) -> Result<Vec<u8>> {
  let mut rng = OsRng;
  match mode {
    PaddingMode::NoPadding => rsa_no_padding_encrypt(pub_key, buffer),
    PaddingMode::Pkcs1v15 => pub_key
      .encrypt(&mut rng, Pkcs1v15Encrypt, buffer)
      .map_err(|e| Error::new(Status::GenericFailure, format!("RSA encryption failed: {e}"))),
    PaddingMode::Oaep(hash_name, label) => {
      validate_oaep_digest(hash_name.as_deref())?;
      let hash = hash_name.as_deref().unwrap_or("sha1").to_lowercase();
      let label_bytes = label.as_deref();
      match hash.as_str() {
        "sha1" => create_oaep_encrypt_and_encrypt::<sha1::Sha1>(pub_key, label_bytes, buffer),
        "sha256" => create_oaep_encrypt_and_encrypt::<sha2::Sha256>(pub_key, label_bytes, buffer),
        "sha384" => create_oaep_encrypt_and_encrypt::<sha2::Sha384>(pub_key, label_bytes, buffer),
        "sha512" => create_oaep_encrypt_and_encrypt::<sha2::Sha512>(pub_key, label_bytes, buffer),
        _ => Err(Error::new(Status::InvalidArg, "ERR_OSSL_EVP_INVALID_DIGEST")),
      }
    }
  }
}

fn decrypt_rsa(priv_key: &RsaPrivateKey, mode: PaddingMode, buffer: &[u8]) -> Result<Vec<u8>> {
  match mode {
    PaddingMode::NoPadding => rsa_no_padding_decrypt(priv_key, buffer),
    PaddingMode::Pkcs1v15 => priv_key
      .decrypt(Pkcs1v15Encrypt, buffer)
      .map_err(|e| Error::new(Status::GenericFailure, format!("RSA decryption failed: {e}"))),
    PaddingMode::Oaep(hash_name, label) => {
      validate_oaep_digest(hash_name.as_deref())?;
      let hash = hash_name.as_deref().unwrap_or("sha1").to_lowercase();
      let label_bytes = label.as_deref();
      let default_hash = if hash_name.is_none() { "sha1" } else { hash.as_str() };
      match default_hash {
        "sha1" => create_oaep_decrypt_and_decrypt::<sha1::Sha1>(priv_key, label_bytes, buffer),
        "sha256" => create_oaep_decrypt_and_decrypt::<sha2::Sha256>(priv_key, label_bytes, buffer),
        "sha384" => create_oaep_decrypt_and_decrypt::<sha2::Sha384>(priv_key, label_bytes, buffer),
        "sha512" => create_oaep_decrypt_and_decrypt::<sha2::Sha512>(priv_key, label_bytes, buffer),
        _ => Err(Error::new(Status::InvalidArg, "ERR_OSSL_EVP_INVALID_DIGEST")),
      }
    }
  }
}

#[napi(js_name = "publicEncrypt")]
pub fn public_encrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, opts) = parse_pem_from_arg(key_arg)?;
  let pub_key = parse_public_key(&pem_str)?;

  let mode = get_padding_mode(&opts)?;
  let encrypted = encrypt_rsa(&pub_key, mode, &buffer)?;
  Ok(Buffer::from(encrypted))
}

#[napi(js_name = "privateDecrypt")]
pub fn private_decrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, opts) = parse_pem_from_arg(key_arg)?;
  let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str))
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse private key: {e}")))?;

  let mode = get_padding_mode(&opts)?;
  let decrypted = decrypt_rsa(&priv_key, mode, &buffer)?;
  Ok(Buffer::from(decrypted))
}

#[napi(js_name = "privateEncrypt")]
pub fn private_encrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, opts) = parse_pem_from_arg(key_arg)?;
  let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str))
    .map_err(|e| Error::new(Status::InvalidArg, format!("Failed to parse private key: {e}")))?;

  let pub_key = RsaPublicKey::from(&priv_key);
  let mode = get_padding_mode(&opts)?;
  let encrypted = encrypt_rsa(&pub_key, mode, &buffer)?;
  Ok(Buffer::from(encrypted))
}

#[napi(js_name = "publicDecrypt")]
pub fn public_decrypt(
  key_arg: Either3<String, Uint8Array, KeyOptions>,
  buffer: Uint8Array,
) -> Result<Buffer> {
  let (pem_str, opts) = parse_pem_from_arg(key_arg)?;
  let mode = get_padding_mode(&opts)?;

  let priv_key = RsaPrivateKey::from_pkcs8_pem(&pem_str)
    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem_str));

  if let Ok(priv_k) = priv_key {
    let decrypted = decrypt_rsa(&priv_k, mode, &buffer)?;
    return Ok(Buffer::from(decrypted));
  }

  let pub_key = parse_public_key(&pem_str)?;

  let encrypted = encrypt_rsa(&pub_key, mode, &buffer)?;
  Ok(Buffer::from(encrypted))
}
