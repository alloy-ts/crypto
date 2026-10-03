use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::aead::{self, UnboundKey, LessSafeKey, Nonce, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

fn parse_algorithm(alg: &str) -> Result<&'static aead::Algorithm> {
  match alg.to_lowercase().replace("-", "").as_str() {
    "aes128gcm" => Ok(&AES_128_GCM),
    "aes256gcm" => Ok(&AES_256_GCM),
    "chacha20poly1305" => Ok(&CHACHA20_POLY1305),
    _ => Err(Error::new(
      Status::InvalidArg,
      format!("Unsupported AEAD algorithm: {alg}"),
    )),
  }
}

#[napi]
pub fn encrypt_aead(
  algorithm: String,
  key: Uint8Array,
  nonce_bytes: Uint8Array,
  plaintext: Uint8Array,
  aad: Option<Uint8Array>,
) -> Result<Buffer> {
  let alg = parse_algorithm(&algorithm)?;
  let unbound_key = UnboundKey::new(alg, &key)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid key length"))?;
  let key = LessSafeKey::new(unbound_key);
  let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid nonce length"))?;

  let aad_bytes = aad.as_ref().map(|a| a.as_ref()).unwrap_or(&[]);
  let mut in_out = plaintext.to_vec();
  key
    .seal_in_place_append_tag(nonce, aead::Aad::from(aad_bytes), &mut in_out)
    .map_err(|_| Error::new(Status::GenericFailure, "Encryption failed"))?;

  Ok(Buffer::from(in_out))
}

#[napi]
pub fn decrypt_aead(
  algorithm: String,
  key: Uint8Array,
  nonce_bytes: Uint8Array,
  ciphertext_and_tag: Uint8Array,
  aad: Option<Uint8Array>,
) -> Result<Buffer> {
  let alg = parse_algorithm(&algorithm)?;
  let unbound_key = UnboundKey::new(alg, &key)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid key length"))?;
  let key = LessSafeKey::new(unbound_key);
  let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid nonce length"))?;

  let aad_bytes = aad.as_ref().map(|a| a.as_ref()).unwrap_or(&[]);
  let mut in_out = ciphertext_and_tag.to_vec();
  let decrypted = key
    .open_in_place(nonce, aead::Aad::from(aad_bytes), &mut in_out)
    .map_err(|_| Error::new(Status::GenericFailure, "Decryption/tag verification failed"))?;

  Ok(Buffer::from(decrypted.to_vec()))
}
