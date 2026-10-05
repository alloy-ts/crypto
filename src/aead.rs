use base64::Engine;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::aead::{self, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

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

fn decode_bytes(input: Either<String, Uint8Array>, encoding: Option<String>) -> Result<Vec<u8>> {
  match input {
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

fn encode_bytes(bytes: &[u8], encoding: Option<String>) -> Either<String, Buffer> {
  match encoding.as_deref() {
    Some("hex") => Either::A(hex::encode(bytes)),
    Some("base64") => Either::A(base64::engine::general_purpose::STANDARD.encode(bytes)),
    Some("latin1") | Some("binary") => {
      let s: String = bytes.iter().map(|&b| b as char).collect();
      Either::A(s)
    }
    Some("utf8") | Some("utf-8") => Either::A(String::from_utf8_lossy(bytes).to_string()),
    _ => Either::B(Buffer::from(bytes.to_vec())),
  }
}

#[napi(object)]
#[derive(Default)]
pub struct CipherOptions {
  pub auth_tag_length: Option<u32>,
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

#[napi(js_name = "Cipheriv")]
pub struct Cipheriv {
  algorithm: String,
  key: Vec<u8>,
  iv: Vec<u8>,
  aad: Vec<u8>,
  plaintext: Vec<u8>,
  tag: Option<Vec<u8>>,
  auth_tag_len: usize,
  finalized: bool,
}

#[napi]
impl Cipheriv {
  #[napi(constructor)]
  pub fn new(
    algorithm: String,
    key: Either<String, Uint8Array>,
    iv: Either<String, Uint8Array>,
    options: Option<CipherOptions>,
  ) -> Result<Self> {
    let key_bytes = decode_bytes(key, None)?;
    let iv_bytes = decode_bytes(iv, None)?;
    let auth_tag_len = options
      .as_ref()
      .and_then(|o| o.auth_tag_length)
      .unwrap_or(16) as usize;
    Ok(Self {
      algorithm,
      key: key_bytes,
      iv: iv_bytes,
      aad: Vec::new(),
      plaintext: Vec::new(),
      tag: None,
      auth_tag_len,
      finalized: false,
    })
  }

  #[napi]
  pub fn update(
    &mut self,
    data: Either<String, Uint8Array>,
    input_encoding: Option<String>,
    _output_encoding: Option<String>,
  ) -> Result<Either<String, Buffer>> {
    if self.finalized {
      return Err(Error::new(Status::GenericFailure, "Cipheriv already finalized"));
    }
    let bytes = decode_bytes(data, input_encoding)?;
    self.plaintext.extend_from_slice(&bytes);
    Ok(encode_bytes(&[], _output_encoding))
  }

  #[napi(js_name = "final")]
  pub fn final_cipher(&mut self, output_encoding: Option<String>) -> Result<Either<String, Buffer>> {
    if self.finalized {
      return Err(Error::new(Status::GenericFailure, "Cipheriv already finalized"));
    }
    self.finalized = true;

    let encrypted_buf = encrypt_aead(
      self.algorithm.clone(),
      Uint8Array::from(self.key.as_slice()),
      Uint8Array::from(self.iv.as_slice()),
      Uint8Array::from(self.plaintext.as_slice()),
      if self.aad.is_empty() {
        None
      } else {
        Some(Uint8Array::from(self.aad.as_slice()))
      },
    )?;

    let enc_bytes = encrypted_buf.as_ref();
    if enc_bytes.len() >= 16 {
      let tag_len = self.auth_tag_len.min(16);
      let ciphertext = &enc_bytes[..enc_bytes.len() - 16];
      let tag = &enc_bytes[enc_bytes.len() - 16..enc_bytes.len() - 16 + tag_len];
      self.tag = Some(tag.to_vec());
      Ok(encode_bytes(ciphertext, output_encoding))
    } else {
      Ok(encode_bytes(enc_bytes, output_encoding))
    }
  }

  #[napi(js_name = "getAuthTag")]
  pub fn get_auth_tag(&self) -> Result<Buffer> {
    if let Some(ref tag) = self.tag {
      Ok(Buffer::from(tag.clone()))
    } else {
      Err(Error::new(Status::GenericFailure, "Authentication tag not available"))
    }
  }

  #[napi(js_name = "setAAD")]
  pub fn set_aad(&mut self, buffer: Either<String, Uint8Array>) -> Result<&Self> {
    let bytes = decode_bytes(buffer, None)?;
    self.aad = bytes;
    Ok(self)
  }
}

#[napi(js_name = "Decipheriv")]
pub struct Decipheriv {
  algorithm: String,
  key: Vec<u8>,
  iv: Vec<u8>,
  aad: Vec<u8>,
  ciphertext: Vec<u8>,
  tag: Option<Vec<u8>>,
  finalized: bool,
}

#[napi]
impl Decipheriv {
  #[napi(constructor)]
  pub fn new(
    algorithm: String,
    key: Either<String, Uint8Array>,
    iv: Either<String, Uint8Array>,
    _options: Option<CipherOptions>,
  ) -> Result<Self> {
    let key_bytes = decode_bytes(key, None)?;
    let iv_bytes = decode_bytes(iv, None)?;
    Ok(Self {
      algorithm,
      key: key_bytes,
      iv: iv_bytes,
      aad: Vec::new(),
      ciphertext: Vec::new(),
      tag: None,
      finalized: false,
    })
  }

  #[napi]
  pub fn update(
    &mut self,
    data: Either<String, Uint8Array>,
    input_encoding: Option<String>,
    _output_encoding: Option<String>,
  ) -> Result<Either<String, Buffer>> {
    if self.finalized {
      return Err(Error::new(Status::GenericFailure, "Decipheriv already finalized"));
    }
    let bytes = decode_bytes(data, input_encoding)?;
    self.ciphertext.extend_from_slice(&bytes);
    Ok(encode_bytes(&[], _output_encoding))
  }

  #[napi(js_name = "final")]
  pub fn final_cipher(&mut self, output_encoding: Option<String>) -> Result<Either<String, Buffer>> {
    if self.finalized {
      return Err(Error::new(Status::GenericFailure, "Decipheriv already finalized"));
    }
    self.finalized = true;

    let mut payload = self.ciphertext.clone();
    if let Some(ref tag) = self.tag {
      payload.extend_from_slice(tag);
    }

    let decrypted_buf = decrypt_aead(
      self.algorithm.clone(),
      Uint8Array::from(self.key.as_slice()),
      Uint8Array::from(self.iv.as_slice()),
      Uint8Array::from(payload.as_slice()),
      if self.aad.is_empty() {
        None
      } else {
        Some(Uint8Array::from(self.aad.as_slice()))
      },
    )?;

    Ok(encode_bytes(decrypted_buf.as_ref(), output_encoding))
  }

  #[napi(js_name = "setAuthTag")]
  pub fn set_auth_tag(&mut self, tag: Either<String, Uint8Array>, encoding: Option<String>) -> Result<&Self> {
    let bytes = decode_bytes(tag, encoding)?;
    self.tag = Some(bytes);
    Ok(self)
  }

  #[napi(js_name = "setAAD")]
  pub fn set_aad(&mut self, buffer: Either<String, Uint8Array>) -> Result<&Self> {
    let bytes = decode_bytes(buffer, None)?;
    self.aad = bytes;
    Ok(self)
  }
}

#[napi(js_name = "createCipheriv")]
pub fn create_cipheriv(
  algorithm: String,
  key: Either<String, Uint8Array>,
  iv: Either<String, Uint8Array>,
  options: Option<CipherOptions>,
) -> Result<Cipheriv> {
  Cipheriv::new(algorithm, key, iv, options)
}

#[napi(js_name = "createDecipheriv")]
pub fn create_decipheriv(
  algorithm: String,
  key: Either<String, Uint8Array>,
  iv: Either<String, Uint8Array>,
  options: Option<CipherOptions>,
) -> Result<Decipheriv> {
  Decipheriv::new(algorithm, key, iv, options)
}
