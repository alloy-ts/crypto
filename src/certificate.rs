use base64::Engine;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::asn1_rs::ToDer;
use x509_parser::der_parser::ber::parse_ber;

pub struct ParsedSpkac<'a> {
  pub pk_and_challenge_raw: &'a [u8],
  pub spki_raw: &'a [u8],
  pub challenge_bytes: &'a [u8],
  pub signature_bytes: Vec<u8>,
}

fn md5_digest(data: &[u8]) -> [u8; 16] {
  md5::compute(data).0
}

fn decode_spkac_input(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Result<Vec<u8>> {
  let (raw_bytes, enc_opt) = match spkac {
    Either::A(s) => {
      if s.len() > 2_147_483_647 {
        return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE"));
      }
      (s.into_bytes(), encoding)
    }
    Either::B(b) => {
      if b.len() > 2_147_483_647 {
        return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE"));
      }
      (b.to_vec(), None)
    }
  };

  if raw_bytes.is_empty() {
    return Ok(vec![]);
  }

  // Handle encodings
  if let Some(enc) = enc_opt.as_deref() {
    let s = std::str::from_utf8(&raw_bytes).unwrap_or("").trim();
    let cleaned = s.strip_prefix("SPKAC=").unwrap_or(s);
    let cleaned = cleaned.strip_prefix("spkac=").unwrap_or(cleaned);
    let cleaned = cleaned.replace(|c: char| c.is_whitespace(), "");

    match enc.to_lowercase().as_str() {
      "base64" => {
        if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
          return Ok(b);
        }
      }
      "hex" => {
        if let Ok(b) = hex::decode(&cleaned) {
          return Ok(b);
        }
      }
      "latin1" | "binary" => {
        return Ok(raw_bytes);
      }
      _ => {}
    }
  }

  // Default decoding behavior
  let s = std::str::from_utf8(&raw_bytes).unwrap_or("").trim();
  let cleaned = s.strip_prefix("SPKAC=").unwrap_or(s);
  let cleaned = cleaned.strip_prefix("spkac=").unwrap_or(cleaned);
  let cleaned = cleaned.replace(|c: char| c.is_whitespace(), "");

  if !cleaned.is_empty() {
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
      return Ok(b);
    }
  }

  Ok(raw_bytes)
}

fn parse_spkac(data: &[u8]) -> Result<ParsedSpkac<'_>> {
  let (_, outer_ber) = parse_ber(data)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid ASN.1 BER/DER structure"))?;

  let outer_seq = outer_ber
    .as_sequence()
    .map_err(|_| Error::new(Status::InvalidArg, "SPKAC must be a SEQUENCE"))?;

  if outer_seq.len() < 3 {
    return Err(Error::new(Status::InvalidArg, "Invalid SPKAC sequence length"));
  }

  let pk_and_challenge_ber = &outer_seq[0];
  let sig_ber = &outer_seq[2];

  let pk_and_challenge_seq = pk_and_challenge_ber
    .as_sequence()
    .map_err(|_| Error::new(Status::InvalidArg, "PublicKeyAndChallenge must be a SEQUENCE"))?;

  if pk_and_challenge_seq.len() < 2 {
    return Err(Error::new(Status::InvalidArg, "Invalid PublicKeyAndChallenge sequence length"));
  }

  let challenge_ber = &pk_and_challenge_seq[1];
  let challenge_bytes = challenge_ber
    .content
    .as_slice()
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid challenge content"))?;

  let signature_bytes = match sig_ber.as_bitstring() {
    Ok(bs) => bs.data.to_vec(),
    Err(_) => {
      let slice = sig_ber
        .content
        .as_slice()
        .map_err(|_| Error::new(Status::InvalidArg, "Invalid signature content"))?;
      if slice.len() > 1 && slice[0] == 0 {
        slice[1..].to_vec()
      } else {
        slice.to_vec()
      }
    }
  };

  // Extract raw DER bytes for pk_and_challenge_raw and spki_raw from data
  let header_len = outer_ber
    .header
    .to_der_len()
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid header length"))?;
  let outer_content_slice = &data[header_len..];

  let (rem1, pk_and_challenge_obj) = parse_ber(outer_content_slice)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid PublicKeyAndChallenge DER"))?;
  let pk_and_challenge_len = outer_content_slice.len() - rem1.len();
  let pk_and_challenge_raw = &outer_content_slice[..pk_and_challenge_len];

  let pk_header_len = pk_and_challenge_obj
    .header
    .to_der_len()
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid pk header length"))?;
  let pk_content_slice = &pk_and_challenge_raw[pk_header_len..];

  let (rem2, _) = parse_ber(pk_content_slice)
    .map_err(|_| Error::new(Status::InvalidArg, "Invalid SubjectPublicKeyInfo DER"))?;
  let spki_len = pk_content_slice.len() - rem2.len();
  let spki_raw = &pk_content_slice[..spki_len];

  Ok(ParsedSpkac {
    pk_and_challenge_raw,
    spki_raw,
    challenge_bytes,
    signature_bytes,
  })
}

fn format_spki_pem(spki_raw: &[u8]) -> String {
  let b64 = base64::engine::general_purpose::STANDARD.encode(spki_raw);
  let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
  for chunk in b64.as_bytes().chunks(64) {
    if let Ok(s) = std::str::from_utf8(chunk) {
      pem.push_str(s);
      pem.push('\n');
    }
  }
  pem.push_str("-----END PUBLIC KEY-----\n");
  pem
}

fn verify_spkac_signature(parsed: &ParsedSpkac) -> bool {
  let pem = format_spki_pem(parsed.spki_raw);

  if let Ok(pub_key) = RsaPublicKey::from_public_key_pem(&pem) {
    use rsa::traits::PublicKeyParts;
    use rsa::BigUint;

    let c = BigUint::from_bytes_be(&parsed.signature_bytes);
    let m = c.modpow(pub_key.e(), pub_key.n());
    let mut dec_bytes = m.to_bytes_be();

    let key_size = pub_key.size();
    while dec_bytes.len() < key_size {
      dec_bytes.insert(0, 0);
    }

    if dec_bytes.len() >= 11 && dec_bytes[0] == 0x00 && dec_bytes[1] == 0x01 {
      let mut idx = 2;
      while idx < dec_bytes.len() && dec_bytes[idx] == 0xff {
        idx += 1;
      }
      if idx < dec_bytes.len() && dec_bytes[idx] == 0x00 {
        let digest_info = &dec_bytes[idx + 1..];

        let hash_md5 = md5_digest(parsed.pk_and_challenge_raw);
        let mut info_md5 = vec![
          0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05,
          0x00, 0x04, 0x10,
        ];
        info_md5.extend_from_slice(&hash_md5);
        if digest_info == info_md5 {
          return true;
        }

        let hash256 = Sha256::digest(parsed.pk_and_challenge_raw);
        let mut info256 = vec![
          0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
          0x05, 0x00, 0x04, 0x20,
        ];
        info256.extend_from_slice(&hash256);
        if digest_info == info256 {
          return true;
        }

        let hash1 = Sha1::digest(parsed.pk_and_challenge_raw);
        let mut info1 = vec![
          0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        ];
        info1.extend_from_slice(&hash1);
        if digest_info == info1 {
          return true;
        }

        let hash512 = Sha512::digest(parsed.pk_and_challenge_raw);
        let mut info512 = vec![
          0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
          0x05, 0x00, 0x04, 0x40,
        ];
        info512.extend_from_slice(&hash512);
        if digest_info == info512 {
          return true;
        }

        let hash384 = Sha384::digest(parsed.pk_and_challenge_raw);
        let mut info384 = vec![
          0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
          0x05, 0x00, 0x04, 0x30,
        ];
        info384.extend_from_slice(&hash384);
        if digest_info == info384 {
          return true;
        }
      }
    }
  }

  let rsa256 = ring::signature::UnparsedPublicKey::new(
    &ring::signature::RSA_PKCS1_2048_8192_SHA256,
    parsed.spki_raw,
  );
  if rsa256
    .verify(parsed.pk_and_challenge_raw, &parsed.signature_bytes)
    .is_ok()
  {
    return true;
  }

  let rsa1 = ring::signature::UnparsedPublicKey::new(
    &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
    parsed.spki_raw,
  );
  if rsa1
    .verify(parsed.pk_and_challenge_raw, &parsed.signature_bytes)
    .is_ok()
  {
    return true;
  }

  let ed25519 =
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, parsed.spki_raw);
  if ed25519
    .verify(parsed.pk_and_challenge_raw, &parsed.signature_bytes)
    .is_ok()
  {
    return true;
  }

  let ecdsa = ring::signature::UnparsedPublicKey::new(
    &ring::signature::ECDSA_P256_SHA256_FIXED,
    parsed.spki_raw,
  );
  if ecdsa
    .verify(parsed.pk_and_challenge_raw, &parsed.signature_bytes)
    .is_ok()
  {
    return true;
  }

  false
}

#[napi]
pub struct Certificate {}

#[napi]
impl Certificate {
  #[napi(constructor)]
  pub fn new() -> Self {
    Certificate {}
  }

  #[napi]
  pub fn export_challenge(
    &self,
    spkac: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<Buffer> {
    Certificate::export_challenge_static(spkac, encoding)
  }

  #[napi]
  pub fn export_public_key(
    &self,
    spkac: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<Buffer> {
    Certificate::export_public_key_static(spkac, encoding)
  }

  #[napi]
  pub fn verify_spkac(
    &self,
    spkac: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<bool> {
    Certificate::verify_spkac_static(spkac, encoding)
  }

  #[napi(js_name = "exportChallenge")]
  pub fn export_challenge_static(
    spkac: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<Buffer> {
    let bytes = decode_spkac_input(spkac, encoding)?;
    if let Ok(parsed) = parse_spkac(&bytes) {
      Ok(Buffer::from(parsed.challenge_bytes))
    } else {
      Ok(Buffer::from(vec![]))
    }
  }

  #[napi(js_name = "exportPublicKey")]
  pub fn export_public_key_static(
    spkac: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<Buffer> {
    let bytes = decode_spkac_input(spkac, encoding)?;
    if let Ok(parsed) = parse_spkac(&bytes) {
      let pem = format_spki_pem(parsed.spki_raw);
      Ok(Buffer::from(pem.into_bytes()))
    } else {
      Ok(Buffer::from(vec![]))
    }
  }

  #[napi(js_name = "verifySpkac")]
  pub fn verify_spkac_static(
    spkac: Either<String, Uint8Array>,
    encoding: Option<String>,
  ) -> Result<bool> {
    let bytes = match decode_spkac_input(spkac, encoding) {
      Ok(b) => b,
      Err(_) => return Ok(false),
    };
    if let Ok(parsed) = parse_spkac(&bytes) {
      Ok(verify_spkac_signature(&parsed))
    } else {
      Ok(false)
    }
  }
}
