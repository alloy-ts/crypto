use napi::bindgen_prelude::*;
use napi_derive::napi;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use x509_parser::der_parser::der::parse_der;
use x509_parser::der_parser::ber::BerObjectContent;

#[napi]
pub fn export_challenge(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Buffer {
  export_challenge_impl(spkac, encoding)
}

#[napi]
pub fn export_public_key(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Buffer {
  export_public_key_impl(spkac, encoding)
}

#[napi]
pub fn verify_spkac(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> bool {
  verify_spkac_impl(spkac, encoding)
}

fn parse_spkac_input(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Option<Vec<u8>> {
  let bytes = match spkac {
    Either::A(s) => {
      let enc = encoding.as_deref().unwrap_or("utf8");
      match enc.to_lowercase().as_str() {
        "base64" => BASE64.decode(s.trim()).ok()?,
        "hex" => hex::decode(s.trim()).ok()?,
        "binary" | "latin1" => s.chars().map(|c| c as u8).collect(),
        _ => {
          let trimmed = s.trim();
          let stripped = if let Some(rest) = trimmed.strip_prefix("SPKAC=") {
            rest.trim()
          } else {
            trimmed
          };
          let cleaned = stripped.replace(['\r', '\n', ' '], "");
          if let Ok(decoded) = BASE64.decode(&cleaned) {
            decoded
          } else {
            s.into_bytes()
          }
        }
      }
    }
    Either::B(b) => {
      let b_slice = b.as_ref();
      if let Some(ref enc) = encoding {
        let s = match enc.to_lowercase().as_str() {
          "hex" => String::from_utf8_lossy(b_slice).to_string(),
          "base64" => String::from_utf8_lossy(b_slice).to_string(),
          "binary" | "latin1" => b_slice.iter().map(|&c| c as char).collect(),
          _ => String::from_utf8_lossy(b_slice).to_string(),
        };
        parse_spkac_input(Either::A(s), None)?
      } else {
        if let Ok(s) = std::str::from_utf8(b_slice) {
          let trimmed = s.trim();
          let stripped = if let Some(rest) = trimmed.strip_prefix("SPKAC=") {
            rest.trim()
          } else {
            trimmed
          };
          let cleaned = stripped.replace(['\r', '\n', ' '], "");
          if let Ok(decoded) = BASE64.decode(&cleaned) {
            decoded
          } else {
            b_slice.to_vec()
          }
        } else {
          b_slice.to_vec()
        }
      }
    }
  };
  Some(bytes)
}

struct ParsedSpkac<'a> {
  spki_der: &'a [u8],
  challenge: &'a [u8],
  pkac_raw: &'a [u8],
  sig_alg_oid: String,
  signature: &'a [u8],
}

fn parse_spkac_der<'a>(der_bytes: &'a [u8]) -> Option<ParsedSpkac<'a>> {
  let (_, top) = parse_der(der_bytes).ok()?;
  let seq = match &top.content {
    BerObjectContent::Sequence(seq) => seq,
    _ => return None,
  };
  if seq.len() < 3 {
    return None;
  }

  let pkac_obj = &seq[0];
  let sig_alg_obj = &seq[1];
  let sig_obj = &seq[2];

  let pkac_content_len = pkac_obj.header.length().definite().ok()? as usize;

  let pkac_seq = match &pkac_obj.content {
    BerObjectContent::Sequence(s) => s,
    _ => return None,
  };
  if pkac_seq.len() < 2 {
    return None;
  }

  let spki_obj = &pkac_seq[0];
  let challenge_obj = &pkac_seq[1];

  let challenge = challenge_obj.as_slice().ok()?;

  let sig_alg_seq = match &sig_alg_obj.content {
    BerObjectContent::Sequence(s) => s,
    _ => return None,
  };
  if sig_alg_seq.is_empty() {
    return None;
  }

  let oid = match &sig_alg_seq[0].content {
    BerObjectContent::OID(oid) => oid.to_string(),
    _ => return None,
  };

  let signature = match &sig_obj.content {
    BerObjectContent::BitString(_, b) => b.data,
    _ => return None,
  };

  let spki_content_len = spki_obj.header.length().definite().ok()? as usize;

  let mut spki_der: Option<&[u8]> = None;
  let mut pkac_raw: Option<&[u8]> = None;

  for offset in 0..der_bytes.len() {
    if let Ok((rem_p, p)) = parse_der(&der_bytes[offset..]) {
      if matches!(p.content, BerObjectContent::Sequence(_)) {
        let p_raw_len = der_bytes.len() - offset - rem_p.len();
        if p.header.length().definite().ok() == Some(pkac_content_len) && pkac_raw.is_none() {
          pkac_raw = Some(&der_bytes[offset..offset + p_raw_len]);
        }
        if p.header.length().definite().ok() == Some(spki_content_len) && spki_der.is_none() {
          spki_der = Some(&der_bytes[offset..offset + p_raw_len]);
        }
      }
    }
  }

  Some(ParsedSpkac {
    spki_der: spki_der?,
    challenge,
    pkac_raw: pkac_raw?,
    sig_alg_oid: oid,
    signature,
  })
}

fn export_challenge_impl(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Buffer {
  if let Some(der_bytes) = parse_spkac_input(spkac, encoding) {
    if let Some(parsed) = parse_spkac_der(&der_bytes) {
      return Buffer::from(parsed.challenge.to_vec());
    }
  }
  Buffer::from(vec![])
}

fn export_public_key_impl(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> Buffer {
  if let Some(der_bytes) = parse_spkac_input(spkac, encoding) {
    if let Some(parsed) = parse_spkac_der(&der_bytes) {
      let b64 = BASE64.encode(parsed.spki_der);
      let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
      for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
      }
      pem.push_str("-----END PUBLIC KEY-----\n");
      return Buffer::from(pem.into_bytes());
    }
  }
  Buffer::from(vec![])
}

fn verify_spkac_impl(
  spkac: Either<String, Uint8Array>,
  encoding: Option<String>,
) -> bool {
  let der_bytes = match parse_spkac_input(spkac, encoding) {
    Some(b) => b,
    None => return false,
  };
  let parsed = match parse_spkac_der(&der_bytes) {
    Some(p) => p,
    None => return false,
  };

  verify_signature(
    parsed.spki_der,
    parsed.pkac_raw,
    &parsed.sig_alg_oid,
    parsed.signature,
  )
}

fn verify_signature(
  spki_der: &[u8],
  data: &[u8],
  sig_alg_oid: &str,
  sig_bytes: &[u8],
) -> bool {
  use rsa::RsaPublicKey;
  use rsa::pkcs8::DecodePublicKey;

  if let Ok(pub_key) = RsaPublicKey::from_public_key_der(spki_der) {
    match sig_alg_oid {
      "1.2.840.113549.1.1.4" => {
        // MD5 with RSA (OID 1.2.840.113549.1.1.4)
        use rsa::Pkcs1v15Sign;
        use ring::digest;
        let md5_hash = digest::digest(&digest::SHA256, data); // Compute digest
        let digest_info_prefix: [u8; 18] = [
          0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10
        ];
        let mut digest_info = Vec::with_capacity(34);
        digest_info.extend_from_slice(&digest_info_prefix);
        digest_info.extend_from_slice(md5_hash.as_ref());
        return pub_key.verify(Pkcs1v15Sign::new_unprefixed(), &digest_info, sig_bytes).is_ok();
      }
      "1.2.840.113549.1.1.5" => {
        use rsa::signature::Verifier;
        use rsa::pkcs1v15::VerifyingKey;
        let scheme = VerifyingKey::<sha1::Sha1>::new_unprefixed(pub_key);
        if let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) {
          if scheme.verify(data, &sig).is_ok() {
            return true;
          }
        }
      }
      "1.2.840.113549.1.1.11" => {
        use rsa::signature::Verifier;
        use rsa::pkcs1v15::VerifyingKey;
        let scheme = VerifyingKey::<sha2::Sha256>::new_unprefixed(pub_key);
        if let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) {
          return scheme.verify(data, &sig).is_ok();
        }
      }
      "1.2.840.113549.1.1.12" => {
        use rsa::signature::Verifier;
        use rsa::pkcs1v15::VerifyingKey;
        let scheme = VerifyingKey::<sha2::Sha384>::new_unprefixed(pub_key);
        if let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) {
          return scheme.verify(data, &sig).is_ok();
        }
      }
      "1.2.840.113549.1.1.13" => {
        use rsa::signature::Verifier;
        use rsa::pkcs1v15::VerifyingKey;
        let scheme = VerifyingKey::<sha2::Sha512>::new_unprefixed(pub_key);
        if let Ok(sig) = rsa::pkcs1v15::Signature::try_from(sig_bytes) {
          return scheme.verify(data, &sig).is_ok();
        }
      }
      _ => {}
    }
  }

  if sig_alg_oid == "1.3.101.112" {
    if spki_der.len() >= 32 {
      let raw_pub = &spki_der[spki_der.len() - 32..];
      let peer_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, raw_pub);
      return peer_key.verify(data, sig_bytes).is_ok();
    }
  }

  false
}
