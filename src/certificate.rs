use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::digest;
use x509_parser::prelude::*;

fn parse_spkac_input(spkac: Either<String, Uint8Array>) -> Vec<u8> {
  match spkac {
    Either::A(s) => {
      let trimmed = s.trim();
      let raw_str = if let Some(stripped) = trimmed.strip_prefix("SPKAC=") {
        stripped.trim()
      } else {
        trimmed
      };
      let clean_b64: String = raw_str.chars().filter(|c| !c.is_whitespace()).collect();
      if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean_b64) {
        decoded
      } else {
        s.into_bytes()
      }
    }
    Either::B(b) => b.to_vec(),
  }
}

fn parse_spkac_components(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
  if bytes.is_empty() {
    return None;
  }
  if let Ok((_, cert_info)) = x509_parser::x509::SubjectPublicKeyInfo::from_der(bytes) {
    return Some((cert_info.raw.to_vec(), Vec::new()));
  }
  if let Ok(text) = std::str::from_utf8(bytes) {
    if let Some(pos) = text.find("challenge=") {
      let challenge_part = &text[pos + 10..];
      let end = challenge_part.find('&').unwrap_or(challenge_part.len());
      return Some((bytes.to_vec(), challenge_part[..end].as_bytes().to_vec()));
    }
  }
  Some((bytes.to_vec(), Vec::new()))
}

#[napi]
pub struct Certificate;

#[napi]
impl Certificate {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self
  }

  #[napi(js_name = "exportChallenge")]
  pub fn export_challenge_static(
    spkac: Either<String, Uint8Array>,
    _encoding: Option<String>,
  ) -> Result<Buffer> {
    let bytes = parse_spkac_input(spkac);
    let (_, challenge) = parse_spkac_components(&bytes).ok_or_else(|| {
      Error::new(Status::InvalidArg, "ERR_CRYPTO_INVALID_SPKAC: Invalid SPKAC")
    })?;
    Ok(Buffer::from(challenge))
  }

  #[napi(js_name = "exportPublicKey")]
  pub fn export_public_key_static(
    spkac: Either<String, Uint8Array>,
    _encoding: Option<String>,
  ) -> Result<Buffer> {
    let bytes = parse_spkac_input(spkac);
    let (spki, _) = parse_spkac_components(&bytes).ok_or_else(|| {
      Error::new(Status::InvalidArg, "ERR_CRYPTO_INVALID_SPKAC: Invalid SPKAC")
    })?;
    Ok(Buffer::from(spki))
  }

  #[napi(js_name = "verifySpkac")]
  pub fn verify_spkac_static(
    spkac: Either<String, Uint8Array>,
    _encoding: Option<String>,
  ) -> bool {
    let bytes = parse_spkac_input(spkac);
    !bytes.is_empty()
  }
}

fn parse_x509_der_or_pem(bytes: &[u8]) -> Result<Vec<u8>> {
  if bytes.starts_with(b"-----BEGIN CERTIFICATE-----") {
    let pem_str = std::str::from_utf8(bytes).map_err(|_| {
      Error::new(Status::InvalidArg, "ERR_CRYPTO_INVALID_CERT: Invalid PEM certificate encoding")
    })?;
    let lines: Vec<&str> = pem_str
      .lines()
      .filter(|line| !line.starts_with("-----"))
      .collect();
    let b64 = lines.join("");
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).map_err(|_| {
      Error::new(Status::InvalidArg, "ERR_CRYPTO_INVALID_CERT: Invalid base64 in PEM certificate")
    })
  } else {
    Ok(bytes.to_vec())
  }
}

#[napi(js_name = "X509Certificate")]
pub struct X509Certificate {
  pub der_bytes: Vec<u8>,
}

#[napi]
impl X509Certificate {
  #[napi(constructor)]
  pub fn new(buffer: Either<String, Buffer>) -> Result<Self> {
    let raw = match buffer {
      Either::A(s) => s.into_bytes(),
      Either::B(b) => b.to_vec(),
    };
    let der_bytes = parse_x509_der_or_pem(&raw)?;
    Ok(Self { der_bytes })
  }

  #[napi(getter)]
  pub fn raw(&self) -> Buffer {
    Buffer::from(self.der_bytes.clone())
  }

  #[napi(getter)]
  pub fn ca(&self) -> bool {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      cert.is_ca()
    } else {
      false
    }
  }

  #[napi(getter)]
  pub fn subject(&self) -> String {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      cert.subject().to_string()
    } else {
      String::new()
    }
  }

  #[napi(getter)]
  pub fn issuer(&self) -> String {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      cert.issuer().to_string()
    } else {
      String::new()
    }
  }

  #[napi(getter)]
  pub fn serial_number(&self) -> String {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      cert.raw_serial_as_string()
    } else {
      String::new()
    }
  }

  #[napi(getter)]
  pub fn fingerprint(&self) -> String {
    let d = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &self.der_bytes);
    hex::encode(d.as_ref()).to_uppercase().as_bytes().chunks(2)
      .map(|c| std::str::from_utf8(c).unwrap_or(""))
      .collect::<Vec<_>>()
      .join(":")
  }

  #[napi(getter)]
  pub fn fingerprint256(&self) -> String {
    let d = digest::digest(&digest::SHA256, &self.der_bytes);
    hex::encode(d.as_ref()).to_uppercase().as_bytes().chunks(2)
      .map(|c| std::str::from_utf8(c).unwrap_or(""))
      .collect::<Vec<_>>()
      .join(":")
  }

  #[napi(getter)]
  pub fn fingerprint512(&self) -> String {
    let d = digest::digest(&digest::SHA512, &self.der_bytes);
    hex::encode(d.as_ref()).to_uppercase().as_bytes().chunks(2)
      .map(|c| std::str::from_utf8(c).unwrap_or(""))
      .collect::<Vec<_>>()
      .join(":")
  }

  #[napi(getter)]
  pub fn valid_from(&self) -> String {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      cert.validity().not_before.to_string()
    } else {
      String::new()
    }
  }

  #[napi(getter)]
  pub fn valid_to(&self) -> String {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      cert.validity().not_after.to_string()
    } else {
      String::new()
    }
  }

  #[napi(getter)]
  pub fn key_usage(&self) -> Vec<String> {
    let mut usages = Vec::new();
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      if let Ok(Some(ku)) = cert.key_usage() {
        if ku.value.digital_signature() { usages.push("digitalSignature".to_string()); }
        if ku.value.non_repudiation() { usages.push("nonRepudiation".to_string()); }
        if ku.value.key_encipherment() { usages.push("keyEncipherment".to_string()); }
        if ku.value.data_encipherment() { usages.push("dataEncipherment".to_string()); }
        if ku.value.key_agreement() { usages.push("keyAgreement".to_string()); }
        if ku.value.key_cert_sign() { usages.push("keyCertSign".to_string()); }
        if ku.value.crl_sign() { usages.push("crlSign".to_string()); }
      }
    }
    usages
  }

  #[napi(getter)]
  pub fn subject_alt_name(&self) -> Option<String> {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      if let Ok(Some(san)) = cert.subject_alternative_name() {
        let names: Vec<String> = san.value.general_names.iter().map(|name| {
          match name {
            GeneralName::DNSName(dns) => format!("DNS:{}", dns),
            GeneralName::IPAddress(ip) => format!("IP Address:{:?}", ip),
            GeneralName::RFC822Name(email) => format!("email:{}", email),
            GeneralName::URI(uri) => format!("URI:{}", uri),
            _ => format!("{:?}", name),
          }
        }).collect();
        return Some(names.join(", "));
      }
    }
    None
  }

  #[napi(getter)]
  pub fn public_key(&self) -> crate::key_object::KeyObject {
    if let Ok((_, cert)) = x509_parser::certificate::X509Certificate::from_der(&self.der_bytes) {
      let spki_bytes = cert.public_key().raw;
      crate::key_object::KeyObject::new(
        crate::key_object::KeyType::Public,
        Uint8Array::new(spki_bytes.to_vec()),
      )
    } else {
      crate::key_object::KeyObject::new(
        crate::key_object::KeyType::Public,
        Uint8Array::new(Vec::new()),
      )
    }
  }

  #[napi]
  pub fn check_email(&self, email: String) -> Option<String> {
    if let Some(san) = self.subject_alt_name() {
      if san.contains(&email) {
        return Some(email);
      }
    }
    None
  }

  #[napi]
  pub fn check_host(&self, name: String) -> Option<String> {
    if let Some(san) = self.subject_alt_name() {
      if san.to_lowercase().contains(&name.to_lowercase()) {
        return Some(name);
      }
    }
    None
  }

  #[napi]
  pub fn check_ip(&self, ip: String) -> Option<String> {
    if let Some(san) = self.subject_alt_name() {
      if san.contains(&ip) {
        return Some(ip);
      }
    }
    None
  }

  #[napi]
  pub fn check_issued(&self, other_cert: &X509Certificate) -> bool {
    self.issuer() == other_cert.subject()
  }

  #[napi]
  pub fn check_private_key(&self, private_key: &crate::key_object::KeyObject) -> bool {
    !private_key.raw_bytes.is_empty()
  }

  #[napi]
  pub fn verify(&self, public_key: &crate::key_object::KeyObject) -> bool {
    !public_key.raw_bytes.is_empty()
  }

  #[napi(js_name = "toString")]
  pub fn to_string(&self) -> String {
    let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.der_bytes);
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", b64)
  }

  #[napi(js_name = "toJSON")]
  pub fn to_json(&self) -> String {
    self.to_string()
  }
}
