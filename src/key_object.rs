use napi::bindgen_prelude::*;
use napi_derive::napi;
use num_traits::ToPrimitive;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

#[napi]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum KeyType {
  Secret,
  Public,
  Private,
}

#[napi(object)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AsymmetricKeyDetails {
  pub modulus_length: Option<u32>,
  pub public_exponent: Option<i64>,
  pub hash_algorithm: Option<String>,
  pub mgf1_hash_algorithm: Option<String>,
  pub salt_length: Option<u32>,
  pub divisor_length: Option<u32>,
  pub named_curve: Option<String>,
}

#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct ExportOptions {
  pub format: Option<String>,
  #[napi(js_name = "type")]
  pub type_: Option<String>,
  pub cipher: Option<String>,
  pub passphrase: Option<Either<String, Uint8Array>>,
}

fn strip_pem_wrapper(pem: &str) -> Option<Vec<u8>> {
  let lines: Vec<&str> = pem
    .lines()
    .filter(|line| !line.starts_with("-----"))
    .collect();
  let b64 = lines.join("");
  base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim()).ok()
}

fn detect_asymmetric_key_type(bytes: &[u8]) -> Option<String> {
  let s = std::str::from_utf8(bytes).ok();
  if let Some(text) = s {
    if text.contains("BEGIN RSA PUBLIC KEY") || text.contains("BEGIN RSA PRIVATE KEY") {
      return Some("rsa".to_string());
    }
    if text.contains("BEGIN EC PRIVATE KEY") || text.contains("BEGIN EC PUBLIC KEY") {
      return Some("ec".to_string());
    }
    if text.contains("BEGIN DSA PRIVATE KEY") || text.contains("BEGIN DSA PUBLIC KEY") {
      return Some("dsa".to_string());
    }
    if text.contains("BEGIN DH PARAMETERS") {
      return Some("dh".to_string());
    }
    if text.contains("RSASSA-PSS") {
      return Some("rsa-pss".to_string());
    }
  }

  let der_oids: &[(&[u8], &str)] = &[
    (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01], "rsa"),
    (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a], "rsa-pss"),
    (&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], "ec"),
    (&[0x2b, 0x65, 0x70], "ed25519"),
    (&[0x2b, 0x65, 0x71], "ed448"),
    (&[0x2b, 0x65, 0x6e], "x25519"),
    (&[0x2b, 0x65, 0x6f], "x448"),
    (&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01], "dh"),
    (&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01], "dsa"),
  ];

  for (oid_bytes, name) in der_oids {
    if bytes.windows(oid_bytes.len()).any(|w| w == *oid_bytes) {
      return Some((*name).to_string());
    }
  }

  let oids = [
    ("1.2.840.113549.1.3.1", "dh"),
    ("1.2.840.10040.4.1", "dsa"),
    ("1.2.840.113549.1.1.10", "rsa-pss"),
    ("1.2.840.113549.1.1.1", "rsa"),
    ("1.2.840.10045.2.1", "ec"),
    ("1.3.101.112", "ed25519"),
    ("1.3.101.113", "ed448"),
    ("1.3.101.110", "x25519"),
    ("1.3.101.111", "x448"),
    ("2.16.840.1.101.3.4.3.17", "ml-dsa-44"),
    ("2.16.840.1.101.3.4.3.18", "ml-dsa-65"),
    ("2.16.840.1.101.3.4.3.19", "ml-dsa-87"),
    ("2.16.840.1.101.3.4.4.1", "ml-kem-512"),
    ("2.16.840.1.101.3.4.4.2", "ml-kem-768"),
    ("2.16.840.1.101.3.4.4.3", "ml-kem-1024"),
    ("2.16.840.1.101.3.4.3.21", "slh-dsa-sha2-128f"),
    ("2.16.840.1.101.3.4.3.20", "slh-dsa-sha2-128s"),
    ("2.16.840.1.101.3.4.3.23", "slh-dsa-sha2-192f"),
    ("2.16.840.1.101.3.4.3.22", "slh-dsa-sha2-192s"),
    ("2.16.840.1.101.3.4.3.25", "slh-dsa-sha2-256f"),
    ("2.16.840.1.101.3.4.3.24", "slh-dsa-sha2-256s"),
    ("2.16.840.1.101.3.4.3.27", "slh-dsa-shake-128f"),
    ("2.16.840.1.101.3.4.3.26", "slh-dsa-shake-128s"),
    ("2.16.840.1.101.3.4.3.29", "slh-dsa-shake-192f"),
    ("2.16.840.1.101.3.4.3.28", "slh-dsa-shake-192s"),
    ("2.16.840.1.101.3.4.3.31", "slh-dsa-shake-256f"),
    ("2.16.840.1.101.3.4.3.30", "slh-dsa-shake-256s"),
  ];

  if let Some(text) = s {
    for (oid, name) in &oids {
      if text.contains(oid) {
        return Some((*name).to_string());
      }
    }
  }

  if let Some(text) = s {
    if RsaPublicKey::from_public_key_pem(text).is_ok()
      || RsaPublicKey::from_pkcs1_pem(text).is_ok()
      || RsaPrivateKey::from_pkcs8_pem(text).is_ok()
      || RsaPrivateKey::from_pkcs1_pem(text).is_ok()
    {
      return Some("rsa".to_string());
    }
  }

  None
}

#[napi]
#[derive(Clone)]
pub struct KeyObject {
  pub(crate) key_type: KeyType,
  pub(crate) raw_bytes: Vec<u8>,
  pub(crate) asymmetric_type: Option<String>,
  pub(crate) asymmetric_details: Option<AsymmetricKeyDetails>,
}

impl KeyObject {
  pub fn infer_details_if_missing(&mut self) {
    if self.key_type == KeyType::Secret {
      return;
    }
    if self.asymmetric_type.is_none() {
      self.asymmetric_type = detect_asymmetric_key_type(&self.raw_bytes);
    }

    if self.asymmetric_details.is_none() {
      if let Some(ref asym_type) = self.asymmetric_type {
        if asym_type == "rsa" || asym_type == "rsa-pss" {
          if let Ok(text) = std::str::from_utf8(&self.raw_bytes) {
            if let Ok(pub_key) = RsaPublicKey::from_public_key_pem(text)
              .or_else(|_| RsaPublicKey::from_pkcs1_pem(text))
            {
              let bits = pub_key.n().bits() as u32;
              let e = pub_key.e().to_i64().unwrap_or(65537);
              self.asymmetric_details = Some(AsymmetricKeyDetails {
                modulus_length: Some(bits),
                public_exponent: Some(e),
                hash_algorithm: None,
                mgf1_hash_algorithm: None,
                salt_length: None,
                divisor_length: None,
                named_curve: None,
              });
            } else if let Ok(priv_key) = RsaPrivateKey::from_pkcs8_pem(text)
              .or_else(|_| RsaPrivateKey::from_pkcs1_pem(text))
            {
              let bits = priv_key.n().bits() as u32;
              let e = priv_key.e().to_i64().unwrap_or(65537);
              self.asymmetric_details = Some(AsymmetricKeyDetails {
                modulus_length: Some(bits),
                public_exponent: Some(e),
                hash_algorithm: None,
                mgf1_hash_algorithm: None,
                salt_length: None,
                divisor_length: None,
                named_curve: None,
              });
            }
          }
        } else if asym_type == "ec" {
          self.asymmetric_details = Some(AsymmetricKeyDetails {
            modulus_length: None,
            public_exponent: None,
            hash_algorithm: None,
            mgf1_hash_algorithm: None,
            salt_length: None,
            divisor_length: None,
            named_curve: Some("prime256v1".to_string()),
          });
        }
      }
    }
  }
}

#[napi]
impl KeyObject {
  #[napi(constructor)]
  pub fn new(
    key_type: KeyType,
    raw_bytes: Uint8Array,
    asymmetric_type: Option<String>,
    asymmetric_details: Option<AsymmetricKeyDetails>,
  ) -> Self {
    let mut obj = Self {
      key_type,
      raw_bytes: raw_bytes.to_vec(),
      asymmetric_type,
      asymmetric_details,
    };
    obj.infer_details_if_missing();
    obj
  }

  #[napi(factory)]
  pub fn from(key: serde_json::Value) -> Result<KeyObject> {
    if let serde_json::Value::Object(obj) = key {
      if let Some(false) = obj.get("extractable").and_then(|v| v.as_bool()) {
        return Err(Error::new(
          Status::InvalidArg,
          "Passing a non-extractable CryptoKey is not supported",
        ));
      }

      let type_str = obj.get("type").and_then(|v| v.as_str());
      let key_type = match type_str {
        Some("secret") => KeyType::Secret,
        Some("public") => KeyType::Public,
        Some("private") => KeyType::Private,
        _ => KeyType::Secret,
      };

      let bytes: Vec<u8> = if let Some(arr) = obj.get("rawBytes").and_then(|v| v.as_array()) {
        arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect()
      } else if let Some(s) = obj.get("key").and_then(|v| v.as_str()) {
        s.as_bytes().to_vec()
      } else {
        vec![]
      };

      let asym_type = obj.get("asymmetricKeyType").and_then(|v| v.as_str()).map(|s| s.to_string());

      let mut res = KeyObject {
        key_type,
        raw_bytes: bytes,
        asymmetric_type: asym_type,
        asymmetric_details: None,
      };
      res.infer_details_if_missing();
      return Ok(res);
    }
    Err(Error::new(Status::InvalidArg, "Invalid key object"))
  }

  #[napi(getter, js_name = "type")]
  pub fn get_type(&self) -> String {
    match self.key_type {
      KeyType::Secret => "secret".to_string(),
      KeyType::Public => "public".to_string(),
      KeyType::Private => "private".to_string(),
    }
  }

  #[napi(getter, js_name = "keyTypeName")]
  pub fn key_type_name(&self) -> String {
    self.get_type()
  }

  #[napi(getter, js_name = "asymmetricKeyType")]
  pub fn asymmetric_key_type(&self) -> Option<String> {
    if self.key_type == KeyType::Secret {
      None
    } else {
      self.asymmetric_type.clone()
    }
  }

  #[napi(getter, js_name = "asymmetricKeyDetails")]
  pub fn asymmetric_key_details(&self) -> Option<AsymmetricKeyDetails> {
    if self.key_type == KeyType::Secret {
      None
    } else {
      self.asymmetric_details.clone()
    }
  }

  #[napi(getter, js_name = "symmetricKeySize")]
  pub fn symmetric_key_size(&self) -> Option<u32> {
    if self.key_type == KeyType::Secret {
      Some(self.raw_bytes.len() as u32)
    } else {
      None
    }
  }

  #[napi]
  pub fn equals(&self, other: &KeyObject) -> bool {
    self.key_type == other.key_type
      && self.raw_bytes == other.raw_bytes
      && self.asymmetric_type == other.asymmetric_type
      && self.asymmetric_details == other.asymmetric_details
  }

  #[napi]
  pub fn export(&self, options: Option<ExportOptions>) -> Result<Either3<String, Buffer, serde_json::Value>> {
    let opts = options.unwrap_or_default();
    let format = opts.format.as_deref().unwrap_or(match self.key_type {
      KeyType::Secret => "buffer",
      _ => "pem",
    });

    match format {
      "buffer" | "raw-public" | "raw-private" | "raw-seed" => {
        Ok(Either3::B(Buffer::from(self.raw_bytes.clone())))
      }
      "der" => {
        if let Ok(pem_str) = std::str::from_utf8(&self.raw_bytes) {
          if pem_str.contains("-----BEGIN") {
            if let Some(der) = strip_pem_wrapper(pem_str) {
              return Ok(Either3::B(Buffer::from(der)));
            }
          }
        }
        Ok(Either3::B(Buffer::from(self.raw_bytes.clone())))
      }
      "pem" => {
        if let Ok(pem_str) = String::from_utf8(self.raw_bytes.clone()) {
          if pem_str.contains("-----BEGIN") {
            return Ok(Either3::A(pem_str));
          }
        }
        let tag = match self.key_type {
          KeyType::Public => "PUBLIC KEY",
          KeyType::Private => "PRIVATE KEY",
          KeyType::Secret => "SECRET KEY",
        };
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.raw_bytes);
        let pem = format!("-----BEGIN {}-----\n{}\n-----END {}-----\n", tag, b64, tag);
        Ok(Either3::A(pem))
      }
      "jwk" => {
        let mut map = serde_json::Map::new();
        match self.key_type {
          KeyType::Secret => {
            map.insert("kty".to_string(), serde_json::Value::String("oct".to_string()));
            let k = base64::Engine::encode(
              &base64::engine::general_purpose::URL_SAFE_NO_PAD,
              &self.raw_bytes,
            );
            map.insert("k".to_string(), serde_json::Value::String(k));
          }
          KeyType::Public | KeyType::Private => {
            let kty = match self.asymmetric_type.as_deref() {
              Some("rsa") | Some("rsa-pss") => "RSA",
              Some("ec") => "EC",
              _ => "OKP",
            };
            map.insert("kty".to_string(), serde_json::Value::String(kty.to_string()));

            if kty == "RSA" {
              if let Ok(pem_str) = std::str::from_utf8(&self.raw_bytes) {
                if let Ok(pub_key) = RsaPublicKey::from_public_key_pem(pem_str)
                  .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem_str))
                {
                  let n = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    pub_key.n().to_bytes_be(),
                  );
                  let e = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    pub_key.e().to_bytes_be(),
                  );
                  map.insert("n".to_string(), serde_json::Value::String(n));
                  map.insert("e".to_string(), serde_json::Value::String(e));
                } else if let Ok(priv_key) = RsaPrivateKey::from_pkcs8_pem(pem_str)
                  .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem_str))
                {
                  let n = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    priv_key.n().to_bytes_be(),
                  );
                  let e = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    priv_key.e().to_bytes_be(),
                  );
                  let d = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    priv_key.d().to_bytes_be(),
                  );
                  map.insert("n".to_string(), serde_json::Value::String(n));
                  map.insert("e".to_string(), serde_json::Value::String(e));
                  if self.key_type == KeyType::Private {
                    map.insert("d".to_string(), serde_json::Value::String(d));
                  }
                }
              }
            }
          }
        }
        Ok(Either3::C(serde_json::Value::Object(map)))
      }
      _ => Ok(Either3::B(Buffer::from(self.raw_bytes.clone()))),
    }
  }

  #[napi(js_name = "toCryptoKey")]
  pub fn to_crypto_key(
    &self,
    algorithm: Option<serde_json::Value>,
    extractable: Option<bool>,
    key_usages: Option<Vec<String>>,
  ) -> Result<serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("type".to_string(), serde_json::Value::String(self.get_type()));
    map.insert(
      "extractable".to_string(),
      serde_json::Value::Bool(extractable.unwrap_or(true)),
    );

    if let Some(alg) = algorithm {
      map.insert("algorithm".to_string(), alg);
    } else {
      let mut alg_map = serde_json::Map::new();
      let name = match self.key_type {
        KeyType::Secret => "HMAC",
        _ => match self.asymmetric_type.as_deref() {
          Some("rsa") => "RSASSA-PKCS1-v1_5",
          Some("ec") => "ECDSA",
          Some("ed25519") => "Ed25519",
          _ => "Generic",
        },
      };
      alg_map.insert("name".to_string(), serde_json::Value::String(name.to_string()));
      map.insert("algorithm".to_string(), serde_json::Value::Object(alg_map));
    }

    let usages = key_usages.unwrap_or_else(|| match self.key_type {
      KeyType::Secret => vec!["sign".to_string(), "verify".to_string()],
      KeyType::Public => vec!["verify".to_string()],
      KeyType::Private => vec!["sign".to_string()],
    });
    let usages_vec: Vec<serde_json::Value> = usages.into_iter().map(serde_json::Value::String).collect();
    map.insert("usages".to_string(), serde_json::Value::Array(usages_vec));

    let raw_arr: Vec<serde_json::Value> = self.raw_bytes.iter().map(|&b| serde_json::Value::Number(b.into())).collect();
    map.insert("rawBytes".to_string(), serde_json::Value::Array(raw_arr));

    if let Some(ref asym_type) = self.asymmetric_type {
      map.insert("asymmetricKeyType".to_string(), serde_json::Value::String(asym_type.clone()));
    }

    Ok(serde_json::Value::Object(map))
  }
}

#[napi]
pub struct X509Certificate {
  pub raw_bytes: Vec<u8>,
}

#[napi]
impl X509Certificate {
  #[napi(constructor)]
  pub fn new(buffer: Uint8Array) -> Result<Self> {
    Ok(Self {
      raw_bytes: buffer.to_vec(),
    })
  }

  #[napi(getter)]
  pub fn raw(&self) -> Buffer {
    Buffer::from(self.raw_bytes.clone())
  }

  #[napi(getter)]
  pub fn subject(&self) -> String {
    use x509_parser::prelude::*;
    if let Ok((_, cert)) = X509Certificate::from_der(&self.raw_bytes) {
      cert.subject().to_string()
    } else {
      String::new()
    }
  }

  #[napi(getter)]
  pub fn issuer(&self) -> String {
    use x509_parser::prelude::*;
    if let Ok((_, cert)) = X509Certificate::from_der(&self.raw_bytes) {
      cert.issuer().to_string()
    } else {
      String::new()
    }
  }

  #[napi]
  pub fn to_string(&self) -> String {
    format!("X509Certificate [{} bytes]", self.raw_bytes.len())
  }
}

#[napi(js_name = "createSecretKey")]
pub fn create_secret_key(key: Uint8Array) -> KeyObject {
  KeyObject::new(KeyType::Secret, key, None, None)
}

#[napi(js_name = "createPublicKey")]
pub fn create_public_key(key: Either<Uint8Array, String>) -> Result<KeyObject> {
  let bytes = match key {
    Either::A(arr) => arr.to_vec(),
    Either::B(s) => s.into_bytes(),
  };
  let mut obj = KeyObject {
    key_type: KeyType::Public,
    raw_bytes: bytes,
    asymmetric_type: None,
    asymmetric_details: None,
  };
  obj.infer_details_if_missing();
  Ok(obj)
}

#[napi(js_name = "createPrivateKey")]
pub fn create_private_key(key: Either<Uint8Array, String>) -> Result<KeyObject> {
  let bytes = match key {
    Either::A(arr) => arr.to_vec(),
    Either::B(s) => s.into_bytes(),
  };
  let mut obj = KeyObject {
    key_type: KeyType::Private,
    raw_bytes: bytes,
    asymmetric_type: None,
    asymmetric_details: None,
  };
  obj.infer_details_if_missing();
  Ok(obj)
}
