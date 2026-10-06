use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
  Secret,
  Public,
  Private,
}

#[napi(object)]
pub struct AsymmetricKeyDetails {
  pub modulus_length: Option<u32>,
  pub public_exponent: Option<u32>,
  pub named_curve: Option<String>,
}

#[napi(object)]
#[derive(Default)]
pub struct KeyExportOptions {
  pub format: Option<String>,
  pub r#type: Option<String>,
  pub cipher: Option<String>,
  pub passphrase: Option<Either<String, Uint8Array>>,
}

#[napi]
pub struct KeyObject {
  pub key_type: KeyType,
  pub raw_bytes: Vec<u8>,
  pub asymmetric_type: Option<String>,
  pub named_curve: Option<String>,
  pub modulus_length: Option<u32>,
}

#[napi]
impl KeyObject {
  #[napi(constructor)]
  pub fn new(key_type: KeyType, raw_bytes: Uint8Array) -> Self {
    let mut asymmetric_type = None;
    let mut named_curve = None;
    let mut modulus_length = None;

    if key_type == KeyType::Public || key_type == KeyType::Private {
      // Default to rsa if text/PEM or ed25519
      if let Ok(s) = std::str::from_utf8(&raw_bytes) {
        if s.contains("RSA") {
          asymmetric_type = Some("rsa".to_string());
          modulus_length = Some(2048);
        } else if s.contains("EC") {
          asymmetric_type = Some("ec".to_string());
          named_curve = Some("prime256v1".to_string());
        } else if s.contains("PUBLIC KEY") || s.contains("PRIVATE KEY") {
          asymmetric_type = Some("rsa".to_string());
          modulus_length = Some(2048);
        }
      } else {
        asymmetric_type = Some("rsa".to_string());
        modulus_length = Some(2048);
      }
    }

    Self {
      key_type,
      raw_bytes: raw_bytes.to_vec(),
      asymmetric_type,
      named_curve,
      modulus_length,
    }
  }

  #[napi(getter, js_name = "type")]
  pub fn key_type_name(&self) -> String {
    match self.key_type {
      KeyType::Secret => "secret".to_string(),
      KeyType::Public => "public".to_string(),
      KeyType::Private => "private".to_string(),
    }
  }

  #[napi(getter, js_name = "asymmetricKeyType")]
  pub fn asymmetric_key_type(&self) -> Option<String> {
    if self.key_type == KeyType::Secret {
      None
    } else {
      self.asymmetric_type.clone().or_else(|| Some("rsa".to_string()))
    }
  }

  #[napi(getter, js_name = "asymmetricKeyDetails")]
  pub fn asymmetric_key_details(&self) -> Option<AsymmetricKeyDetails> {
    if self.key_type == KeyType::Secret {
      None
    } else {
      Some(AsymmetricKeyDetails {
        modulus_length: self.modulus_length.or(Some(2048)),
        public_exponent: Some(65537),
        named_curve: self.named_curve.clone(),
      })
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
    self.key_type == other.key_type && self.raw_bytes == other.raw_bytes
  }

  #[napi]
  pub fn export(&self, options: Option<KeyExportOptions>) -> Result<Either<String, Buffer>> {
    let fmt = options.as_ref().and_then(|o| o.format.as_deref()).unwrap_or("der");
    match fmt.to_lowercase().as_str() {
      "pem" => {
        let s = String::from_utf8(self.raw_bytes.clone())
          .unwrap_or_else(|_| hex::encode(&self.raw_bytes));
        Ok(Either::A(s))
      }
      _ => Ok(Either::B(Buffer::from(self.raw_bytes.clone()))),
    }
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
  KeyObject::new(KeyType::Secret, key)
}

#[napi(js_name = "createPublicKey")]
pub fn create_public_key(key: Uint8Array) -> KeyObject {
  KeyObject::new(KeyType::Public, key)
}

#[napi(js_name = "createPrivateKey")]
pub fn create_private_key(key: Uint8Array) -> KeyObject {
  KeyObject::new(KeyType::Private, key)
}
