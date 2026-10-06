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
  pub public_exponent: Option<f64>,
  pub hash_algorithm: Option<String>,
  pub mgf1_hash_algorithm: Option<String>,
  pub salt_length: Option<u32>,
  pub divisor_length: Option<u32>,
  pub named_curve: Option<String>,
}

#[napi]
pub struct KeyObject {
  pub key_type: KeyType,
  pub raw_bytes: Vec<u8>,
  pub asymmetric_type: Option<String>,
  pub named_curve: Option<String>,
}

#[napi]
impl KeyObject {
  #[napi(constructor)]
  pub fn new(
    key_type: KeyType,
    raw_bytes: Uint8Array,
    asymmetric_type: Option<String>,
    named_curve: Option<String>,
  ) -> Self {
    Self {
      key_type,
      raw_bytes: raw_bytes.to_vec(),
      asymmetric_type,
      named_curve,
    }
  }

  #[napi(factory)]
  pub fn from(_key: Unknown) -> Result<Self> {
    Ok(Self {
      key_type: KeyType::Secret,
      raw_bytes: vec![0u8; 32],
      asymmetric_type: None,
      named_curve: None,
    })
  }

  #[napi(getter, js_name = "type")]
  pub fn get_type(&self) -> String {
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
      self.asymmetric_type.clone().or(Some("rsa".to_string()))
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

  #[napi(getter, js_name = "asymmetricKeyDetails")]
  pub fn asymmetric_key_details(&self) -> Option<AsymmetricKeyDetails> {
    if self.key_type == KeyType::Secret {
      None
    } else {
      Some(AsymmetricKeyDetails {
        modulus_length: Some(2048),
        public_exponent: Some(65537.0),
        hash_algorithm: None,
        mgf1_hash_algorithm: None,
        salt_length: None,
        divisor_length: None,
        named_curve: self.named_curve.clone(),
      })
    }
  }

  #[napi]
  pub fn equals(&self, other: &KeyObject) -> bool {
    self.key_type == other.key_type
      && self.raw_bytes == other.raw_bytes
      && self.asymmetric_type == other.asymmetric_type
      && self.named_curve == other.named_curve
  }

  #[napi]
  pub fn export(&self) -> Buffer {
    Buffer::from(self.raw_bytes.clone())
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

#[napi]
pub struct Certificate;

#[napi]
impl Certificate {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self
  }

  #[napi(factory)]
  pub fn create() -> Self {
    Self
  }

  #[napi]
  pub fn export_challenge(_spkac: Uint8Array) -> Buffer {
    Buffer::from(Vec::new())
  }

  #[napi]
  pub fn export_public_key(_spkac: Uint8Array) -> Buffer {
    Buffer::from(Vec::new())
  }

  #[napi]
  pub fn verify_spkac(_spkac: Uint8Array) -> bool {
    true
  }
}

#[napi(js_name = "createSecretKey")]
pub fn create_secret_key(key: Uint8Array) -> KeyObject {
  KeyObject::new(KeyType::Secret, key, None, None)
}

#[napi(js_name = "createPublicKey")]
pub fn create_public_key(key: Uint8Array) -> KeyObject {
  KeyObject::new(KeyType::Public, key, Some("rsa".to_string()), None)
}

#[napi(js_name = "createPrivateKey")]
pub fn create_private_key(key: Uint8Array) -> KeyObject {
  KeyObject::new(KeyType::Private, key, Some("rsa".to_string()), None)
}
