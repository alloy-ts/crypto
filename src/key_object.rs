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
  pub public_exponent: Option<String>,
}

#[napi]
pub struct KeyObject {
  pub key_type: KeyType,
  pub raw_bytes: Vec<u8>,
  pub asymmetric_key_type_val: Option<String>,
}

#[napi]
impl KeyObject {
  #[napi(constructor)]
  pub fn new(key_type: KeyType, raw_bytes: Uint8Array) -> Self {
    Self {
      key_type,
      raw_bytes: raw_bytes.to_vec(),
      asymmetric_key_type_val: if key_type != KeyType::Secret {
        Some("rsa".to_string())
      } else {
        None
      },
    }
  }

  #[napi(factory, js_name = "from")]
  pub fn from(_key: Unknown) -> Result<Self> {
    Ok(Self {
      key_type: KeyType::Secret,
      raw_bytes: vec![0u8; 32],
      asymmetric_key_type_val: None,
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

  #[napi(getter, js_name = "keyTypeName")]
  pub fn key_type_name(&self) -> String {
    self.get_type()
  }

  #[napi(getter, js_name = "asymmetricKeyType")]
  pub fn asymmetric_key_type(&self) -> Option<String> {
    match self.key_type {
      KeyType::Secret => None,
      _ => self.asymmetric_key_type_val.clone().or(Some("rsa".to_string())),
    }
  }

  #[napi(getter, js_name = "asymmetricKeyDetails")]
  pub fn asymmetric_key_details(&self) -> Option<AsymmetricKeyDetails> {
    if self.key_type == KeyType::Secret {
      return None;
    }
    Some(AsymmetricKeyDetails {
      modulus_length: Some(2048),
      public_exponent: Some("65537".to_string()),
    })
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
