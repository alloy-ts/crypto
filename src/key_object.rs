use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi]
#[derive(Clone, Copy)]
pub enum KeyType {
  Secret,
  Public,
  Private,
}

#[napi]
pub struct KeyObject {
  pub key_type: KeyType,
  pub raw_bytes: Vec<u8>,
}

#[napi]
impl KeyObject {
  #[napi(constructor)]
  pub fn new(key_type: KeyType, raw_bytes: Uint8Array) -> Self {
    Self {
      key_type,
      raw_bytes: raw_bytes.to_vec(),
    }
  }

  #[napi(getter, js_name = "type")]
  pub fn get_type(&self) -> String {
    match self.key_type {
      KeyType::Secret => "secret".to_string(),
      KeyType::Public => "public".to_string(),
      KeyType::Private => "private".to_string(),
    }
  }

  #[napi(getter, js_name = "symmetricKeySize")]
  pub fn symmetric_key_size(&self) -> Option<u32> {
    match self.key_type {
      KeyType::Secret => Some(self.raw_bytes.len() as u32),
      _ => None,
    }
  }

  #[napi(getter, js_name = "asymmetricKeyType")]
  pub fn asymmetric_key_type(&self) -> Option<String> {
    match self.key_type {
      KeyType::Secret => None,
      _ => {
        if self.raw_bytes.len() == 32 {
          Some("ed25519".to_string())
        } else {
          Some("rsa".to_string())
        }
      }
    }
  }

  #[napi]
  pub fn equals(&self, other: &KeyObject) -> bool {
    let self_type = self.get_type();
    let other_type = other.get_type();
    self_type == other_type && self.raw_bytes == other.raw_bytes
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
