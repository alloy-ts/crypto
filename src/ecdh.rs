use napi::bindgen_prelude::*;
use napi_derive::napi;
use ring::agreement;

#[napi(js_name = "ECDH")]
pub struct ECDH {
  _curve_name: String,
  private_key: Option<agreement::EphemeralPrivateKey>,
  public_key_bytes: Vec<u8>,
}

#[napi]
impl ECDH {
  #[napi(constructor)]
  pub fn new(curve_name: String) -> Result<Self> {
    let rng = ring::rand::SystemRandom::new();
    let alg = match curve_name.to_lowercase().as_str() {
      "p256" | "prime256v1" | "secp256r1" => &agreement::ECDH_P256,
      "p384" | "secp384r1" => &agreement::ECDH_P384,
      "x25519" => &agreement::X25519,
      _ => {
        return Err(Error::new(
          Status::InvalidArg,
          format!("Unsupported curve: {curve_name}"),
        ))
      }
    };

    let key = agreement::EphemeralPrivateKey::generate(alg, &rng)
      .map_err(|_| Error::new(Status::GenericFailure, "Failed to generate ECDH key"))?;
    let pub_bytes = key
      .compute_public_key()
      .map_err(|_| Error::new(Status::GenericFailure, "Failed to compute public key"))?
      .as_ref()
      .to_vec();

    Ok(Self {
      _curve_name: curve_name,
      private_key: Some(key),
      public_key_bytes: pub_bytes,
    })
  }

  #[napi]
  pub fn get_public_key(&self) -> Buffer {
    Buffer::from(self.public_key_bytes.clone())
  }

  #[napi]
  pub fn compute_secret(&mut self, peer_public_key: Uint8Array) -> Result<Buffer> {
    let private_key = self
      .private_key
      .take()
      .ok_or_else(|| Error::new(Status::GenericFailure, "ECDH key already consumed"))?;
    let peer_key = agreement::UnparsedPublicKey::new(private_key.algorithm(), &peer_public_key);

    agreement::agree_ephemeral(private_key, &peer_key, |k| Ok(Buffer::from(k.to_vec())))
      .map_err(|_| Error::new(Status::GenericFailure, "Key agreement failed"))?
  }
}

#[napi(js_name = "createECDH")]
pub fn create_ecdh(curve_name: String) -> Result<ECDH> {
  ECDH::new(curve_name)
}

#[napi(js_name = "createDiffieHellman")]
pub fn create_diffie_hellman(group_or_prime: Either<String, u32>) -> Result<ECDH> {
  let curve = match group_or_prime {
    Either::A(s) => s,
    Either::B(_) => "p256".to_string(),
  };
  ECDH::new(curve)
}

#[napi(js_name = "createDiffieHellmanGroup")]
pub fn create_diffie_hellman_group(name: String) -> Result<ECDH> {
  ECDH::new(name)
}
