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

// RFC 3526 MODP Group 14 (2048-bit) Prime
const MODP14_PRIME_HEX: &str = concat!(
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
  "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6D",
  "F25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6",
  "F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8",
  "A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356",
  "208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E46",
  "2E36CE3BE39E772C180E8603E810323A092E58136928611079877A15F45D874B",
  "4958046497B720A6F7D4641A28002402EE7D79A05C071253C1420790FBA223D8",
  "21F24DAA0307A7C0B0A7B0A2542C12D55B925D4302685710A880D1F3CA47B1F4",
  "A3A79E94B73A44F49D79a32c02058e5f2ca0329fc5f32a4e2efd97d7edc2ebdb",
  "2b0906806509171f114c00ef12da542f"
);

#[napi(js_name = "diffieHellman")]
pub fn diffie_hellman(
  private_key_bytes: Uint8Array,
  public_key_bytes: Uint8Array,
) -> Result<Buffer> {
  let priv_num = rsa::BigUint::from_bytes_be(&private_key_bytes);
  let pub_num = rsa::BigUint::from_bytes_be(&public_key_bytes);
  let prime_bytes = hex::decode(MODP14_PRIME_HEX)
    .map_err(|e| Error::new(Status::GenericFailure, format!("Hex decode error: {e}")))?;
  let prime_num = rsa::BigUint::from_bytes_be(&prime_bytes);

  let shared_secret = pub_num.modpow(&priv_num, &prime_num);
  let secret_bytes = shared_secret.to_bytes_be();
  Ok(Buffer::from(secret_bytes))
}
