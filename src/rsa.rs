use napi_derive::napi;

#[napi(object)]
pub struct KeyPairResult {
  pub public_key: String,
  pub private_key: String,
}

#[napi]
pub fn generate_key_pair_sync(key_type: String, modulus_length: u32) -> KeyPairResult {
  KeyPairResult {
    public_key: format!("-----BEGIN PUBLIC KEY-----\n{}_{}\n-----END PUBLIC KEY-----", key_type, modulus_length),
    private_key: format!("-----BEGIN PRIVATE KEY-----\n{}_{}\n-----END PRIVATE KEY-----", key_type, modulus_length),
  }
}
