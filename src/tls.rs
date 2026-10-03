use std::sync::Arc;

use napi_derive::napi;
use rustls::crypto::CryptoProvider;

#[napi]
pub enum CryptoProviderType {
  Ring,
  OpenSSL,
  BoringSSL,
  MbedTLS,
}

#[napi(js_name = "TLS")]
pub struct TLS {
  provider_type: CryptoProviderType,
}

#[napi]
impl TLS {
  #[napi(constructor)]
  pub fn new(provider: Option<CryptoProviderType>) -> Self {
    Self {
      provider_type: provider.unwrap_or(CryptoProviderType::Ring),
    }
  }

  #[napi(getter)]
  pub fn provider_name(&self) -> String {
    match self.provider_type {
      CryptoProviderType::Ring => "ring".to_string(),
      CryptoProviderType::OpenSSL => "openssl".to_string(),
      CryptoProviderType::BoringSSL => "boringssl".to_string(),
      CryptoProviderType::MbedTLS => "mbedtls".to_string(),
    }
  }

  pub fn get_rustls_provider(&self) -> Arc<CryptoProvider> {
    match self.provider_type {
      CryptoProviderType::Ring => Arc::new(rustls::crypto::ring::default_provider()),
      CryptoProviderType::OpenSSL => Arc::new(rustls_openssl::default_provider()),
      CryptoProviderType::BoringSSL => Arc::new(boring_rustls_provider::provider()),
      CryptoProviderType::MbedTLS => Arc::new(rustls_mbedcrypto_provider::mbedtls_crypto_provider()),
    }
  }

  #[napi]
  pub fn is_supported(&self) -> bool {
    true
  }
}
