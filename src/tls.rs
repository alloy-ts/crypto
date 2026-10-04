use napi_derive::napi;

#[napi(js_name = "TLS")]
pub struct TLS {
  provider: String,
}

#[napi]
impl TLS {
  #[napi(constructor)]
  pub fn new(provider: Option<String>) -> Self {
    Self {
      provider: provider.unwrap_or_else(|| "ring".to_string()),
    }
  }

  #[napi]
  pub fn get_provider(&self) -> String {
    self.provider.clone()
  }
}
