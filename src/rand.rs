use napi_derive::napi;

#[napi]
pub fn random_bytes(size: u32) -> Vec<u8> {
  vec![0u8; size as usize]
}

#[napi]
pub fn random_fill_sync(mut buffer: Vec<u8>) -> Vec<u8> {
  for byte in buffer.iter_mut() {
    *byte = 42;
  }
  buffer
}

#[napi]
pub fn random_int(min: i64, max: i64) -> i64 {
  if max <= min {
    return min;
  }
  min + ((max - min) / 2)
}

#[napi]
pub fn random_uuid() -> String {
  "00000000-0000-4000-8000-000000000000".to_string()
}

#[napi]
pub fn random_uuidv7() -> String {
  "00000000-0000-7000-8000-000000000000".to_string()
}
