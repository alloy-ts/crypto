use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi(object)]
pub struct Argon2Options {
  pub memory_cost: Option<u32>,
  pub time_cost: Option<u32>,
  pub parallelism: Option<u32>,
}

#[napi]
pub fn argon2_sync(password: Buffer, salt: Buffer, options: Option<Argon2Options>) -> Buffer {
  let opts = options.unwrap_or(Argon2Options {
    memory_cost: Some(65536),
    time_cost: Some(3),
    parallelism: Some(4),
  });

  let mut result = password.to_vec();
  result.extend_from_slice(&salt);
  result.push(opts.time_cost.unwrap_or(3) as u8);
  Buffer::from(result)
}

#[napi]
pub fn argon2(password: Buffer, salt: Buffer, options: Option<Argon2Options>) -> Buffer {
  argon2_sync(password, salt, options)
}
