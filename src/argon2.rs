use argon2_rust::{
  params::{Memory, TagLen},
  Algorithm as Argon2Algorithm, Argon2, Params, Version as Argon2Version,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct Argon2Parameters {
  pub message: Option<Either<String, Uint8Array>>,
  pub nonce: Option<Either<String, Uint8Array>>,
  pub parallelism: Option<u32>,
  pub tag_length: Option<f64>,
  pub memory: Option<f64>,
  pub passes: Option<f64>,
  pub secret: Option<Either<String, Uint8Array>>,
  pub associated_data: Option<Either<String, Uint8Array>>,
}

fn thread_budget(lanes: u32) -> u32 {
  let available = std::thread::available_parallelism()
    .map(|n| n.get() as u32)
    .unwrap_or(1)
    .max(1);
  lanes.min(available)
}

fn either_bytes(input: &Option<Either<String, Uint8Array>>) -> Vec<u8> {
  match input {
    Some(Either::A(s)) => s.as_bytes().to_vec(),
    Some(Either::B(b)) => b.to_vec(),
    None => Vec::new(),
  }
}

fn derive_raw_argon2(
  algorithm: &str,
  params: Argon2Parameters,
) -> Result<Vec<u8>> {
  let alg = match algorithm {
    "argon2d" => Argon2Algorithm::Argon2d,
    "argon2i" => Argon2Algorithm::Argon2i,
    "argon2id" => Argon2Algorithm::Argon2id,
    _ => return Err(Error::new(Status::InvalidArg, format!("Unsupported algorithm: {algorithm}"))),
  };

  let mut builder = Params::builder();
  if let Some(mem) = params.memory {
    builder = builder.memory(Memory::kib(mem as u64));
  }
  if let Some(passes) = params.passes {
    builder = builder.passes(passes as u32);
  }
  if let Some(p) = params.parallelism {
    builder = builder.lanes(p).threads(thread_budget(p));
  }
  if let Some(tag_len) = params.tag_length {
    builder = builder.tag_len(TagLen::bytes(tag_len as u64));
  }

  let p = builder.build().map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
  let hasher = Argon2::new(alg, Argon2Version::V0x13, p);

  let msg = either_bytes(&params.message);
  let salt = either_bytes(&params.nonce);
  let secret = either_bytes(&params.secret);
  let ad = either_bytes(&params.associated_data);

  hasher
    .hash_with_ad(&msg, &salt, &secret, &ad)
    .map_err(|e| Error::new(Status::GenericFailure, format!("Argon2 derivation failed: {e}")))
}

#[napi(js_name = "argon2Sync")]
pub fn argon2_sync_node(
  algorithm: String,
  parameters: Argon2Parameters,
) -> Result<Buffer> {
  let raw = derive_raw_argon2(&algorithm, parameters)?;
  Ok(Buffer::from(raw))
}

pub struct Argon2NodeTask {
  algorithm: String,
  parameters: Argon2Parameters,
}

#[napi]
impl Task for Argon2NodeTask {
  type Output = Vec<u8>;
  type JsValue = Buffer;

  fn compute(&mut self) -> Result<Self::Output> {
    derive_raw_argon2(&self.algorithm, std::mem::take(&mut self.parameters))
  }

  fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
    Ok(Buffer::from(output))
  }
}

#[napi(js_name = "argon2")]
pub fn argon2_node(
  algorithm: String,
  parameters: Argon2Parameters,
) -> AsyncTask<Argon2NodeTask> {
  AsyncTask::new(Argon2NodeTask {
    algorithm,
    parameters,
  })
}
