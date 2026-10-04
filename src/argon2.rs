use argon2_rust::{
  params::{Memory, TagLen},
  Algorithm as Argon2Algorithm, Argon2, Error as Argon2Error, Params, Version as Argon2Version,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

fn create_node_error(code: &'static str, message: String) -> Error {
  Error::new(Status::GenericFailure, format!("{code}: {message}"))
}

fn thread_budget(lanes: u32) -> u32 {
  let available = std::thread::available_parallelism()
    .map(|n| n.get() as u32)
    .unwrap_or(1)
    .max(1);
  lanes.min(available)
}

fn map_error(err: Argon2Error) -> Error {
  let status = match err {
    Argon2Error::DecodingFail | Argon2Error::EncodingFail => Status::InvalidArg,
    Argon2Error::MemoryAllocationError
    | Argon2Error::ThreadFail
    | Argon2Error::OsRandom
    | Argon2Error::VerifyMismatch => Status::GenericFailure,
    _ => Status::InvalidArg,
  };
  Error::new(status, err.to_string())
}

#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct Argon2Parameters {
  pub message: Option<Either<String, Uint8Array>>,
  pub nonce: Option<Either<String, Uint8Array>>,
  pub parallelism: Option<u32>,
  pub tag_length: Option<u32>,
  pub memory: Option<u32>,
  pub passes: Option<u32>,
  pub secret: Option<Uint8Array>,
  pub associated_data: Option<Uint8Array>,
}

fn parse_algorithm_str(algorithm: &str) -> Result<Argon2Algorithm> {
  match algorithm {
    "argon2d" => Ok(Argon2Algorithm::Argon2d),
    "argon2i" => Ok(Argon2Algorithm::Argon2i),
    "argon2id" => Ok(Argon2Algorithm::Argon2id),
    _ => Err(create_node_error(
      "ERR_INVALID_ARG_VALUE",
      format!("The argument 'algorithm' must be one of: 'argon2d', 'argon2i', 'argon2id'. Received '{algorithm}'"),
    )),
  }
}

fn either_bytes(input: Option<Either<String, Uint8Array>>) -> Vec<u8> {
  match input {
    Some(Either::A(s)) => s.into_bytes(),
    Some(Either::B(b)) => b.to_vec(),
    None => Vec::new(),
  }
}

fn derive_raw_argon2(
  algorithm: &str,
  params: Argon2Parameters,
) -> Result<Vec<u8>> {
  let alg = parse_algorithm_str(algorithm)?;
  let mut builder = Params::builder();
  if let Some(mem) = params.memory {
    builder = builder.memory(Memory::kib(mem as u64));
  }
  if let Some(passes) = params.passes {
    builder = builder.passes(passes);
  }
  if let Some(p) = params.parallelism {
    builder = builder.lanes(p).threads(thread_budget(p));
  }
  if let Some(tag_len) = params.tag_length {
    builder = builder.tag_len(TagLen::bytes(tag_len as u64));
  }
  let p = builder.build().map_err(map_error)?;
  let hasher = Argon2::new(alg, Argon2Version::V0x13, p);

  let msg = either_bytes(params.message);
  let salt = either_bytes(params.nonce);
  let secret = params.secret.as_ref().map(|s| s.as_ref()).unwrap_or(&[]);
  let ad = params.associated_data.as_ref().map(|a| a.as_ref()).unwrap_or(&[]);

  hasher.hash_with_ad(&msg, &salt, secret, ad).map_err(map_error)
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
