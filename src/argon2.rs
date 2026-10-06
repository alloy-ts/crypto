use argon2_rust::{
  params::{Memory, TagLen},
  Algorithm as Argon2Algorithm, Argon2, Error as Argon2Error, Params, Version as Argon2Version,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct Argon2Parameters {
  pub message: Option<Either<String, Uint8Array>>,
  pub nonce: Option<Either<String, Uint8Array>>,
  pub parallelism: Option<u32>,
  pub tag_length: Option<u32>,
  pub memory: Option<u32>,
  pub passes: Option<u32>,
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

fn either_bytes(input: Option<Either<String, Uint8Array>>) -> Vec<u8> {
  match input {
    Some(Either::A(s)) => s.into_bytes(),
    Some(Either::B(b)) => b.to_vec(),
    None => Vec::new(),
  }
}

fn parse_algorithm_str(algorithm: &str) -> Result<Argon2Algorithm> {
  match algorithm.to_lowercase().as_str() {
    "argon2d" => Ok(Argon2Algorithm::Argon2d),
    "argon2i" => Ok(Argon2Algorithm::Argon2i),
    "argon2id" => Ok(Argon2Algorithm::Argon2id),
    _ => Err(Error::new(
      Status::InvalidArg,
      format!("Unsupported Argon2 algorithm: {algorithm}"),
    )),
  }
}

fn validate_and_derive(
  algorithm: &str,
  params: Argon2Parameters,
) -> Result<Vec<u8>> {
  let alg = parse_algorithm_str(algorithm)?;

  let message = params.message.ok_or_else(|| {
    Error::new(Status::InvalidArg, "ERR_INVALID_ARG_TYPE: message is required")
  })?;
  let nonce = params.nonce.ok_or_else(|| {
    Error::new(Status::InvalidArg, "ERR_INVALID_ARG_TYPE: nonce is required")
  })?;
  let parallelism = params.parallelism.ok_or_else(|| {
    Error::new(Status::InvalidArg, "ERR_INVALID_ARG_TYPE: parallelism is required")
  })?;
  let tag_length = params.tag_length.ok_or_else(|| {
    Error::new(Status::InvalidArg, "ERR_INVALID_ARG_TYPE: tagLength is required")
  })?;
  let memory = params.memory.ok_or_else(|| {
    Error::new(Status::InvalidArg, "ERR_INVALID_ARG_TYPE: memory is required")
  })?;
  let passes = params.passes.ok_or_else(|| {
    Error::new(Status::InvalidArg, "ERR_INVALID_ARG_TYPE: passes is required")
  })?;

  if parallelism < 1 || parallelism > (1 << 24) - 1 {
    return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE: parallelism out of range"));
  }
  if tag_length < 4 {
    return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE: tagLength must be at least 4"));
  }
  if memory < 8 * parallelism {
    return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE: memory must be at least 8 * parallelism"));
  }
  if passes < 1 {
    return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE: passes must be at least 1"));
  }

  let msg_bytes = either_bytes(Some(message));
  let nonce_bytes = either_bytes(Some(nonce));
  if nonce_bytes.len() < 8 {
    return Err(Error::new(Status::InvalidArg, "ERR_OUT_OF_RANGE: nonce must be at least 8 bytes"));
  }

  let secret_bytes = either_bytes(params.secret);
  let ad_bytes = either_bytes(params.associated_data);

  let mut builder = Params::builder();
  builder = builder.memory(Memory::kib(memory as u64));
  builder = builder.passes(passes);
  builder = builder.lanes(parallelism).threads(thread_budget(parallelism));
  builder = builder.tag_len(TagLen::bytes(tag_length as u64));

  let p = builder.build().map_err(map_error)?;
  let hasher = Argon2::new(alg, Argon2Version::V0x13, p);

  hasher.hash_with_ad(&msg_bytes, &nonce_bytes, &secret_bytes, &ad_bytes).map_err(map_error)
}

#[napi(js_name = "argon2Sync")]
pub fn argon2_sync_node(
  algorithm: String,
  parameters: Argon2Parameters,
) -> Result<Buffer> {
  let raw = validate_and_derive(&algorithm, parameters)?;
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
    validate_and_derive(&self.algorithm, std::mem::take(&mut self.parameters))
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
