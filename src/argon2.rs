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

fn either_bytes_ref(input: Option<&Either<String, Uint8Array>>) -> Vec<u8> {
  match input {
    Some(Either::A(s)) => s.as_bytes().to_vec(),
    Some(Either::B(b)) => b.as_ref().to_vec(),
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

fn validate_and_derive_argon2(
  algorithm: &str,
  params: &Argon2Parameters,
) -> Result<Vec<u8>> {
  let alg = parse_algorithm_str(algorithm)?;

  if params.message.is_none() {
    return Err(Error::new(
      Status::InvalidArg,
      "The 'parameters.message' property is required",
    ));
  }
  let msg = either_bytes_ref(params.message.as_ref());

  if params.nonce.is_none() {
    return Err(Error::new(
      Status::InvalidArg,
      "The 'parameters.nonce' property is required",
    ));
  }
  let nonce = either_bytes_ref(params.nonce.as_ref());
  if nonce.len() < 8 {
    return Err(Error::new(
      Status::InvalidArg,
      "The 'parameters.nonce' buffer length must be at least 8",
    ));
  }

  let parallelism = match params.parallelism {
    Some(p) if p >= 1 && p <= 16_777_215 => p,
    _ => {
      return Err(Error::new(
        Status::InvalidArg,
        "The value of 'parameters.parallelism' is out of range",
      ))
    }
  };

  let tag_len = match params.tag_length {
    Some(t) if t >= 4 => t,
    _ => {
      return Err(Error::new(
        Status::InvalidArg,
        "The value of 'parameters.tagLength' is out of range",
      ))
    }
  };

  let memory = match params.memory {
    Some(m) if (m as u64) >= 8 * (parallelism as u64) => m,
    _ => {
      return Err(Error::new(
        Status::InvalidArg,
        "The value of 'parameters.memory' is out of range",
      ))
    }
  };

  let passes = match params.passes {
    Some(p) if p >= 1 => p,
    _ => {
      return Err(Error::new(
        Status::InvalidArg,
        "The value of 'parameters.passes' is out of range",
      ))
    }
  };

  let secret = either_bytes_ref(params.secret.as_ref());
  let ad = either_bytes_ref(params.associated_data.as_ref());

  let mut builder = Params::builder();
  builder = builder.memory(Memory::kib(memory as u64));
  builder = builder.passes(passes);
  builder = builder.lanes(parallelism).threads(thread_budget(parallelism));
  builder = builder.tag_len(TagLen::bytes(tag_len as u64));

  let p = builder.build().map_err(map_error)?;
  let hasher = Argon2::new(alg, Argon2Version::V0x13, p);

  hasher.hash_with_ad(&msg, &nonce, &secret, &ad).map_err(map_error)
}

#[napi(js_name = "argon2Sync")]
pub fn argon2_sync_node(
  algorithm: String,
  parameters: Argon2Parameters,
) -> Result<Buffer> {
  let raw = validate_and_derive_argon2(&algorithm, &parameters)?;
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
    validate_and_derive_argon2(&self.algorithm, &self.parameters)
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
