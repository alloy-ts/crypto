use napi::bindgen_prelude::*;
use napi::sys;
use napi_derive::napi;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{SystemTime, UNIX_EPOCH};

#[napi(object, object_to_js = false)]
#[derive(Default)]
pub struct RandomUUIDOptions {
  pub disable_entropy_cache: Option<bool>,
}

#[derive(Clone, Copy)]
struct BufferInfo {
  ptr: *mut u8,
  element_size: usize,
  total_elements: usize,
}

fn get_js_null(env: &Env) -> Result<sys::napi_value> {
  let mut val = std::ptr::null_mut();
  unsafe {
    check_status!(sys::napi_get_null(env.raw(), &mut val), "Failed to get null")?;
  }
  Ok(val)
}

fn get_js_undefined(env: &Env) -> Result<sys::napi_value> {
  let mut val = std::ptr::null_mut();
  unsafe {
    check_status!(sys::napi_get_undefined(env.raw(), &mut val), "Failed to get undefined")?;
  }
  Ok(val)
}

fn to_napi_val<T: ToNapiValue>(env: &Env, val: T) -> Result<sys::napi_value> {
  unsafe { ToNapiValue::to_napi_value(env.raw(), val) }
}

fn invoke_callback(
  env: &Env,
  cb: &Function,
  err_val: sys::napi_value,
  res_val: sys::napi_value,
) -> Result<()> {
  let mut res = std::ptr::null_mut();
  let args = [err_val, res_val];
  let undefined = get_js_undefined(env)?;
  unsafe {
    check_status!(
      sys::napi_call_function(
        env.raw(),
        undefined,
        cb.raw(),
        2,
        args.as_ptr(),
        &mut res,
      ),
      "Callback execution failed"
    )?;
  }
  Ok(())
}

fn extract_buffer_info(env: &Env, obj: &Object) -> Result<BufferInfo> {
  let mut is_typedarray = false;
  let mut is_arraybuffer = false;
  let mut is_dataview = false;
  let mut is_buffer = false;

  unsafe {
    sys::napi_is_typedarray(env.raw(), obj.raw(), &mut is_typedarray);
    sys::napi_is_arraybuffer(env.raw(), obj.raw(), &mut is_arraybuffer);
    sys::napi_is_dataview(env.raw(), obj.raw(), &mut is_dataview);
    sys::napi_is_buffer(env.raw(), obj.raw(), &mut is_buffer);
  }

  if is_typedarray {
    let mut typedarray_type = sys::TypedarrayType::uint8_array;
    let mut length = 0;
    let mut data = std::ptr::null_mut();
    let mut arraybuffer = std::ptr::null_mut();
    let mut byte_offset = 0;
    unsafe {
      check_status!(
        sys::napi_get_typedarray_info(
          env.raw(),
          obj.raw(),
          &mut typedarray_type,
          &mut length,
          &mut data,
          &mut arraybuffer,
          &mut byte_offset,
        ),
        "Failed to get TypedArray info"
      )?;
    }
    let element_size = match typedarray_type {
      sys::TypedarrayType::int8_array
      | sys::TypedarrayType::uint8_array
      | sys::TypedarrayType::uint8_clamped_array => 1,
      sys::TypedarrayType::int16_array | sys::TypedarrayType::uint16_array => 2,
      sys::TypedarrayType::int32_array
      | sys::TypedarrayType::uint32_array
      | sys::TypedarrayType::float32_array => 4,
      sys::TypedarrayType::float64_array => 8,
      _ => 1,
    };
    return Ok(BufferInfo {
      ptr: data as *mut u8,
      element_size,
      total_elements: length,
    });
  }

  if is_buffer {
    let mut data = std::ptr::null_mut();
    let mut len = 0;
    unsafe {
      check_status!(
        sys::napi_get_buffer_info(env.raw(), obj.raw(), &mut data, &mut len),
        "Failed to get Buffer info"
      )?;
    }
    return Ok(BufferInfo {
      ptr: data as *mut u8,
      element_size: 1,
      total_elements: len,
    });
  }

  if is_dataview {
    let mut byte_length = 0;
    let mut data = std::ptr::null_mut();
    let mut arraybuffer = std::ptr::null_mut();
    let mut byte_offset = 0;
    unsafe {
      check_status!(
        sys::napi_get_dataview_info(
          env.raw(),
          obj.raw(),
          &mut byte_length,
          &mut data,
          &mut arraybuffer,
          &mut byte_offset,
        ),
        "Failed to get DataView info"
      )?;
    }
    return Ok(BufferInfo {
      ptr: data as *mut u8,
      element_size: 1,
      total_elements: byte_length,
    });
  }

  if is_arraybuffer {
    let mut data = std::ptr::null_mut();
    let mut byte_length = 0;
    unsafe {
      check_status!(
        sys::napi_get_arraybuffer_info(env.raw(), obj.raw(), &mut data, &mut byte_length),
        "Failed to get ArrayBuffer info"
      )?;
    }
    return Ok(BufferInfo {
      ptr: data as *mut u8,
      element_size: 1,
      total_elements: byte_length,
    });
  }

  Err(Error::new(
    Status::InvalidArg,
    "ERR_INVALID_ARG_TYPE: The \"buffer\" argument must be an instance of ArrayBuffer, Buffer, TypedArray, or DataView",
  ))
}

const MAX_SIZE: usize = 2147483647; // 2**31 - 1

#[napi(js_name = "randomBytes", ts_args_type = "size: number, callback?: (err: Error | null, buf: Buffer) => void", ts_return_type = "Buffer | void")]
pub fn random_bytes(env: Env, size: f64, callback: Option<Function>) -> Result<Option<Buffer>> {
  if size.is_nan() || size < 0.0 || size > (MAX_SIZE as f64) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: The value of \"size\" is out of range. It must be >= 0 and <= 2147483647",
    ));
  }

  let size_usize = size as usize;
  let mut buf = vec![0u8; size_usize];
  let rng = SystemRandom::new();
  rng
    .fill(&mut buf)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  let buffer = Buffer::from(buf);

  if let Some(cb) = callback {
    let buf_val = to_napi_val(&env, buffer)?;
    invoke_callback(&env, &cb, get_js_null(&env)?, buf_val)?;
    Ok(None)
  } else {
    Ok(Some(buffer))
  }
}

fn process_random_fill(
  env: &Env,
  obj: Object,
  offset_arg: Option<f64>,
  size_arg: Option<f64>,
) -> Result<(*mut u8, usize)> {
  let info = extract_buffer_info(env, &obj)?;

  let offset = offset_arg.unwrap_or(0.0);
  if offset.is_nan() || offset < 0.0 || offset > (info.total_elements as f64) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: The value of \"offset\" is out of range",
    ));
  }
  let offset_elem = offset as usize;

  let default_size = (info.total_elements - offset_elem) as f64;
  let size = size_arg.unwrap_or(default_size);
  if size.is_nan() || size < 0.0 || size > (MAX_SIZE as f64) {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: The value of \"size\" is out of range",
    ));
  }
  let size_elem = size as usize;

  if offset_elem + size_elem > info.total_elements {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: offset + size is out of bounds",
    ));
  }

  let byte_offset = offset_elem * info.element_size;
  let byte_size = size_elem * info.element_size;

  unsafe {
    let target_ptr = info.ptr.add(byte_offset);
    Ok((target_ptr, byte_size))
  }
}

#[napi(js_name = "randomFillSync")]
pub fn random_fill_sync(
  env: Env,
  buffer: Object,
  offset: Option<f64>,
  size: Option<f64>,
) -> Result<Object> {
  let (target_ptr, byte_size) = process_random_fill(&env, buffer.clone(), offset, size)?;

  if byte_size > 0 {
    let slice = unsafe { std::slice::from_raw_parts_mut(target_ptr, byte_size) };
    let rng = SystemRandom::new();
    rng
      .fill(slice)
      .map_err(|_| Error::new(Status::GenericFailure, "Random fill failed"))?;
  }

  Ok(buffer)
}

#[napi(
  js_name = "randomFill",
  ts_args_type = "buffer: ArrayBuffer | Buffer | TypedArray | DataView, offsetOrCallback?: number | ((err: Error | null, buf: any) => void), sizeOrCallback?: number | ((err: Error | null, buf: any) => void), callback?: (err: Error | null, buf: any) => void",
  ts_return_type = "void"
)]
pub fn random_fill(
  env: Env,
  buffer: Object,
  arg1: Option<Either<f64, Function>>,
  arg2: Option<Either<f64, Function>>,
  arg3: Option<Function>,
) -> Result<()> {
  let mut offset_val: Option<f64> = None;
  let mut size_val: Option<f64> = None;
  let mut cb_opt: Option<Function> = None;

  match arg1 {
    Some(Either::B(cb)) => {
      cb_opt = Some(cb);
    }
    Some(Either::A(off)) => {
      offset_val = Some(off);
      match arg2 {
        Some(Either::B(cb)) => {
          cb_opt = Some(cb);
        }
        Some(Either::A(sz)) => {
          size_val = Some(sz);
          if let Some(cb) = arg3 {
            cb_opt = Some(cb);
          }
        }
        None => {}
      }
    }
    None => {}
  }

  let cb = match cb_opt {
    Some(f) => f,
    None => {
      return Err(Error::new(
        Status::InvalidArg,
        "ERR_INVALID_ARG_TYPE: The \"callback\" argument must be of type function",
      ));
    }
  };

  let (target_ptr, byte_size) = process_random_fill(&env, buffer.clone(), offset_val, size_val)?;

  if byte_size > 0 {
    let slice = unsafe { std::slice::from_raw_parts_mut(target_ptr, byte_size) };
    let rng = SystemRandom::new();
    rng
      .fill(slice)
      .map_err(|_| Error::new(Status::GenericFailure, "Random fill failed"))?;
  }

  let buf_val = to_napi_val(&env, buffer)?;
  invoke_callback(&env, &cb, get_js_null(&env)?, buf_val)?;
  Ok(())
}

const MAX_SAFE_INTEGER: f64 = 9007199254740991.0; // 2**53 - 1
const MIN_SAFE_INTEGER: f64 = -9007199254740991.0; // -(2**53 - 1)
const MAX_INT_RANGE: u64 = 281474976710656; // 2**48

fn generate_unbiased_random_int(min: i64, max: i64) -> Result<i64> {
  if min >= max {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: min must be less than max",
    ));
  }
  let range = (max - min) as u64;
  if range >= MAX_INT_RANGE {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: range (max - min) must be less than 2**48",
    ));
  }

  let limit = u64::MAX - (u64::MAX % range);
  let rng = SystemRandom::new();
  loop {
    let mut bytes = [0u8; 8];
    rng
      .fill(&mut bytes)
      .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;
    let val = u64::from_le_bytes(bytes);
    if val < limit {
      return Ok(min + ((val % range) as i64));
    }
  }
}

#[napi(
  js_name = "randomInt",
  ts_args_type = "minOrMax: number, maxOrCallback?: number | ((err: Error | null, n?: number) => void), callback?: (err: Error | null, n?: number) => void",
  ts_return_type = "number | void"
)]
pub fn random_int(
  env: Env,
  arg0: f64,
  arg1: Option<Either<f64, Function>>,
  arg2: Option<Function>,
) -> Result<Option<i64>> {
  let mut min_val: f64 = 0.0;
  let max_val: f64;
  let mut cb_opt: Option<Function> = None;

  match arg1 {
    Some(Either::B(cb)) => {
      max_val = arg0;
      cb_opt = Some(cb);
    }
    Some(Either::A(num)) => {
      min_val = arg0;
      max_val = num;
      if let Some(cb) = arg2 {
        cb_opt = Some(cb);
      }
    }
    None => {
      max_val = arg0;
    }
  }

  if min_val < MIN_SAFE_INTEGER || min_val > MAX_SAFE_INTEGER || !min_val.is_finite() || min_val.trunc() != min_val {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: min must be a safe integer",
    ));
  }
  if max_val < MIN_SAFE_INTEGER || max_val > MAX_SAFE_INTEGER || !max_val.is_finite() || max_val.trunc() != max_val {
    return Err(Error::new(
      Status::InvalidArg,
      "ERR_OUT_OF_RANGE: max must be a safe integer",
    ));
  }

  let min_i64 = min_val as i64;
  let max_i64 = max_val as i64;

  let n = generate_unbiased_random_int(min_i64, max_i64)?;

  if let Some(cb) = cb_opt {
    let js_num = to_napi_val(&env, n)?;
    invoke_callback(&env, &cb, get_js_null(&env)?, js_num)?;
    Ok(None)
  } else {
    Ok(Some(n))
  }
}

#[napi(js_name = "randomUUID")]
pub fn random_uuid(_options: Option<RandomUUIDOptions>) -> Result<String> {
  let mut bytes = [0u8; 16];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  Ok(format!(
    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
    u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
    u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
    u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
    u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
    u64::from_be_bytes([
      0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ])
  ))
}

#[napi(js_name = "randomUUIDv7")]
pub fn random_uuid_v7(_options: Option<RandomUUIDOptions>) -> Result<String> {
  let now_ms = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| Error::new(Status::GenericFailure, "System time error"))?
    .as_millis() as u64;

  let mut bytes = [0u8; 16];
  let rng = SystemRandom::new();
  rng
    .fill(&mut bytes)
    .map_err(|_| Error::new(Status::GenericFailure, "Random generation failed"))?;

  bytes[0] = (now_ms >> 40) as u8;
  bytes[1] = (now_ms >> 32) as u8;
  bytes[2] = (now_ms >> 24) as u8;
  bytes[3] = (now_ms >> 16) as u8;
  bytes[4] = (now_ms >> 8) as u8;
  bytes[5] = now_ms as u8;

  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  Ok(format!(
    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
    u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
    u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
    u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
    u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
    u64::from_be_bytes([
      0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    ])
  ))
}
