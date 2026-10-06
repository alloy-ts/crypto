import { createBuildCommand, NapiCli } from '@napi-rs/cli'
import { readFileSync, writeFileSync } from 'node:fs'

const build = createBuildCommand(process.argv.slice(2))
const options = build.getOptions()
const cli = new NapiCli()

const { task } = await cli.build({
  ...options,
  outputDir: 'build',
  cargoOptions: build.cargoOptions,
})

await task

const jsPath = 'build/index.js'
let content = readFileSync(jsPath, 'utf8')

const patch = `
function createArgon2Error(ctor, code, message) {
  const err = new ctor(message);
  err.code = code;
  return err;
}

function isBufferSource(val) {
  return (
    typeof val === "string" ||
    val instanceof ArrayBuffer ||
    (typeof SharedArrayBuffer !== "undefined" && val instanceof SharedArrayBuffer) ||
    ArrayBuffer.isView(val)
  );
}

function getArrayBufferOrView(val, name) {
  if (val === undefined) return undefined;
  if (!isBufferSource(val)) {
    let typeStr = typeof val;
    if (typeStr === "number") {
      typeStr = "type number (" + val + ")";
    } else if (val !== null && typeof val === "object") {
      typeStr = "an instance of " + (val.constructor ? val.constructor.name : "Object");
    }
    throw createArgon2Error(
      TypeError,
      "ERR_INVALID_ARG_TYPE",
      'The "' + name + '" property must be of type string or an instance of ArrayBuffer, Buffer, TypedArray, or DataView. Received ' + typeStr
    );
  }
  return val;
}

function toCopiedBuffer(val) {
  if (val === undefined || val === null) return undefined;
  if (typeof val === "string") return val;
  if (val instanceof ArrayBuffer || (typeof SharedArrayBuffer !== "undefined" && val instanceof SharedArrayBuffer)) {
    if (val.byteLength === 0) return Buffer.alloc(0);
    return Buffer.from(new Uint8Array(val));
  }
  if (ArrayBuffer.isView(val)) {
    if (val.byteLength === 0) return Buffer.alloc(0);
    return Buffer.from(new Uint8Array(val.buffer, val.byteOffset, val.byteLength));
  }
  return val;
}

function validateArgon2Args(algorithm, parameters, isAsync, callback) {
  if (typeof algorithm !== "string") {
    let receivedStr;
    if (algorithm === undefined) {
      receivedStr = "undefined";
    } else if (typeof algorithm === "number") {
      receivedStr = "type number (" + algorithm + ")";
    } else {
      receivedStr = typeof algorithm;
    }
    throw createArgon2Error(
      TypeError,
      "ERR_INVALID_ARG_TYPE",
      'The "algorithm" argument must be of type string. Received ' + receivedStr
    );
  }

  if (algorithm !== "argon2d" && algorithm !== "argon2i" && algorithm !== "argon2id") {
    throw createArgon2Error(
      TypeError,
      "ERR_INVALID_ARG_VALUE",
      "The argument 'algorithm' must be one of: 'argon2d', 'argon2i', 'argon2id'. Received '" + algorithm + "'"
    );
  }

  if (!parameters || typeof parameters !== "object" || Array.isArray(parameters)) {
    let receivedStr = parameters === null ? "null" : typeof parameters;
    throw createArgon2Error(
      TypeError,
      "ERR_INVALID_ARG_TYPE",
      'The "parameters" argument must be of type object. Received ' + receivedStr
    );
  }

  if (isAsync) {
    if (typeof callback !== "function") {
      let receivedStr;
      if (callback === null) {
        receivedStr = "null";
      } else if (typeof callback === "object") {
        receivedStr = "an instance of " + (callback.constructor ? callback.constructor.name : "Object");
      } else {
        receivedStr = typeof callback;
      }
      throw createArgon2Error(
        TypeError,
        "ERR_INVALID_ARG_TYPE",
        'The "callback" argument must be of type function. Received ' + receivedStr
      );
    }
  }

  const bufferTypesMsg = "must be of type string or an instance of ArrayBuffer, Buffer, TypedArray, or DataView. Received undefined";

  if (parameters.message === undefined) {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.message" property ' + bufferTypesMsg);
  }
  getArrayBufferOrView(parameters.message, "parameters.message");

  if (parameters.nonce === undefined) {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.nonce" property ' + bufferTypesMsg);
  }
  const nonce = getArrayBufferOrView(parameters.nonce, "parameters.nonce");
  let nonceLen = 0;
  if (typeof nonce === "string") nonceLen = Buffer.byteLength(nonce);
  else if (nonce instanceof ArrayBuffer || (typeof SharedArrayBuffer !== "undefined" && nonce instanceof SharedArrayBuffer)) nonceLen = nonce.byteLength;
  else if (ArrayBuffer.isView(nonce)) nonceLen = nonce.byteLength;
  if (nonceLen < 8 || nonceLen > 4294967295) {
    throw createArgon2Error(
      RangeError,
      "ERR_OUT_OF_RANGE",
      'The value of "parameters.nonce.byteLength" is out of range. It must be >= 8 && <= 4294967295. Received ' + nonceLen
    );
  }

  if (parameters.parallelism === undefined) {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.parallelism" property must be of type number. Received undefined');
  }
  if (typeof parameters.parallelism !== "number") {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.parallelism" property must be of type number. Received ' + typeof parameters.parallelism);
  }
  if (parameters.parallelism < 1 || parameters.parallelism > 16777215) {
    throw createArgon2Error(
      RangeError,
      "ERR_OUT_OF_RANGE",
      'The value of "parameters.parallelism" is out of range. It must be >= 1 && <= 16777215. Received ' + parameters.parallelism
    );
  }

  if (parameters.tagLength === undefined) {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.tagLength" property must be of type number. Received undefined');
  }
  if (typeof parameters.tagLength !== "number") {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.tagLength" property must be of type number. Received ' + typeof parameters.tagLength);
  }
  if (parameters.tagLength < 4 || parameters.tagLength > 4294967295) {
    throw createArgon2Error(
      RangeError,
      "ERR_OUT_OF_RANGE",
      'The value of "parameters.tagLength" is out of range. It must be >= 4 && <= 4294967295. Received ' + parameters.tagLength
    );
  }

  if (parameters.memory === undefined) {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.memory" property must be of type number. Received undefined');
  }
  if (typeof parameters.memory !== "number") {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.memory" property must be of type number. Received ' + typeof parameters.memory);
  }
  const minMemory = 8 * parameters.parallelism;
  if (parameters.memory < minMemory || parameters.memory > 4294967295) {
    throw createArgon2Error(
      RangeError,
      "ERR_OUT_OF_RANGE",
      'The value of "parameters.memory" is out of range. It must be >= ' + minMemory + ' && <= 4294967295. Received ' + parameters.memory
    );
  }

  if (parameters.passes === undefined) {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.passes" property must be of type number. Received undefined');
  }
  if (typeof parameters.passes !== "number") {
    throw createArgon2Error(TypeError, "ERR_INVALID_ARG_TYPE", 'The "parameters.passes" property must be of type number. Received ' + typeof parameters.passes);
  }
  if (parameters.passes < 1 || parameters.passes > 4294967295) {
    throw createArgon2Error(
      RangeError,
      "ERR_OUT_OF_RANGE",
      'The value of "parameters.passes" is out of range. It must be >= 1 && <= 4294967295. Received ' + parameters.passes
    );
  }

  getArrayBufferOrView(parameters.secret, "parameters.secret");
  getArrayBufferOrView(parameters.associatedData, "parameters.associatedData");
}

const originalArgon2Sync = nativeBinding.argon2Sync;
const originalArgon2Async = nativeBinding.argon2;

function argon2Sync(algorithm, parameters) {
  validateArgon2Args(algorithm, parameters, false);
  const clonedParams = {
    ...parameters,
    message: toCopiedBuffer(parameters.message),
    nonce: toCopiedBuffer(parameters.nonce),
    secret: toCopiedBuffer(parameters.secret),
    associatedData: toCopiedBuffer(parameters.associatedData),
  };
  return originalArgon2Sync(algorithm, clonedParams);
}

function argon2(algorithm, parameters, callback) {
  validateArgon2Args(algorithm, parameters, true, callback);
  const clonedParams = {
    ...parameters,
    message: toCopiedBuffer(parameters.message),
    nonce: toCopiedBuffer(parameters.nonce),
    secret: toCopiedBuffer(parameters.secret),
    associatedData: toCopiedBuffer(parameters.associatedData),
  };
  originalArgon2Async(algorithm, clonedParams)
    .then(
      (result) => { callback(null, result); },
      (err) => { callback(err); }
    );
}

Object.defineProperty(argon2, "length", { value: 3, configurable: true });
Object.defineProperty(argon2Sync, "length", { value: 2, configurable: true });

nativeBinding.argon2Sync = argon2Sync;
nativeBinding.argon2 = argon2;
module.exports.argon2Sync = argon2Sync;
module.exports.argon2 = argon2;

// Add static methods to Certificate class for compatibility
if (nativeBinding.Certificate) {
  const CertClass = nativeBinding.Certificate;
  CertClass.exportChallenge = function(spkac) {
    return new CertClass().exportChallenge(spkac);
  };
  CertClass.exportPublicKey = function(spkac) {
    return new CertClass().exportPublicKey(spkac);
  };
  CertClass.verifySpkac = function(spkac) {
    return new CertClass().verifySpkac(spkac);
  };
}

// Wrap RSA functions for code validation
function wrapRsaKeyOp(fn) {
  return function(key, buffer) {
    if (key && typeof key === 'object' && !ArrayBuffer.isView(key) && !Array.isArray(key)) {
      if (key.padding === 1 && key.oaepHash !== undefined) {
        throw createArgon2Error(TypeError, 'ERR_INVALID_ARG_VALUE', "oaepHash cannot be specified with RSA_PKCS1_PADDING");
      }
      if (key.oaepHash !== undefined && typeof key.oaepHash !== 'string') {
        throw createArgon2Error(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "key.oaepHash" property must be of type string.');
      }
      if (key.oaepLabel !== undefined && !isBufferSource(key.oaepLabel)) {
        throw createArgon2Error(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "key.oaepLabel" property must be of type string or an instance of ArrayBuffer, Buffer, TypedArray, or DataView.');
      }
    }
    try {
      return fn(key, buffer);
    } catch(err) {
      if (err && err.message && err.message.includes("ERR_OSSL_EVP_INVALID_DIGEST")) {
        err.code = "ERR_OSSL_EVP_INVALID_DIGEST";
      } else if (err && err.message && err.message.includes("ERR_INVALID_ARG_VALUE")) {
        err.code = "ERR_INVALID_ARG_VALUE";
      }
      throw err;
    }
  };
}

const origPublicEncrypt = nativeBinding.publicEncrypt;
const origPrivateDecrypt = nativeBinding.privateDecrypt;
const origPrivateEncrypt = nativeBinding.privateEncrypt;
const origPublicDecrypt = nativeBinding.publicDecrypt;

const wrappedPublicEncrypt = wrapRsaKeyOp(origPublicEncrypt);
const wrappedPrivateDecrypt = wrapRsaKeyOp(origPrivateDecrypt);
const wrappedPrivateEncrypt = wrapRsaKeyOp(origPrivateEncrypt);
const wrappedPublicDecrypt = wrapRsaKeyOp(origPublicDecrypt);

nativeBinding.publicEncrypt = wrappedPublicEncrypt;
nativeBinding.privateDecrypt = wrappedPrivateDecrypt;
nativeBinding.privateEncrypt = wrappedPrivateEncrypt;
nativeBinding.publicDecrypt = wrappedPublicDecrypt;

module.exports.publicEncrypt = wrappedPublicEncrypt;
module.exports.privateDecrypt = wrappedPrivateDecrypt;
module.exports.privateEncrypt = wrappedPrivateEncrypt;
module.exports.publicDecrypt = wrappedPublicDecrypt;
`

content += patch
writeFileSync(jsPath, content)
