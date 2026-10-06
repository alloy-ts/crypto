# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API signatures, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `rsa`, `sha1`, `sha2`, and `argon2-rust`).

---

## API Compatibility Table

| Standard `node:crypto` API | Our Implementation Signature | Compatibility Status | Implementation Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.argon2(algorithm, parameters, callback)` | `argon2(algorithm: string, parameters: Argon2Parameters)` | **Partial** | Asynchronous Argon2d/i/id key derivation returning `Buffer`. Differs in signature (returns Promise instead of taking callback). |
| `crypto.argon2Sync(algorithm, parameters)` | `argon2Sync(algorithm: string, parameters: Argon2Parameters)` | **Compatible** (Node v24.7.0+ spec) | Synchronous Argon2d/i/id key derivation returning `Buffer`. |
| `crypto.createHash(algorithm)` | `createHash(algorithm: string): Hash` | **Partial** | Standalone object (`sha1`, `sha256`, `sha384`, `sha512`, `sha512-256`) via `ring`. Does not extend `stream.Transform`. |
| `crypto.hash(algorithm, data, outputEncoding)` | `hash(algorithm, data, outputEncoding?): string \| Buffer` | **Compatible** | One-shot digest calculation utility. |
| `crypto.getHashes()` | `getHashes(): string[]` | **Compatible** | Returns array of supported digest algorithm names (`['sha1', 'sha256', 'sha384', 'sha512', 'sha512-256']`). |
| `crypto.createHmac(algorithm, key, encoding)` | `createHmac(algorithm, key, encoding?): Hmac` | **Partial** | HMAC creation via `ring::hmac`. Does not extend `stream.Transform`. |
| `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)` | `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>` | **Partial** | Asynchronous PBKDF2 returning `Promise<Buffer>` instead of accepting a Node-style callback. |
| `crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)` | `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.createCipheriv(algorithm, key, iv[, options])` | *Not Implemented* | **Missing** | Standard AES/ChaCha stream and block ciphers are missing. (Custom `encryptAead` function provided instead). |
| `crypto.createDecipheriv(algorithm, key, iv[, options])` | *Not Implemented* | **Missing** | Standard AES/ChaCha decipher stream and block ciphers are missing. (Custom `decryptAead` function provided instead). |
| `crypto.createECDH(curveName)` | `createECDH(curveName: string): ECDH` | **Partial** | Elliptic Curve Diffie-Hellman exchange (`P-256`, `P-384`, `X25519`). |
| `crypto.createDiffieHellman(groupOrPrime)` | `createDiffieHellman(groupOrPrime)` | **Partial** | Diffie-Hellman key exchange helper wrapper. |
| `crypto.createDiffieHellmanGroup(name)` | `createDiffieHellmanGroup(name)` | **Partial** | Diffie-Hellman predefined modp group wrapper. |
| `crypto.generateKeyPair(type, options, callback)` | `generateKeyPair(typeName: string): Promise<KeyPairResult>` | **Partial** | Asynchronous RSA and Ed25519 key pair generation. Signature returns Promise instead of taking callback. |
| `crypto.generateKeyPairSync(type, options)` | `generateKeyPairSync(typeName: string)` | **Partial** | Synchronous RSA and Ed25519 key pair generation. Options parameter is not fully supported. |
| `crypto.publicEncrypt(key, buffer)` | `publicEncrypt(keyArg, buffer)` | **Compatible** | RSA public key encryption with PKCS1v15, OAEP (SHA1/SHA256/384/512), and NoPadding modes. |
| `crypto.privateDecrypt(privateKey, buffer)` | `privateDecrypt(keyArg, buffer)` | **Compatible** | RSA private key decryption with PKCS1v15, OAEP, and NoPadding modes. |
| `crypto.privateEncrypt(privateKey, buffer)` | `privateEncrypt(keyArg, buffer)` | **Compatible** | RSA private key encryption. |
| `crypto.publicDecrypt(key, buffer)` | `publicDecrypt(keyArg, buffer)` | **Compatible** | RSA public key decryption. |
| `crypto.randomBytes(size, callback)` | `randomBytes(size: number): Buffer` / `randomBytesAsync(size): Promise<Buffer>` | **Partial** | Synchronous `randomBytes` returns `Buffer`. Async version is exported as `randomBytesAsync` (Promise) instead of accepting callback. |
| `crypto.randomFill(buffer, offset, size, callback)` | `randomFill(buffer, offset?, size?): Promise<Uint8Array>` | **Partial** | Asynchronous random buffer fill returns `Promise` instead of invoking callback. |
| `crypto.randomFillSync(buffer, offset, size)` | `randomFillSync(buffer, offset?, size?): Uint8Array` | **Compatible** | Synchronous random buffer fill via `ring::rand`. |
| `crypto.randomInt(min, max)` | `randomInt(min: number, max?: number): number` | **Partial** | Unbiased random integer generation. Synchronous only; callback-style async overload missing. |
| `crypto.randomUUID()` | `randomUUID(): string` | **Compatible** | RFC 4122 version 4 UUID generator. |
| `crypto.randomUUIDv7()` | `randomUUIDv7(): string` | **Compatible** (Node v26.1.0+ spec) | RFC 9562 version 7 time-ordered UUID generator. |
| `crypto.scrypt(password, salt, keylen[, options], callback)` | *Not Implemented* | **Missing** | Scrypt KDF function is missing. |
| `crypto.scryptSync(password, salt, keylen[, options])` | *Not Implemented* | **Missing** | Synchronous Scrypt KDF function is missing. |
| `crypto.hkdf(digest, ikm, salt, info, keylen, callback)` | *Not Implemented* | **Missing** | HKDF key derivation function is missing. |
| `crypto.hkdfSync(digest, ikm, salt, info, keylen)` | *Not Implemented* | **Missing** | Synchronous HKDF key derivation function is missing. |
| `crypto.timingSafeEqual(a, b)` | *Not Implemented* | **Missing** | Constant-time buffer comparison function is missing. |
| `crypto.createSign(algorithm)` / `crypto.sign(...)` | `createSign(algorithm) / sign(algorithm, data, key)` | **Partial** | Digital signature generation (Ed25519, ECDSA P-256). `Sign` object does not extend `stream.Writable`. |
| `crypto.createVerify(algorithm)` / `crypto.verify(...)` | `createVerify(algorithm) / verify(algorithm, data, key, sig)` | **Partial** | Digital signature verification. `Verify` object does not extend `stream.Writable`. |
| `crypto.createSecretKey` / `createPublicKey` / `createPrivateKey` | `createSecretKey / createPublicKey / createPrivateKey` | **Partial** | Key object factory functions returning `KeyObject`. Missing string/PEM parsing for `createPublicKey`/`createPrivateKey`. |
| `Class: KeyObject` | `KeyObject` | **Partial** | Key representation for secret, public, and private keys. Missing `.export()`, `.equals()`, `.asymmetricKeyDetails`, `.toCryptoKey()`, `KeyObject.from()`. |
| `Class: X509Certificate` | `X509Certificate` | **Partial** | X.509 certificate parsing (`subject`, `issuer`, `raw`). Missing checking methods (`checkHost`, `checkEmail`, `checkIP`, `checkIssued`, `checkPrivateKey`, `verify`, fingerprints). |
| `Class: Certificate` | *Not Implemented* | **Missing** | SPKAC certificate class (`exportChallenge`, `exportPublicKey`, `verifySpkac`) is missing. |
| `crypto.checkPrime` / `generatePrime` | *Not Implemented* | **Missing** | Prime generation and checking utilities are missing. |
| `crypto.parsePKCS12` | *Not Implemented* | **Missing** | PKCS#12 bundle parser is missing. |
| `crypto.getCurves()` | *Not Implemented* | **Missing** | Curve enumeration function is missing. |
| `crypto.getMacs()` | *Not Implemented* | **Missing** | MAC algorithm enumeration function is missing. |
| `crypto.constants` | *Not Implemented* | **Missing** | OpenSSL and Node.js crypto constants object is missing. |
| `crypto.webcrypto` / `crypto.subtle` | *Not Implemented* | **Missing** | Web Crypto API standard implementations (`subtle`, `getRandomValues`) are missing. |
| AEAD Encryption / Decryption | `encryptAead` / `decryptAead` | **Extension** | High-performance AES-GCM and ChaCha20-Poly1305 AEAD routines. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension** | Exposes `rustls` with configurable backends (`ring`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`). |

---

## Audit: Missing Features & Differences Against node:crypto

Below is a detailed breakdown of missing features, API signature differences, and architectural deviations between standard `node:crypto` and `@lib/crypto` (`src/*`):

### 1. Missing Core Crypto APIs
- **Symmetric Ciphers (`Cipheriv` & `Decipheriv`)**:
  - Node.js provides `crypto.createCipheriv(algorithm, key, iv[, options])`, `crypto.createDecipheriv(...)`, and the classes `Cipheriv` and `Decipheriv` for symmetric encryption/decryption (AES-128/192/256 in CBC, CTR, GCM, CCM, OCB, XTS modes, etc.).
  - Current implementation only provides standalone helper functions `encryptAead` and `decryptAead`.
- **Key Derivation Functions (Scrypt & HKDF)**:
  - `crypto.scrypt(password, salt, keylen[, options], callback)` and `crypto.scryptSync(...)` are missing.
  - `crypto.hkdf(digest, ikm, salt, info, keylen, callback)` and `crypto.hkdfSync(...)` are missing.
- **Timing Safe Comparison**:
  - `crypto.timingSafeEqual(a, b)` for constant-time comparison of buffers/typed arrays is missing.
- **Certificate Handling (SPKAC & Advanced X509)**:
  - `crypto.Certificate` class (`exportChallenge`, `exportPublicKey`, `verifySpkac`) for HTML5 SPKAC requests is missing.
  - `X509Certificate` class in `src/key_object.rs` lacks fingerprint properties (`fingerprint`, `fingerprint256`, `fingerprint512`), verification (`verify(publicKey)`), and check methods (`checkHost`, `checkEmail`, `checkIP`, `checkIssued`, `checkPrivateKey`).
- **Primes & PKCS12**:
  - `crypto.checkPrime`, `crypto.checkPrimeSync`, `crypto.generatePrime`, `crypto.generatePrimeSync` are missing.
  - `crypto.parsePKCS12(bundle[, options])` for `.p12`/`.pfx` bundles is missing.
- **WebCrypto & Constants**:
  - `crypto.webcrypto` and `crypto.subtle` (W3C Web Crypto API) are missing.
  - `crypto.constants` (exporting OpenSSL flags like `RSA_PKCS1_PADDING`, `SSL_OP_*`) is missing.
  - `crypto.getCurves()`, `crypto.getMacs()`, `crypto.setEngine()`, `crypto.getFips()`, `crypto.setFips()`, `crypto.secureHeapUsed()` are missing.

### 2. Stream Class Hierarchy Differences
- **Node.js `node:crypto` Architecture**: `Hash`, `Hmac`, `Cipheriv`, and `Decipheriv` inherit from `stream.Transform` (readable and writable streams). `Sign` and `Verify` inherit from `stream.Writable`. This allows piping (`readStream.pipe(cipher).pipe(writeStream)`).
- **Current Implementation**: Classes in `src/*` (`Hash`, `Hmac`, `Sign`, `Verify`) are standalone NAPI classes exposed directly from Rust. They implement `.update()` and `.digest()`/`.sign()`/`.verify()` methods, but do NOT extend Node.js Stream classes and cannot be used in Node stream pipelines.

### 3. Callback vs Promise / Sync Signature Mismatches
- **Node.js `node:crypto` Specification**: Asynchronous functions accept Node-style error-first callbacks `(err, result) => void` as their final argument (e.g. `randomBytes(size, cb)`, `randomFill(buf, cb)`, `pbkdf2(..., cb)`, `generateKeyPair(type, options, cb)`).
- **Current Implementation**:
  - `randomBytes`: Synchronous version takes `size` and returns `Buffer`. Async version is exported as `randomBytesAsync` returning a `Promise`. Callback parameter is not supported.
  - `randomFill`: Asynchronous version returns a `Promise<Uint8Array>` rather than accepting `(err, buf)` callback.
  - `pbkdf2`: Returns `Promise<Buffer>` directly rather than accepting a callback function.
  - `generateKeyPair`: Returns `Promise<KeyPairResult>` rather than invoking a callback.

### 4. Partial Class & Object Implementations
- **`KeyObject`**:
  - Missing `.export([options])` method to export keys to PEM, DER, JWK, or raw formats.
  - Missing `.equals(otherKeyObject)` method for key object comparison.
  - Missing `.asymmetricKeyDetails`, `.asymmetricKeyType`, `.toCryptoKey()`, and static `KeyObject.from(cryptoKey)`.
  - `createPublicKey` and `createPrivateKey` currently expect `Uint8Array` raw key material and do not support PEM string parsing or object options.

### 5. Algorithm & Backend Scope
- **Hash Algorithms**: `src/crypto_hasher.rs` supports `sha1`, `sha256`, `sha384`, `sha512`, `sha512-256` via `ring`. Standard `node:crypto` supports broader OpenSSL digest algorithms (e.g., MD5, SHA3-256/512, BLAKE2b/s, RIPEMD160).
- **Key Exchanges & Curves**: `src/ecdh.rs` supports `P-256`, `P-384`, `X25519`. Standard `node:crypto` supports `secp256k1`, `P-521`, and Diffie-Hellman MODP groups (`modp14`, etc.).

---

## Module Reference

### 1. Argon2 (`src/argon2.rs`)
- `argon2(algorithm: string, parameters: Argon2Parameters): Promise<Buffer>`
- `argon2Sync(algorithm: string, parameters: Argon2Parameters): Buffer`

### 2. Hasher (`src/crypto_hasher.rs`)
- `createHash(algorithm: string): Hash`
- `hash(algorithm: string, data: string | Uint8Array, outputEncoding?: string): string | Buffer`
- `getHashes(): string[]`

### 3. HMAC (`src/hmac.rs`)
- `createHmac(algorithm: string, key: string | Uint8Array, encoding?: string): Hmac`
- `new Hmac(algorithm, key, encoding)`
- `Hmac.prototype.update(data, inputEncoding)`
- `Hmac.prototype.digest(outputEncoding)`

### 4. PBKDF2 (`src/pbkdf2.rs`)
- `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>`
- `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer`

### 5. ECDH (`src/ecdh.rs`)
- `createECDH(curveName: string): ECDH`
- `createDiffieHellman(groupOrPrime: string | number): ECDH`
- `createDiffieHellmanGroup(name: string): ECDH`

### 6. RSA (`src/rsa.rs`)
- `generateKeyPair(typeName: string): Promise<KeyPairResult>`
- `generateKeyPairSync(typeName: string): KeyPairResult`
- `publicEncrypt(keyArg, buffer): Buffer`
- `privateDecrypt(keyArg, buffer): Buffer`
- `privateEncrypt(keyArg, buffer): Buffer`
- `publicDecrypt(keyArg, buffer): Buffer`

### 7. Random (`src/random.rs`)
- `randomBytes(size: number): Buffer`
- `randomBytesAsync(size: number): Promise<Buffer>`
- `randomFill(buffer: Uint8Array, offset?: number, size?: number): Promise<Uint8Array>`
- `randomFillSync(buffer: Uint8Array, offset?: number, size?: number): Uint8Array`
- `randomInt(min: number, max?: number): number`
- `randomUUID(): string`
- `randomUUIDv7(): string`

### 8. Sign / Verify / KeyObject (`src/signature.rs`, `src/agreement.rs`, `src/key_object.rs`)
- `createSign(algorithm: string): Sign`
- `sign(algorithm, data, privateKey): Buffer`
- `createVerify(algorithm: string): Verify`
- `verify(algorithm, data, publicKey, signature): boolean`
- `createSecretKey(key: Uint8Array): KeyObject`
- `createPublicKey(key: Uint8Array): KeyObject`
- `createPrivateKey(key: Uint8Array): KeyObject`
- `new X509Certificate(buffer: Uint8Array)`

### 9. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
