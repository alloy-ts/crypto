# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `rsa`, and `argon2-rust`).

---

## API Compatibility Table

| `node:crypto` Standard API | Our Implementation | Compatibility Status | Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.argon2(algorithm, parameters, callback)` | `argon2(algorithm, parameters)` | **Compatible** | Asynchronous Argon2 derivation returning `Promise<Buffer>` (or callback handling via JS wrapper). Supports `argon2d`, `argon2i`, `argon2id`. |
| `crypto.argon2Sync(algorithm, parameters)` | `argon2Sync(algorithm, parameters)` | **Compatible** | Synchronous Argon2 derivation returning `Buffer`. Supports `argon2d`, `argon2i`, `argon2id`. |
| `crypto.createHash(algorithm[, options])` | `createHash(algorithm)` / `Hash` class | **Compatible** | Powered by `ring` digest routines (`sha256`, `sha384`, `sha512`, `sha1`). Implements `update` and `digest`. |
| `crypto.hash(algorithm, data[, options])` | `hash(algorithm, data, outputEncoding)` | **Compatible** | One-shot hashing utility returning `string` or `Buffer`. |
| `crypto.getHashes()` | `getHashes()` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac(algorithm, key[, options])` | `createHmac(algorithm, key, encoding)` / `Hmac` class | **Compatible** | Powered by `ring::hmac` supporting `update` and `digest` with encoding options (`hex`, `base64`, `binary`). |
| `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)` | `pbkdf2(password, salt, iterations, keylen, digest)` | **Compatible** | Asynchronous PBKDF2 key derivation using NAPI async task & `ring::pbkdf2`. |
| `crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)` | `pbkdf2Sync(password, salt, iterations, keylen, digest)` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.generateKeyPair(type, options, callback)` | `generateKeyPair(typeName)` | **Compatible** | Asynchronous key pair generation for `rsa`, `ed25519`, `p256`. |
| `crypto.generateKeyPairSync(type, options)` | `generateKeyPairSync(typeName)` | **Compatible** | Synchronous key pair generation for `rsa`, `ed25519`, `p256`. |
| `crypto.publicEncrypt(key, buffer)` | `publicEncrypt(keyArg, buffer)` | **Compatible** | RSA public key encryption supporting PEM, DER, and KeyOptions. |
| `crypto.privateDecrypt(privateKey, buffer)` | `privateDecrypt(keyArg, buffer)` | **Compatible** | RSA private key decryption supporting PEM, DER, and KeyOptions. |
| `crypto.privateEncrypt(privateKey, buffer)` | `privateEncrypt(keyArg, buffer)` | **Compatible** | RSA private key encryption supporting PEM, DER, and KeyOptions. |
| `crypto.publicDecrypt(key, buffer)` | `publicDecrypt(keyArg, buffer)` | **Compatible** | RSA public key decryption supporting PEM, DER, and KeyOptions. |
| `crypto.createSign(algorithm[, options])` | `createSign(algorithm)` / `Sign` class | **Compatible** | Stream/class interface for creating digital signatures. |
| `crypto.sign(algorithm, data, key[, callback])` | `sign(algorithm, data, privateKey)` | **Compatible** | One-shot digital signature calculation. |
| `crypto.createVerify(algorithm[, options])` | `createVerify(algorithm)` / `Verify` class | **Compatible** | Stream/class interface for signature verification. |
| `crypto.verify(algorithm, data, key, signature[, callback])` | `verify(algorithm, data, publicKey, signature)` | **Compatible** | One-shot signature verification returning `boolean`. |
| `crypto.createECDH(curveName)` | `createECDH(curveName)` / `ECDH` class | **Compatible** | Elliptic Curve Diffie-Hellman key exchange supporting `p256` and secp curves. |
| `crypto.createSecretKey(key[, encoding])` | `createSecretKey(key)` / `KeyObject` | **Compatible** | Creates symmetric secret `KeyObject`. |
| `crypto.createPublicKey(key)` | `createPublicKey(key)` / `KeyObject` | **Compatible** | Creates asymmetric public `KeyObject`. |
| `crypto.createPrivateKey(key)` | `createPrivateKey(key)` / `KeyObject` | **Compatible** | Creates asymmetric private `KeyObject`. |
| `crypto.randomBytes(size[, callback])` | `randomBytes(size)` | **Compatible** | Generates cryptographically secure random bytes as `Buffer`. |
| `crypto.randomFillSync(buffer[, offset][, size])` | `randomFillSync(buffer, offset, size)` | **Compatible** | Fills buffer with random data synchronously. |
| `crypto.randomInt([min, ]max[, callback])` | `randomInt(min, max)` | **Compatible** | Returns a random integer in the range `[min, max)`. |
| `crypto.randomUUID([options])` | `randomUUID()` | **Compatible** | Generates an RFC 4122 version 4 UUID string. |
| Argon2 PHC Hashing & Verification | `argon2Hash`, `argon2HashSync`, `argon2Verify`, `argon2VerifySync`, `argon2ParseOptions` | **Extension / High-Perf** | Follows PHC string formatting using `argon2-rust` (PHC format, customizable memory/time cost/parallelism). |
| AEAD Encryption / Decryption | `encryptAead`, `decryptAead` | **Extension / Native AEAD** | AES-GCM and AEAD cipher operations with optional AAD. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension / Native TLS** | Exposes `rustls` with configurable backends: `ring` (default), OpenSSL (`rustls-openssl`), BoringSSL (`boring-rustls-provider`), and MbedTLS (`rustls-mbedcrypto-provider`). |

---

## Module Reference

### 1. Hasher (`src/crypto_hasher.rs`)
- `createHash(algorithm: string): Hash`
- `hash(algorithm: string, data: string | Uint8Array, outputEncoding?: string | null): string | Buffer`
- `getHashes(): string[]`

### 2. HMAC (`src/hmac.rs`)
- `createHmac(algorithm: string, key: string | Uint8Array, encoding?: string | null): Hmac`
- `new Hmac(algorithm, key, encoding?)`
- `Hmac.prototype.update(data: string | Uint8Array, inputEncoding?: string | null): this`
- `Hmac.prototype.digest(outputEncoding?: string | null): string | Buffer`

### 3. PBKDF2 (`src/pbkdf2.rs`)
- `pbkdf2(password: string | Uint8Array, salt: string | Uint8Array, iterations: number, keylen: number, digest: string, abortSignal?: AbortSignal | null): Promise<Buffer>`
- `pbkdf2Sync(password: string | Uint8Array, salt: string | Uint8Array, iterations: number, keylen: number, digest: string): Buffer`

### 4. Argon2 (`src/argon2.rs`)
- `argon2(algorithm: string, parameters: Argon2Parameters): Promise<Buffer>`
- `argon2Sync(algorithm: string, parameters: Argon2Parameters): Buffer`
- `argon2Hash(password: string | Uint8Array, options?: Options | null, abortSignal?: AbortSignal | null): Promise<string>`
- `argon2HashSync(password: string | Uint8Array, options?: Options | null): string`
- `argon2HashRaw(password: string | Uint8Array, options?: Options | null, abortSignal?: AbortSignal | null): Promise<Buffer>`
- `argon2HashRawSync(password: string | Uint8Array, options?: Options | null): Buffer`
- `argon2Verify(hashed: string | Uint8Array, password: string | Uint8Array, options?: Options | null, abortSignal?: AbortSignal | null): Promise<boolean>`
- `argon2VerifySync(hashed: string | Uint8Array, password: string | Uint8Array, options?: Options | null): boolean`
- `argon2ParseOptions(hashed: string | Uint8Array): ParsedHashOptions`

### 5. RSA & Key Pair (`src/rsa.rs`)
- `generateKeyPair(typeName: string): Promise<KeyPairResult>`
- `generateKeyPairSync(typeName: string): KeyPairResult`
- `publicEncrypt(keyArg: string | Uint8Array | KeyOptions, buffer: Uint8Array): Buffer`
- `privateDecrypt(keyArg: string | Uint8Array | KeyOptions, buffer: Uint8Array): Buffer`
- `privateEncrypt(keyArg: string | Uint8Array | KeyOptions, buffer: Uint8Array): Buffer`
- `publicDecrypt(keyArg: string | Uint8Array | KeyOptions, buffer: Uint8Array): Buffer`

### 6. Sign & Verify (`src/signature.rs`, `src/agreement.rs`)
- `createSign(algorithm: string): Sign`
- `sign(algorithm: string, data: string | Uint8Array, privateKey: Uint8Array): Buffer`
- `createVerify(algorithm: string): Verify`
- `verify(algorithm: string, data: string | Uint8Array, publicKey: Uint8Array, signature: Uint8Array): boolean`

### 7. ECDH (`src/ecdh.rs`)
- `createECDH(curveName: string): ECDH`
- `new ECDH(curveName: string)`
- `ECDH.prototype.getPublicKey(): Buffer`
- `ECDH.prototype.computeSecret(peerPublicKey: Uint8Array): Buffer`

### 8. KeyObject (`src/key_object.rs`)
- `createSecretKey(key: Uint8Array): KeyObject`
- `createPublicKey(key: Uint8Array): KeyObject`
- `createPrivateKey(key: Uint8Array): KeyObject`
- `KeyObject.prototype.keyType: KeyType`
- `KeyObject.prototype.keyTypeName: string`
- `KeyObject.prototype.export(): Buffer`

### 9. Random Utilities (`src/rand.rs`)
- `randomBytes(size: number): Buffer`
- `randomFillSync(buffer: Uint8Array, offset?: number | null, size?: number | null): Uint8Array`
- `randomInt(min: number, max?: number | null): number`
- `randomUUID(): string`

### 10. AEAD (`src/aead.rs`)
- `encryptAead(algorithm: string, key: Uint8Array, nonceBytes: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array | null): Buffer`
- `decryptAead(algorithm: string, key: Uint8Array, nonceBytes: Uint8Array, ciphertextAndTag: Uint8Array, aad?: Uint8Array | null): Buffer`

### 11. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType | null)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
- `TLS.prototype.providerName: string`
- `TLS.prototype.isSupported(): boolean`
