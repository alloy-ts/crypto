# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, and `argon2-rust`).

---

## API Compatibility Table

| `node:crypto` Standard API | Our Implementation | Compatibility Status | Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.createHash(algorithm)` | `createHash(algorithm)` / `Hash` class | **Compatible** | Powered by `ring` digest routines (SHA1, SHA256, SHA384, SHA512, SHA512-256). |
| `crypto.hash(algorithm, data, outputEncoding)` | `hash(...)` | **Compatible** | One-shot hashing utility. |
| `crypto.getHashes()` | `getHashes()` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac(algorithm, key)` | `createHmac(...)` / `Hmac` class | **Compatible** | Powered by `ring::hmac` supporting `update` and `digest` with encoding options (`hex`, `base64`, `binary`). |
| `crypto.pbkdf2(...)` | `pbkdf2(...)` | **Compatible** | Asynchronous PBKDF2 key derivation using NAPI async task & `ring::pbkdf2`. |
| `crypto.pbkdf2Sync(...)` | `pbkdf2Sync(...)` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| Argon2 Hashing & Verification | `argon2Hash`, `argon2HashSync`, `argon2Verify`, `argon2VerifySync`, `argon2ParseOptions` | **Extension / High-Perf** | Follows `@node-rs/argon2` specs using `argon2-rust` (PHC format, customizable memory/time cost/parallelism). |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension / Native TLS** | Exposes `rustls` with configurable backends: `ring` (default), OpenSSL (`rustls-openssl`), BoringSSL (`boring-rustls-provider`), and MbedTLS (`rustls-mbedcrypto-provider`). |
| `crypto.createCipheriv` / `createDecipheriv` | *Planned / Out of Scope* | Not Implemented | Symmetric ciphers AES-GCM / ChaCha20-Poly1305 can be added in future iterations. |
| `crypto.generateKeyPair` / `Sign` / `Verify` | *Planned / Out of Scope* | Not Implemented | Asymmetric RSA/ECDSA signing & key generation. |
| `crypto.randomBytes` / `randomUUID` | *Planned / Out of Scope* | Not Implemented | Delegates to Node's built-in or `ring::rand`. |

---

## Module Reference

### 1. Hasher (`src/crypto_hasher.rs`)
- `createHash(algorithm: string): Hash`
- `hash(algorithm: string, data: string | Uint8Array, outputEncoding?: string): string | Buffer`
- `getHashes(): string[]`

### 2. HMAC (`src/hmac.rs`)
- `createHmac(algorithm: string, key: string | Uint8Array, encoding?: string): Hmac`
- `new Hmac(algorithm, key, encoding)`
- `Hmac.prototype.update(data, inputEncoding)`
- `Hmac.prototype.digest(outputEncoding)`

### 3. PBKDF2 (`src/pbkdf2.rs`)
- `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>`
- `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer`

### 4. Argon2 (`src/argon2.rs`)
- `argon2Hash(password, options?, abortSignal?): Promise<string>`
- `argon2HashSync(password, options?): string`
- `argon2HashRaw(password, options?): Promise<Buffer>`
- `argon2HashRawSync(password, options?): Buffer`
- `argon2Verify(hashed, password, options?): Promise<boolean>`
- `argon2VerifySync(hashed, password, options?): boolean`
- `argon2ParseOptions(hashed): ParsedHashOptions`

### 5. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
- `TLS.prototype.providerName: string`
- `TLS.prototype.isSupported(): boolean`
