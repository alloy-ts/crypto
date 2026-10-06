# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `rsa`, and `argon2-rust`).

---

## API Compatibility Table

| `node:crypto` Standard API | Our Implementation | Compatibility Status | Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.createHash(algorithm)` | `createHash(algorithm)` / `Hash` class | **Compatible** | Powered by `ring` digest routines (SHA1, SHA256, SHA384, SHA512, SHA512-256). |
| `crypto.hash(algorithm, data, outputEncoding)` | `hash(...)` | **Compatible** | One-shot hashing utility. |
| `crypto.getHashes()` | `getHashes()` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac(algorithm, key)` | `createHmac(...)` / `Hmac` class | **Compatible** | Powered by `ring::hmac` supporting `update` and `digest` with encoding options (`hex`, `base64`, `binary`, `latin1`). |
| `crypto.pbkdf2(...)` | `pbkdf2(...)` | **Compatible** | Asynchronous PBKDF2 key derivation using NAPI async task & `ring::pbkdf2`. |
| `crypto.pbkdf2Sync(...)` | `pbkdf2Sync(...)` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.argon2(...)` / `crypto.argon2Sync(...)` | `argon2(...)` / `argon2Sync(...)` | **Compatible** | Argon2 key derivation conforming to node:crypto and `@node-rs/argon2` specs via `argon2-rust`. |
| Argon2 Hashing & Verification | `argon2Hash`, `argon2HashSync`, `argon2Verify`, `argon2VerifySync`, `argon2ParseOptions` | **Compatible** | PHC format password hashing and verification with customizable memory/time cost/parallelism. |
| `crypto.randomBytes(...)` | `randomBytes(...)` | **Compatible** | Cryptographically secure pseudo-random bytes generated via `ring::rand`. |
| `crypto.randomFillSync(...)` | `randomFillSync(...)` | **Compatible** | Synchronously fills typed array or buffer with random bytes. |
| `crypto.randomInt(...)` | `randomInt(...)` | **Compatible** | Generates unbiased random integers within specified range. |
| `crypto.randomUUID(...)` | `randomUUID(...)` | **Compatible** | RFC 4122 v4 UUID generator. |
| `crypto.publicEncrypt` / `privateDecrypt` | `publicEncrypt` / `privateDecrypt` | **Compatible** | RSA OAEP/PKCS#1 v1.5/NoPadding encryption and decryption using `rsa` crate. |
| `crypto.privateEncrypt` / `publicDecrypt` | `privateEncrypt` / `publicDecrypt` | **Compatible** | RSA public key decryption and private key encryption. |
| `crypto.generateKeyPair` / `generateKeyPairSync` | `generateKeyPair` / `generateKeyPairSync` | **Compatible** | Keypair generation for RSA, Ed25519, and P-256. |
| `crypto.createECDH` / `createDiffieHellman` | `ECDH` class / `createECDH` | **Compatible** | ECDH key exchange powered by `ring::agreement` (P-256, P-384, X25519). |
| `crypto.createSign` / `crypto.sign` | `Sign` class / `createSign` / `sign` | **Compatible** | Digital signatures with Ed25519 and ECDSA P-256. |
| `crypto.createVerify` / `crypto.verify` | `Verify` class / `createVerify` / `verify` | **Compatible** | Signature verification with Ed25519 and ECDSA P-256. |
| `crypto.createPublicKey` / `createPrivateKey` / `createSecretKey` | `KeyObject` class / factory functions | **Compatible** | Key object management for public, private, and secret keys. |
| `crypto.X509Certificate` | `X509Certificate` class | **Compatible** | X.509 certificate parser powered by `x509-parser`. |
| AEAD Encryption / Decryption | `encrypt_aead` / `decrypt_aead` | **Compatible** | AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 via `ring::aead`. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension / Native TLS** | Exposes `rustls` with configurable backends: `ring` (default), OpenSSL (`rustls-openssl`), BoringSSL (`boring-rustls-provider`), and MbedTLS (`rustls-mbedcrypto-provider`). |

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
- `argon2(algorithm, parameters): Promise<Buffer>`
- `argon2Sync(algorithm, parameters): Buffer`
- `argon2Hash(password, options?, abortSignal?): Promise<string>`
- `argon2HashSync(password, options?): string`
- `argon2HashRaw(password, options?): Promise<Buffer>`
- `argon2HashRawSync(password, options?): Buffer`
- `argon2Verify(hashed, password, options?): Promise<boolean>`
- `argon2VerifySync(hashed, password, options?): boolean`
- `argon2ParseOptions(hashed): ParsedHashOptions`

### 5. Random (`src/rand.rs`)
- `randomBytes(size: number): Buffer`
- `randomFillSync(buffer, offset?, size?): Uint8Array`
- `randomInt(min: number, max?: number): number`
- `randomUUID(): string`

### 6. RSA (`src/rsa.rs`)
- `publicEncrypt(key, buffer): Buffer`
- `privateDecrypt(key, buffer): Buffer`
- `privateEncrypt(key, buffer): Buffer`
- `publicDecrypt(key, buffer): Buffer`
- `generateKeyPair(type): Promise<KeyPairResult>`
- `generateKeyPairSync(type): KeyPairResult`

### 7. ECDH (`src/ecdh.rs`)
- `new ECDH(curveName: string)`
- `createECDH(curveName: string): ECDH`
- `createDiffieHellman(groupOrPrime): ECDH`
- `createDiffieHellmanGroup(name): ECDH`

### 8. Sign & Verify (`src/signature.rs` & `src/agreement.rs`)
- `createSign(algorithm): Sign`
- `sign(algorithm, data, privateKey): Buffer`
- `createVerify(algorithm): Verify`
- `verify(algorithm, data, publicKey, signature): boolean`

### 9. KeyObject & X509 (`src/key_object.rs`)
- `createSecretKey(key): KeyObject`
- `createPublicKey(key): KeyObject`
- `createPrivateKey(key): KeyObject`
- `new X509Certificate(buffer)`

### 10. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
- `TLS.prototype.providerName: string`
- `TLS.prototype.isSupported(): boolean`
