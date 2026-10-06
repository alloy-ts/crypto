# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` (Cargo crate `lib_crypto_native`) provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `argon2-rust`, `rsa`, `sha2`, `sha1`, and `x509-parser`).

---

## API Compatibility Table

| `node:crypto` Standard API | Our Implementation | Compatibility Status | Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.argon2(algorithm, parameters, callback)` | `argon2(algorithm, parameters)` | **Compatible (v24.7.0)** | Asynchronous Argon2 key derivation (supports `argon2d`, `argon2i`, `argon2id`). |
| `crypto.argon2Sync(algorithm, parameters)` | `argon2Sync(algorithm, parameters)` | **Compatible (v24.7.0)** | Synchronous Argon2 key derivation returning derived key `Buffer`. |
| `crypto.createHash(algorithm, options)` | `createHash(algorithm)` / `Hash` class | **Compatible** | Powered by `ring` digest routines (SHA1, SHA256, SHA384, SHA512, SHA512-256). |
| `crypto.hash(algorithm, data, options)` | `hash(...)` | **Compatible** | One-shot hashing utility. |
| `crypto.getHashes()` | `getHashes()` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac(algorithm, key, options)` | `createHmac(...)` / `Hmac` class | **Compatible** | Powered by `ring::hmac` supporting `update` and `digest` with encoding options (`hex`, `base64`, `binary`). |
| `crypto.createMac(algorithm, key, options)` | `createMac(...)` / `Mac` class | **Compatible** | Powered by `ring::hmac` for MAC computation. |
| `crypto.pbkdf2(...)` | `pbkdf2(...)` | **Compatible** | Asynchronous PBKDF2 key derivation using NAPI async task & `ring::pbkdf2`. |
| `crypto.pbkdf2Sync(...)` | `pbkdf2Sync(...)` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.createCipheriv` / `createDecipheriv` / AEAD | `encryptAead`, `decryptAead` | **Compatible** | AEAD encryption/decryption (AES-GCM, ChaCha20-Poly1305) via `ring::aead`. |
| `crypto.createECDH(curveName)` | `createECDH(...)` / `ECDH` class | **Compatible** | Powered by `ring::agreement` (P-256, P-384, X25519). |
| `crypto.createDiffieHellman` / `createDiffieHellmanGroup` | `createDiffieHellman`, `createDiffieHellmanGroup` | **Compatible** | MODP group & DH key agreement wrappers. |
| `crypto.generateKeyPair` / `generateKeyPairSync` | `generateKeyPair`, `generateKeyPairSync` | **Compatible** | Asymmetric key pair generation (RSA, Ed25519, EC) via `rsa` & `ring`. |
| `crypto.privateDecrypt` / `privateEncrypt` / `publicDecrypt` / `publicEncrypt` | `privateDecrypt`, `privateEncrypt`, `publicDecrypt`, `publicEncrypt` | **Compatible** | RSA public/private key encryption & decryption with `RSA_NO_PADDING`, `RSA_PKCS1_PADDING`, and `RSA_PKCS1_OAEP_PADDING`. |
| `crypto.sign` / `createSign` | `sign`, `createSign` / `Sign` class | **Compatible** | Digital signing via `ring` & `rsa`. |
| `crypto.verify` / `createVerify` | `verify`, `createVerify` / `Verify` class | **Compatible** | Signature verification via `ring` & `rsa`. |
| `crypto.randomBytes` / `randomFillSync` / `randomInt` / `randomUUID` | `randomBytes`, `randomFillSync`, `randomInt`, `randomUUID` | **Compatible** | Cryptographically secure random number/byte/UUID generation via `ring::rand`. |
| `crypto.createPrivateKey` / `createPublicKey` / `createSecretKey` | `KeyObject`, `createPrivateKey`, `createPublicKey`, `createSecretKey` | **Compatible** | `KeyObject` key representations. |
| `Class: X509Certificate` | `X509Certificate` class | **Compatible** | X.509 certificate parsing via `x509-parser`. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension / Native TLS** | Exposes `rustls` with configurable backends: `ring` (default), OpenSSL (`rustls-openssl`), BoringSSL (`boring-rustls-provider`), and MbedTLS (`rustls-mbedcrypto-provider`). |

---

## Module Reference

### 1. Hasher (`src/crypto_hasher.rs`)
- `createHash(algorithm: string): Hash`
- `hash(algorithm: string, data: string | Uint8Array, outputEncoding?: string): string | Buffer`
- `getHashes(): string[]`

### 2. HMAC & MAC (`src/hmac.rs`)
- `createHmac(algorithm: string, key: string | Uint8Array, encoding?: string): Hmac`
- `createMac(algorithm: string, key: string | Uint8Array): Hmac`
- `new Hmac(algorithm, key, encoding)`
- `Hmac.prototype.update(data, inputEncoding)`
- `Hmac.prototype.digest(outputEncoding)`

### 3. PBKDF2 (`src/pbkdf2.rs`)
- `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>`
- `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer`

### 4. Argon2 (`src/argon2.rs`)
- `argon2(algorithm: string, parameters: Argon2Parameters): Promise<Buffer>` (Node v24.7.0 API)
- `argon2Sync(algorithm: string, parameters: Argon2Parameters): Buffer` (Node v24.7.0 API)
- `argon2Hash(password, options?, abortSignal?): Promise<string>`
- `argon2HashSync(password, options?): string`
- `argon2HashRaw(password, options?): Promise<Buffer>`
- `argon2HashRawSync(password, options?): Buffer`
- `argon2Verify(hashed, password, options?): Promise<boolean>`
- `argon2VerifySync(hashed, password, options?): boolean`
- `argon2ParseOptions(hashed): ParsedHashOptions`

### 5. AEAD (`src/aead.rs`)
- `encryptAead(algorithm: string, key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): AeadResult`
- `decryptAead(algorithm: string, key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Buffer`

### 6. ECDH & Diffie-Hellman (`src/ecdh.rs`)
- `createECDH(curveName: string): ECDH`
- `createDiffieHellman(...)`: DiffieHellman instance
- `createDiffieHellmanGroup(name: string)`: DiffieHellmanGroup instance

### 7. RSA & Key Pairs (`src/rsa.rs`)
- `generateKeyPairSync(type: string): KeyPairResult`
- `generateKeyPair(type: string): Promise<KeyPairResult>`
- `publicEncrypt(key, buffer): Buffer`
- `privateDecrypt(key, buffer): Buffer`
- `privateEncrypt(key, buffer): Buffer`
- `publicDecrypt(key, buffer): Buffer`

### 8. Random (`src/rand.rs`)
- `randomBytes(size: number): Buffer`
- `randomFillSync(buffer: Uint8Array, offset?: number, size?: number): Uint8Array`
- `randomInt(min: number, max?: number): number`
- `randomUUID(): string`

### 9. KeyObject & Agreement & Signature (`src/key_object.rs`, `src/agreement.rs`, `src/signature.rs`)
- `KeyObject` class, `createPrivateKey`, `createPublicKey`, `createSecretKey`
- `Sign` class, `createSign`, `sign`
- `Verify` class, `createVerify`, `verify`
- `X509Certificate` class

### 10. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
- `TLS.prototype.providerName: string`
- `TLS.prototype.isSupported(): boolean`
