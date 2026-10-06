# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API signatures, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `rsa`, `sha1`, `sha2`, and `argon2-rust`).

---

## API Compatibility Table

| Standard `node:crypto` API | Our Implementation Signature | Compatibility Status | Implementation Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.argon2(algorithm, parameters, callback)` | `argon2(algorithm: string, parameters: Argon2Parameters)` | **Compatible** (Node v24.7.0+ spec) | Asynchronous Argon2d/i/id key derivation returning `Buffer`. |
| `crypto.argon2Sync(algorithm, parameters)` | `argon2Sync(algorithm: string, parameters: Argon2Parameters)` | **Compatible** (Node v24.7.0+ spec) | Synchronous Argon2d/i/id key derivation returning `Buffer`. |
| `crypto.Certificate` | `Certificate` | **Compatible** | SPKAC processing (`exportChallenge`, `exportPublicKey`, `verifySpkac`) with static and legacy instance API support. |
| `crypto.createHash(algorithm)` | `createHash(algorithm: string): Hash` | **Compatible** | Stream transform & object hashing (`sha1`, `sha256`, `sha384`, `sha512`, `sha512-256`) via `ring`. |
| `crypto.hash(algorithm, data, outputEncoding)` | `hash(algorithm, data, outputEncoding?): string \| Buffer` | **Compatible** | One-shot digest calculation utility. |
| `crypto.getHashes()` | `getHashes(): string[]` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac(algorithm, key, encoding)` | `createHmac(algorithm, key, encoding?): Hmac` | **Compatible** | HMAC creation and calculation via `ring::hmac`. |
| `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)` | `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>` | **Compatible** | Asynchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)` | `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.createECDH(curveName)` | `createECDH(curveName: string): ECDH` | **Compatible** | Elliptic Curve Diffie-Hellman exchange (`P-256`, `P-384`, `X25519`). |
| `crypto.createDiffieHellman(groupOrPrime)` | `createDiffieHellman(groupOrPrime)` | **Compatible** | Diffie-Hellman key exchange helper. |
| `crypto.createDiffieHellmanGroup(name)` | `createDiffieHellmanGroup(name)` | **Compatible** | Diffie-Hellman predefined modp group wrapper. |
| `crypto.generateKeyPair(type, options, callback)` | `generateKeyPair(typeName: string)` | **Compatible** | Asynchronous RSA and Ed25519 key pair generation. |
| `crypto.generateKeyPairSync(type, options)` | `generateKeyPairSync(typeName: string)` | **Compatible** | Synchronous RSA and Ed25519 key pair generation. |
| `crypto.publicEncrypt(key, buffer)` | `publicEncrypt(keyArg, buffer)` | **Compatible** | RSA public key encryption with PKCS1v15, OAEP (SHA1/SHA256/384/512), and NoPadding modes. |
| `crypto.privateDecrypt(privateKey, buffer)` | `privateDecrypt(keyArg, buffer)` | **Compatible** | RSA private key decryption with PKCS1v15, OAEP, and NoPadding modes. |
| `crypto.privateEncrypt(privateKey, buffer)` | `privateEncrypt(keyArg, buffer)` | **Compatible** | RSA private key encryption. |
| `crypto.publicDecrypt(key, buffer)` | `publicDecrypt(keyArg, buffer)` | **Compatible** | RSA public key decryption. |
| `crypto.randomBytes(size, callback)` | `randomBytes(size: number): Buffer` / `randomBytesAsync(size): Promise<Buffer>` | **Compatible** | Cryptographically secure random byte generation via `ring::rand`. |
| `crypto.randomFill(buffer, offset, size, callback)` | `randomFill(buffer, offset?, size?): Promise<Uint8Array>` | **Compatible** | Asynchronous random buffer fill via `ring::rand`. |
| `crypto.randomFillSync(buffer, offset, size)` | `randomFillSync(buffer, offset?, size?): Uint8Array` | **Compatible** | Synchronous random buffer fill. |
| `crypto.randomInt(min, max)` | `randomInt(min: number, max?: number): number` | **Compatible** | Unbiased random integer generation. |
| `crypto.randomUUID()` | `randomUUID(): string` | **Compatible** | RFC 4122 version 4 UUID generator. |
| `crypto.randomUUIDv7()` | `randomUUIDv7(): string` | **Compatible** (Node v26.1.0+ spec) | RFC 9562 version 7 time-ordered UUID generator. |
| `crypto.createSign(algorithm)` / `crypto.sign(...)` | `createSign(algorithm) / sign(algorithm, data, key)` | **Compatible** | Digital signature generation (Ed25519, ECDSA P-256). |
| `crypto.createVerify(algorithm)` / `crypto.verify(...)` | `createVerify(algorithm) / verify(algorithm, data, key, sig)` | **Compatible** | Digital signature verification. |
| `crypto.createSecretKey` / `createPublicKey` / `createPrivateKey` | `createSecretKey / createPublicKey / createPrivateKey` | **Compatible** | Key object factory functions returning `KeyObject`. |
| `Class: KeyObject` | `KeyObject` | **Compatible** | Key representation for secret, public, and private keys. |
| `Class: X509Certificate` | `X509Certificate` | **Compatible** | X.509 certificate parsing (`subject`, `issuer`, `raw`) via `x509-parser`. |
| AEAD Encryption / Decryption | `encryptAead` / `decryptAead` | **Extension** | High-performance AES-GCM and ChaCha20-Poly1305 AEAD routines. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension** | Exposes `rustls` with configurable backends (`ring`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`). |

---

## Module Reference

### 1. Argon2 (`src/argon2.rs`)
- `argon2(algorithm: string, parameters: Argon2Parameters): Promise<Buffer>`
- `argon2Sync(algorithm: string, parameters: Argon2Parameters): Buffer`

### 2. Certificate (`src/certificate.rs`)
- `Certificate.exportChallenge(spkac, encoding?): Buffer`
- `Certificate.exportPublicKey(spkac, encoding?): Buffer`
- `Certificate.verifySpkac(spkac, encoding?): boolean`
- `new Certificate()` (legacy API with instance `exportChallenge`, `exportPublicKey`, `verifySpkac`)

### 3. Hasher (`src/crypto_hasher.rs`)
- `createHash(algorithm: string): Hash`
- `hash(algorithm: string, data: string | Uint8Array, outputEncoding?: string): string | Buffer`
- `getHashes(): string[]`

### 4. HMAC (`src/hmac.rs`)
- `createHmac(algorithm: string, key: string | Uint8Array, encoding?: string): Hmac`
- `new Hmac(algorithm, key, encoding)`
- `Hmac.prototype.update(data, inputEncoding)`
- `Hmac.prototype.digest(outputEncoding)`

### 5. PBKDF2 (`src/pbkdf2.rs`)
- `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>`
- `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer`

### 6. ECDH (`src/ecdh.rs`)
- `createECDH(curveName: string): ECDH`
- `createDiffieHellman(groupOrPrime: string | number): ECDH`
- `createDiffieHellmanGroup(name: string): ECDH`

### 7. RSA (`src/rsa.rs`)
- `generateKeyPair(typeName: string): Promise<KeyPairResult>`
- `generateKeyPairSync(typeName: string): KeyPairResult`
- `publicEncrypt(keyArg, buffer): Buffer`
- `privateDecrypt(keyArg, buffer): Buffer`
- `privateEncrypt(keyArg, buffer): Buffer`
- `publicDecrypt(keyArg, buffer): Buffer`

### 8. Random (`src/random.rs`)
- `randomBytes(size: number): Buffer`
- `randomBytesAsync(size: number): Promise<Buffer>`
- `randomFill(buffer: Uint8Array, offset?: number, size?: number): Promise<Uint8Array>`
- `randomFillSync(buffer: Uint8Array, offset?: number, size?: number): Uint8Array`
- `randomInt(min: number, max?: number): number`
- `randomUUID(): string`
- `randomUUIDv7(): string`

### 9. Sign / Verify / KeyObject (`src/signature.rs`, `src/agreement.rs`, `src/key_object.rs`)
- `createSign(algorithm: string): Sign`
- `sign(algorithm, data, privateKey): Buffer`
- `createVerify(algorithm: string): Verify`
- `verify(algorithm, data, publicKey, signature): boolean`
- `createSecretKey(key: Uint8Array): KeyObject`
- `createPublicKey(key: Uint8Array): KeyObject`
- `createPrivateKey(key: Uint8Array): KeyObject`
- `new X509Certificate(buffer: Uint8Array)`

### 10. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
