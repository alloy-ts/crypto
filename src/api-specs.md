# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` (native crate `lib-crypto-native`) provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `rsa`, and `argon2-rust`).

---

## API Compatibility Table

| `node:crypto` Standard API | Our Implementation | Compatibility Status | Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.argon2` / `crypto.argon2Sync` | `argon2` / `argon2Sync` | **Compatible** | Argon2 key derivation conforming to node:crypto argon2 specs. Powered by `argon2-rust`. |
| `crypto.argon2Hash` / `crypto.argon2Verify` | `argon2Hash` / `argon2Verify` / `argon2HashSync` / `argon2VerifySync` | **Extension** | PHC format string hashing & verification helpers. |
| `crypto.createHash` / `crypto.hash` | `createHash` / `Hash` / `hash` | **Compatible** | Powered by `ring` digest routines (SHA1, SHA256, SHA384, SHA512, SHA512-256). |
| `crypto.getHashes` | `getHashes()` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac` | `createHmac(...)` / `Hmac` class | **Compatible** | Powered by `ring::hmac` supporting `update` and `digest` with encoding options (`hex`, `base64`, `latin1`). |
| `crypto.pbkdf2` / `crypto.pbkdf2Sync` | `pbkdf2` / `pbkdf2Sync` | **Compatible** | Key derivation using `ring::pbkdf2`. |
| AEAD (GCM, ChaChaPoly) | `encrypt_aead` / `decrypt_aead` | **Compatible** | Powered by `ring::aead`. |
| `crypto.createECDH` / `createDiffieHellman` / `diffieHellman` | `createECDH` / `ECDH` / `createDiffieHellman` / `diffieHellman` | **Compatible** | Elliptic curve Diffie-Hellman powered by `ring::agreement`. |
| `crypto.generateKeyPair` / `generateKeyPairSync` | `generateKeyPair` / `generateKeyPairSync` | **Compatible** | RSA and Ed25519 key pair generation powered by `rsa` and `ring`. |
| `crypto.publicEncrypt` / `privateDecrypt` / `privateEncrypt` / `publicDecrypt` | `publicEncrypt` / `privateDecrypt` / `privateEncrypt` / `publicDecrypt` | **Compatible** | RSA public/private key encryption & decryption with PKCS1v15, OAEP, or NoPadding. |
| `crypto.randomBytes` / `randomFillSync` / `randomInt` / `randomUUID` / `randomUUIDv7` / `generatePrimeSync` | `randomBytes` / `randomFillSync` / `randomInt` / `randomUUID` / `randomUUIDv7` / `generatePrimeSync` | **Compatible** | Cryptographically secure pseudo-random data powered by `ring::rand`. |
| Key Objects & Certificates | `KeyObject` / `CryptoKeyPair` / `X509Certificate` / `createSecretKey` / `createPublicKey` / `createPrivateKey` | **Compatible** | Secret/Public/Private key management and X.509 certificate parsing via `x509-parser`. |
| `crypto.createSign` / `crypto.sign` | `createSign` / `Sign` / `sign` | **Compatible** | Digital signature generation powered by `ring::signature`. |
| `crypto.createVerify` / `crypto.verify` / `crypto.createMac` | `createVerify` / `Verify` / `verify` / `createMac` | **Compatible** | Signature verification and MAC generation powered by `ring`. |
| TLS Engine & Providers | `TLS` class / `CryptoProviderType` | **Extension** | Exposes `rustls` with configurable backends: `ring` (default), OpenSSL (`rustls-openssl`), BoringSSL (`boring-rustls-provider`), and MbedTLS (`rustls-mbedcrypto-provider`). |

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
- `argon2Verify(hashed, password, options?): Promise<boolean>`
- `argon2VerifySync(hashed, password, options?): boolean`
- `argon2ParseOptions(hashed): ParsedHashOptions`

### 5. AEAD (`src/aead.rs`)
- `encrypt_aead(algorithm, key, nonce, plaintext, aad?): Buffer`
- `decrypt_aead(algorithm, key, nonce, ciphertextAndTag, aad?): Buffer`

### 6. ECDH & Diffie-Hellman (`src/ecdh.rs`)
- `createECDH(curveName): ECDH`
- `createDiffieHellman(groupOrPrime): ECDH`
- `createDiffieHellmanGroup(name): ECDH`
- `diffieHellman(privateKeyBytes, publicKeyBytes): Buffer`

### 7. RSA & Key Pair Generation (`src/rsa.rs`)
- `generateKeyPair(typeName): Promise<KeyPairResult>`
- `generateKeyPairSync(typeName): KeyPairResult`
- `publicEncrypt(key, buffer): Buffer`
- `privateDecrypt(key, buffer): Buffer`
- `privateEncrypt(key, buffer): Buffer`
- `publicDecrypt(key, buffer): Buffer`

### 8. Random (`src/random.rs`)
- `randomBytes(size): Buffer`
- `randomFillSync(buffer, offset?, size?): Uint8Array`
- `randomInt(min, max?): number`
- `randomUUID(): string`
- `randomUUIDv7(): string`
- `generatePrimeSync(size): Buffer`

### 9. Key Object & Certificate (`src/key_object.rs`)
- `new KeyObject(keyType, rawBytes)`
- `new X509Certificate(buffer)`
- `createSecretKey(key)`
- `createPublicKey(key)`
- `createPrivateKey(key)`

### 10. Agreement & Verification (`src/agreement.rs`)
- `new Verify(algorithm)`
- `createVerify(algorithm): Verify`
- `verify(algorithm, data, publicKey, signature): boolean`
- `createMac(algorithm, key): Hmac`

### 11. Signature (`src/signature.rs`)
- `new Sign(algorithm)`
- `createSign(algorithm): Sign`
- `sign(algorithm, data, privateKey): Buffer`

### 12. TLS (`src/tls.rs`)
- `new TLS(provider?: CryptoProviderType)`
- `CryptoProviderType`: `Ring` (0), `OpenSSL` (1), `BoringSSL` (2), `MbedTLS` (3)
- `TLS.prototype.providerName: string`
- `TLS.prototype.isSupported(): boolean`
