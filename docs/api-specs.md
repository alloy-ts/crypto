# API Specs & Node:Crypto Compatibility

This document tabulates the standard Node.js `node:crypto` API signatures, our implementation details via NAPI-RS, and compatibility status.

## Overview

`@lib/crypto` provides native Node.js cryptographic implementations powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, `rsa`, `sha1`, `sha2`, and `argon2-rust`).

---

## API Compatibility Table

| Standard `node:crypto` API | Our Implementation Signature | Compatibility Status | Implementation Notes / Backend |
| :--- | :--- | :--- | :--- |
| `crypto.argon2(algorithm, parameters, callback)` | `argon2(algorithm, parameters, callback)` / `Promise` | **Compatible** (Node v24.7.0+ spec) | Asynchronous Argon2d/i/id key derivation with input cloning and parameter validation. |
| `crypto.argon2Sync(algorithm, parameters)` | `argon2Sync(algorithm, parameters)` | **Compatible** (Node v24.7.0+ spec) | Synchronous Argon2d/i/id key derivation returning `Buffer`. |
| `crypto.createHash(algorithm)` | `createHash(algorithm: string): Hash` | **Compatible** | Stream transform & object hashing (`sha1`, `sha256`, `sha384`, `sha512`, `sha512-256`) via `ring`. |
| `crypto.hash(algorithm, data, outputEncoding)` | `hash(algorithm, data, outputEncoding?): string \| Buffer` | **Compatible** | One-shot digest calculation utility. |
| `crypto.getHashes()` | `getHashes(): string[]` | **Compatible** | Returns array of supported digest algorithm names. |
| `crypto.createHmac(algorithm, key, encoding)` | `createHmac(algorithm, key, encoding?): Hmac` | **Compatible** | HMAC creation and calculation via `ring::hmac`. |
| `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)` | `pbkdf2(password, salt, iterations, keylen, digest, callback?): Promise<Buffer>` | **Compatible** | Asynchronous PBKDF2 key derivation using `ring::pbkdf2`. Supports both callback and Promise. |
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
| `crypto.randomBytes(size, callback)` | `randomBytes(size, callback?): Buffer` | **Compatible** | Cryptographically secure random byte generation via `ring::rand`. Supports sync return and async callback. |
| `crypto.randomFill(buffer, offset, size, callback)` | `randomFill(buffer, offset?, size?, callback?): Promise<Uint8Array>` | **Compatible** | Asynchronous / callback-based random buffer fill via `ring::rand`. |
| `crypto.randomFillSync(buffer, offset, size)` | `randomFillSync(buffer, offset?, size?): Uint8Array` | **Compatible** | Synchronous random buffer fill. |
| `crypto.randomInt(min, max, callback)` | `randomInt(min, max?, callback?): number` | **Compatible** | Unbiased random integer generation. Supports both sync return and async callback. |
| `crypto.randomUUID()` | `randomUUID(): string` | **Compatible** | RFC 4122 version 4 UUID generator. |
| `crypto.randomUUIDv7()` | `randomUUIDv7(): string` | **Compatible** (Node v26.1.0+ spec) | RFC 9562 version 7 time-ordered UUID generator. |
| `crypto.createSign(algorithm)` / `crypto.sign(...)` | `createSign(algorithm) / sign(algorithm, data, key)` | **Compatible** | Digital signature generation (Ed25519, ECDSA P-256). |
| `crypto.createVerify(algorithm)` / `crypto.verify(...)` | `createVerify(algorithm) / verify(algorithm, data, key, sig)` | **Compatible** | Digital signature verification. |
| `crypto.createSecretKey` / `createPublicKey` / `createPrivateKey` | `createSecretKey / createPublicKey / createPrivateKey` | **Compatible** | Key object factory functions returning `KeyObject`. |
| `Class: KeyObject` | `KeyObject` | **Compatible** | Key representation for secret, public, and private keys. |
| `Class: X509Certificate` | `X509Certificate` | **Compatible** (Basic) | X.509 certificate parsing (`subject`, `issuer`, `raw`, `toString`) via `x509-parser`. |
| AEAD Encryption / Decryption | `encryptAead` / `decryptAead` | **Extension** | High-performance AES-GCM and ChaCha20-Poly1305 AEAD routines. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension** | Exposes `rustls` with configurable backends (`ring`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`). |

---

## Module Reference

### 1. Argon2 (`src/argon2.rs`)
- `argon2(algorithm: string, parameters: Argon2Parameters, callback?: Function): Promise<Buffer> | void`
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
- `pbkdf2(password, salt, iterations, keylen, digest, callback?: Function): Promise<Buffer> | void`
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
- `randomBytes(size: number, callback?: Function): Buffer | void`
- `randomBytesAsync(size: number): Promise<Buffer>`
- `randomFill(buffer: Uint8Array, offset?: number, size?: number, callback?: Function): Promise<Uint8Array> | void`
- `randomFillSync(buffer: Uint8Array, offset?: number, size?: number): Uint8Array`
- `randomInt(min: number, max?: number, callback?: Function): number | void`
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

---

## Missing Node.js `node:crypto` APIs & Features

Compared to the standard `node:crypto` API specification, the following APIs and features are currently not implemented in `@lib/crypto`:

1. **Streaming Ciphers & AEAD Classes**:
   - `Cipheriv` / `Decipheriv` transform streams and factory functions `crypto.createCipheriv` / `crypto.createDecipheriv`.
   - Streaming methods: `cipher.setAuthTag()`, `cipher.getAuthTag()`, `cipher.setAAD()`, `cipher.setAutoPadding()`.
   *(Note: `@lib/crypto` provides `encryptAead` and `decryptAead` one-shot utilities).*

2. **Key Derivation Functions (KDFs)**:
   - `crypto.scrypt` and `crypto.scryptSync`.
   - `crypto.hkdf` and `crypto.hkdfSync` (standalone wrappers).

3. **SPKAC & Certificate Utilities**:
   - `Certificate` class and static/instance methods: `Certificate.exportChallenge`, `Certificate.exportPublicKey`, `Certificate.verifySpkac`.

4. **Prime Number Operations**:
   - `crypto.checkPrime` and `crypto.checkPrimeSync`.
   - `crypto.generatePrime` and `crypto.generatePrimeSync`.

5. **Key Management & Constants**:
   - `crypto.constants` object (e.g., `RSA_PKCS1_PADDING`, `RSA_PKCS1_OAEP_PADDING`, OpenSSL flags).
   - `crypto.encapsulate` and `crypto.decapsulate` (KEM operations).
   - `crypto.generateKey` and `crypto.generateKeySync` (symmetric secret key generation for HMAC/AES).

6. **Full DiffieHellman & ECDH Classes**:
   - Full `DiffieHellman` class methods (`computeSecret`, `generateKeys`, `getPrime`, `getGenerator`, `getPrivateKey`, `getPublicKey`, `setPrivateKey`, `setPublicKey`, `verifyError`).
   - `ECDH.convertKey` and `ecdh.getPrivateKey()` / `ecdh.setPrivateKey()`.

7. **Utilities & Info**:
   - `crypto.timingSafeEqual(a, b)` (constant-time buffer equality check).
   - `crypto.getCipherInfo(nameOrNid)` and `crypto.getCiphers()`.
   - `crypto.getCurves()`.
   - `crypto.getMacs()` and `crypto.createMac(algorithm, key[, options])`.
   - `crypto.parsePKCS12(bundle[, options])`.
   - `crypto.getFips()` and `crypto.setFips(bool)`.
   - `crypto.secureHeapUsed()`.
   - `crypto.setEngine(engine[, flags])`.
   - `crypto.getRandomValues(typedArray)`.
   - `crypto.subtle` / `crypto.webcrypto` (Web Crypto API standard bindings).

8. **Advanced X509 Certificate Properties & Verification**:
   - Properties: `fingerprint`, `fingerprint256`, `fingerprint512`, `infoAccess`, `subjectAltName`, `keyUsage`, `validFrom`, `validFromDate`, `validTo`, `validToDate`, `signatureAlgorithm`, `signatureAlgorithmOid`, `issuerCertificate`.
   - Methods: `checkEmail`, `checkHost`, `checkIP`, `checkIssued`, `checkPrivateKey`, `verify`, `toJSON`, `toLegacyObject`.

9. **Hash / Stream Extras**:
   - `hash.copy()` (deep copying internal hash state).
