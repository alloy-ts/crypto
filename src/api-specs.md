# API Specs & Node:Crypto Compatibility

This document provides a full audit of Node's official `node:crypto` API exports against our native implementation `@lib/crypto`.

---

## 1. Node.js `node:crypto` Export Audit

Below is the complete comparison against Node.js `node:crypto` exports:

### Methods

| Method | Status | Our Export / Notes |
| :--- | :--- | :--- |
| `argon2` | **Supported** | `argon2(algorithm, parameters)` |
| `argon2Sync` | **Supported** | `argon2Sync(algorithm, parameters)` |
| `checkPrime` | Missing | Not implemented |
| `checkPrimeSync` | Missing | Not implemented |
| `createCipheriv` | Missing | Symmetric streaming ciphers not implemented |
| `createDecipheriv` | Missing | Symmetric streaming ciphers not implemented |
| `createDiffieHellman` | **Partial** | Alias returning ECDH instance |
| `createDiffieHellmanGroup` | **Partial** | Alias returning ECDH instance |
| `createECDH` | **Supported** | `createECDH(curveName)` |
| `createHash` | **Supported** | `createHash(algorithm)` |
| `createHmac` | **Supported** | `createHmac(algorithm, key, options)` |
| `createMac` | **Supported** | `createMac(algorithm, key)` |
| `createPrivateKey` | **Supported** | `createPrivateKey(key)` |
| `createPublicKey` | **Supported** | `createPublicKey(key)` |
| `createSecretKey` | **Supported** | `createSecretKey(key)` |
| `createSign` | **Supported** | `createSign(algorithm)` |
| `createVerify` | **Supported** | `createVerify(algorithm)` |
| `decapsulate` | Missing | Not implemented |
| `diffieHellman` | Missing | Not implemented |
| `encapsulate` | Missing | Not implemented |
| `generateKey` | Missing | Not implemented |
| `generateKeyPair` | **Supported** | `generateKeyPair(typeName)` |
| `generateKeyPairSync` | **Supported** | `generateKeyPairSync(typeName)` |
| `generateKeySync` | Missing | Not implemented |
| `generatePrime` | Missing | Not implemented |
| `generatePrimeSync` | Missing | Not implemented |
| `getCipherInfo` | Missing | Not implemented |
| `getCiphers` | Missing | Not implemented |
| `getCurves` | Missing | Not implemented |
| `getDiffieHellman` | Missing | Not implemented |
| `getFips` | Missing | Not implemented |
| `getHashes` | **Supported** | `getHashes()` |
| `getMacs` | Missing | Not implemented |
| `hash` | **Supported** | `hash(algorithm, data, outputEncoding)` |
| `hkdf` | Missing | Not implemented |
| `hkdfSync` | Missing | Not implemented |
| `parsePKCS12` | Missing | Not implemented |
| `pbkdf2` | **Supported** | `pbkdf2(password, salt, iterations, keylen, digest)` |
| `pbkdf2Sync` | **Supported** | `pbkdf2Sync(password, salt, iterations, keylen, digest)` |
| `privateDecrypt` | **Supported** | `privateDecrypt(keyArg, buffer)` |
| `privateEncrypt` | **Supported** | `privateEncrypt(keyArg, buffer)` |
| `publicDecrypt` | **Supported** | `publicDecrypt(keyArg, buffer)` |
| `publicEncrypt` | **Supported** | `publicEncrypt(keyArg, buffer)` |
| `randomBytes` | **Supported** | `randomBytes(size)` |
| `randomFill` | Missing | Async version not implemented (sync available) |
| `randomFillSync` | **Supported** | `randomFillSync(buffer, offset, size)` |
| `randomInt` | **Supported** | `randomInt(min, max)` |
| `randomUUID` | **Supported** | `randomUUID()` |
| `randomUUIDv7` | Missing | Not implemented |
| `scrypt` | Missing | Not implemented |
| `scryptSync` | Missing | Not implemented |
| `setEngine` | Missing | Deprecated in Node.js |
| `setFips` | Missing | Not implemented |
| `sign` | **Supported** | `sign(algorithm, data, privateKey)` |
| `timingSafeEqual` | Missing | Not implemented |
| `verify` | **Supported** | `verify(algorithm, data, publicKey, signature)` |

### Classes

| Class | Status | Our Export / Notes |
| :--- | :--- | :--- |
| `Certificate` | Missing | Legacy SPKAC certificate class not implemented |
| `Cipheriv` | Missing | Streaming cipher stream class not implemented |
| `Decipheriv` | Missing | Streaming decipher stream class not implemented |
| `DiffieHellman` | Missing | Classic DH class not implemented (ECDH available) |
| `DiffieHellmanGroup` | Missing | Classic DH Group class not implemented |
| `ECDH` | **Supported** | `ECDH` class |
| `Hash` | **Supported** | `Hash` class |
| `Hmac` | **Supported** | `Hmac` class |
| `KeyObject` | **Supported** | `KeyObject` class |
| `Mac` | Missing | Stream class not implemented (`createMac` helper available) |
| `Sign` | **Supported** | `Sign` class |
| `Verify` | **Supported** | `Verify` class |
| `X509Certificate` | **Supported** | `X509Certificate` class |

### Properties, Constants, and Aliases

| Property / Property Alias | Status | Notes |
| :--- | :--- | :--- |
| `constants` | Missing | `crypto.constants` object not implemented |
| `fips` | Missing | Deprecated `crypto.fips` getter/setter not implemented |
| `webcrypto` | Missing | `crypto.webcrypto` Web Crypto API not implemented |
| `subtle` | Missing | `crypto.subtle` alias not implemented |
| `getRandomValues` | Missing | `crypto.getRandomValues` alias not implemented |
| `secureHeapUsed` | Missing | `crypto.secureHeapUsed()` not implemented |
| `prng` | Missing | Deprecated `randomBytes` alias not implemented |
| `pseudoRandomBytes` | Missing | Deprecated `randomBytes` alias not implemented |
| `rng` | Missing | Deprecated `randomBytes` alias not implemented |

---

## 2. Additional Extensions Provided in `@lib/crypto`

| API | Type | Notes |
| :--- | :--- | :--- |
| `argon2Hash` / `argon2HashSync` | High-Perf Argon2 | PHC string password hashing |
| `argon2Verify` / `argon2VerifySync` | High-Perf Argon2 | PHC string password verification |
| `argon2ParseOptions` | Utility | PHC string parameter parsing |
| `encryptAead` / `decryptAead` | Native AEAD | High-performance AES-GCM AEAD encryption and decryption with AAD |
| `TLS` / `CryptoProviderType` | Native TLS Engine | Native Rustls provider selection (`Ring`, `OpenSSL`, `BoringSSL`, `MbedTLS`) |
