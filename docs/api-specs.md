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
| `crypto.createHash(algorithm)` | `createHash(algorithm: string): Hash` | **Partially Compatible** | Basic object hashing (`sha1`, `sha256`, `sha384`, `sha512`, `sha512-256`) via `ring`. Stream interface & `hash.copy()` missing. |
| `crypto.hash(algorithm, data, outputEncoding)` | `hash(algorithm, data, outputEncoding?): string \| Buffer` | **Compatible** | One-shot digest calculation utility. |
| `crypto.getHashes()` | `getHashes(): string[]` | **Compatible** | Returns array of supported digest algorithm names (`sha1`, `sha256`, `sha384`, `sha512`, `sha512-256`). |
| `crypto.createHmac(algorithm, key, encoding)` | `createHmac(algorithm, key, encoding?): Hmac` | **Partially Compatible** | HMAC creation and calculation via `ring::hmac`. Stream interface missing. |
| `crypto.pbkdf2(password, salt, iterations, keylen, digest, callback)` | `pbkdf2(password, salt, iterations, keylen, digest): Promise<Buffer>` | **Compatible** | Asynchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.pbkdf2Sync(password, salt, iterations, keylen, digest)` | `pbkdf2Sync(password, salt, iterations, keylen, digest): Buffer` | **Compatible** | Synchronous PBKDF2 key derivation using `ring::pbkdf2`. |
| `crypto.createECDH(curveName)` | `createECDH(curveName: string): ECDH` | **Partially Compatible** | Basic Elliptic Curve Diffie-Hellman exchange (`P-256`, `P-384`, `X25519`). Missing `ECDH.convertKey`, `generateKeys`, `setPrivateKey`, `setPublicKey`. |
| `crypto.createDiffieHellman(groupOrPrime)` | `createDiffieHellman(groupOrPrime)` | **Partial / Stub** | Currently aliased to `ECDH`. True prime/generator DiffieHellman class is missing. |
| `crypto.createDiffieHellmanGroup(name)` | `createDiffieHellmanGroup(name)` | **Partial / Stub** | Currently aliased to `ECDH`. Predefined MODP group class is missing. |
| `crypto.generateKeyPair(type, options, callback)` | `generateKeyPair(typeName: string)` | **Partially Compatible** | Asynchronous RSA and Ed25519 key pair generation. Missing detailed options (`modulusLength`, `namedCurve`, `publicKeyEncoding`, etc.). |
| `crypto.generateKeyPairSync(type, options)` | `generateKeyPairSync(typeName: string)` | **Partially Compatible** | Synchronous RSA and Ed25519 key pair generation. Missing detailed options. |
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
| `crypto.createSign(algorithm)` / `crypto.sign(...)` | `createSign(algorithm) / sign(algorithm, data, key)` | **Partially Compatible** | Digital signature generation (Ed25519, ECDSA P-256). Missing stream interface and advanced signature options (`dsaEncoding`, `padding`, `saltLength`, `context`). |
| `crypto.createVerify(algorithm)` / `crypto.verify(...)` | `createVerify(algorithm) / verify(algorithm, data, key, sig)` | **Partially Compatible** | Digital signature verification. Missing stream interface and advanced signature options. |
| `crypto.createSecretKey` / `createPublicKey` / `createPrivateKey` | `createSecretKey / createPublicKey / createPrivateKey` | **Partially Compatible** | Factory functions returning basic `KeyObject`. |
| `Class: KeyObject` | `KeyObject` | **Partially Compatible** | Key representation for secret, public, and private keys. Missing `KeyObject.from()`, `equals()`, `toCryptoKey()`, and key details properties (`asymmetricKeyDetails`, `asymmetricKeyType`, `symmetricKeySize`, `type`). `export()` options ignored. |
| `Class: X509Certificate` | `X509Certificate` | **Partially Compatible** | X.509 certificate parsing (`subject`, `issuer`, `raw`) via `x509-parser`. Missing `ca`, fingerprints (`fingerprint`, `fingerprint256`, `fingerprint512`), verification methods (`checkEmail`, `checkHost`, `checkIP`, `checkIssued`, `checkPrivateKey`, `verify`), and validity dates. |
| AEAD Encryption / Decryption | `encryptAead` / `decryptAead` | **Extension** | High-performance AES-GCM and ChaCha20-Poly1305 AEAD routines. |
| TLS Engine & Crypto Providers | `TLS` class / `CryptoProviderType` | **Extension** | Exposes `rustls` with configurable backends (`ring`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`). |

---

## Detailed Gap Analysis (What is missing vs. standard `node:crypto`)

### 1. Entirely Missing Classes and API Suites
- **`Cipheriv` & `Decipheriv`**:
  - `crypto.createCipheriv(algorithm, key, iv[, options])` and `crypto.createDecipheriv(...)`
  - Streaming cipher transformations, `cipher.update()`, `cipher.final()`, `cipher.getAuthTag()`, `cipher.setAAD()`, `cipher.setAuthTag()`, `cipher.setAutoPadding()`.
- **`Certificate` (SPKAC)**:
  - `Certificate.exportChallenge()`, `Certificate.exportPublicKey()`, `Certificate.verifySpkac()`.
- **`Mac`**:
  - `crypto.createMac(algorithm, key[, options])`, `mac.update()`, `mac.final()`, `crypto.getMacs()`.
- **`DiffieHellman` / `DiffieHellmanGroup`**:
  - Full classic prime/generator Diffie-Hellman key exchange classes and methods (`generateKeys()`, `computeSecret()`, `getPrime()`, `getGenerator()`, `getPublicKey()`, `getPrivateKey()`, `setPublicKey()`, `setPrivateKey()`).

### 2. Missing Module-Level Utility Methods
- **Key Derivation Functions**:
  - `crypto.scrypt(password, salt, keylen[, options], callback)` & `crypto.scryptSync(...)`
  - `crypto.hkdf(digest, ikm, salt, info, keylen, callback)` & `crypto.hkdfSync(...)`
- **Constant-Time Comparison**:
  - `crypto.timingSafeEqual(a, b)`
- **Prime Number Generation & Check**:
  - `crypto.checkPrime(candidate[, options], callback)` & `crypto.checkPrimeSync(...)`
  - `crypto.generatePrime(size[, options], callback)` & `crypto.generatePrimeSync(...)`
- **Symmetric Key Generation**:
  - `crypto.generateKey(type, options, callback)` & `crypto.generateKeySync(...)`
- **Key Encapsulation Mechanism (KEM)**:
  - `crypto.encapsulate(key[, callback])` & `crypto.decapsulate(key, ciphertext[, callback])`
- **Diffie-Hellman One-Shot Secret Computation**:
  - `crypto.diffieHellman(options[, callback])`
- **Cipher & Curve Info Utilities**:
  - `crypto.getCipherInfo(nameOrNid[, options])`
  - `crypto.getCiphers()`
  - `crypto.getCurves()`
- **FIPS & Secure Heap Controls**:
  - `crypto.getFips()`, `crypto.setFips(bool)`
  - `crypto.secureHeapUsed()`, `crypto.setEngine(engine[, flags])`
- **PKCS#12 & WebCrypto Aliases**:
  - `crypto.parsePKCS12(bundle[, options])`
  - `crypto.getRandomValues(typedArray)`
  - `crypto.subtle` & `crypto.webcrypto`

### 3. Partial Class Implementations / Missing Options
- **`Hash`**:
  - Missing `hash.copy([options])`.
  - Missing Node.js `stream.Transform` interface integration.
- **`KeyObject`**:
  - Missing static method `KeyObject.from(key)`.
  - Missing instance properties: `asymmetricKeyDetails`, `asymmetricKeyType`, `symmetricKeySize`, `type`.
  - Missing instance methods: `equals(otherKeyObject)`, `toCryptoKey(...)`.
  - `export([options])` ignores formatting options (`format`, `type`, `cipher`, `passphrase`) and always returns raw bytes.
- **`X509Certificate`**:
  - Missing properties: `ca`, `fingerprint`, `fingerprint256`, `fingerprint512`, `infoAccess`, `issuerCertificate`, `keyUsage`, `publicKey`, `serialNumber`, `subjectAltName`, `validFrom`, `validFromDate`, `validTo`, `validToDate`, `signatureAlgorithm`, `signatureAlgorithmOid`.
  - Missing methods: `checkEmail()`, `checkHost()`, `checkIP()`, `checkIssued()`, `checkPrivateKey()`, `verify()`, `toJSON()`, `toLegacyObject()`.
- **`Sign` & `Verify`**:
  - Missing `stream.Writable` stream inheritance.
  - `sign()` and `verify()` do not support advanced options (`dsaEncoding`, `padding`, `saltLength`, `context`).
- **`ECDH`**:
  - Missing static method `ECDH.convertKey()`.
  - Missing instance methods `generateKeys()`, `getPrivateKey()`, `setPrivateKey()`, `setPublicKey()`.
- **`generateKeyPair` / `generateKeyPairSync`**:
  - Only accepts a string `typeName` ('ed25519' or 'rsa'); missing full `options` object (`modulusLength`, `publicExponent`, `namedCurve`, `publicKeyEncoding`, `privateKeyEncoding`, etc.) and key types (`ec`, `dh`, `dsa`, `rsa-pss`, `ml-dsa`, `ml-kem`, `slh-dsa`).
