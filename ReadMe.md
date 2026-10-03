# `@lib/crypto`

Native `node:crypto` compatible cryptographic module built with NAPI-RS and powered by Rust (`ring`, `rustls`, `rustls-openssl`, `boring-rustls-provider`, `rustls-mbedcrypto-provider`, and `argon2-rust`).

## Features

- **Hasher**: `createHash(algorithm)`, `hash(algorithm, data, encoding)`, `getHashes()`
- **HMAC**: `createHmac(algorithm, key)`, `Hmac` class supporting `update` and `digest` (`hex`, `base64`, `binary`, Buffer)
- **PBKDF2**: `pbkdf2` (async NAPI task) and `pbkdf2Sync`
- **Argon2**: High-performance Argon2 password hashing, verification, raw buffer hashing, and PHC option parsing
- **TLS & Crypto Providers**: `TLS` class exposing Ring, OpenSSL (`rustls-openssl`), BoringSSL (`boring-rustls-provider`), and MbedTLS (`rustls-mbedcrypto-provider`) backends for `rustls`

## Usage Examples

### Hash

```ts
import { createHash, hash, getHashes } from '@lib/crypto'

// Object-based streaming hash
const hasher = createHash('sha256')
hasher.update('Hello, world!')
const digestHex = hasher.digest('hex')

// One-shot hashing
const digestBase64 = hash('sha512', 'Hello, world!', 'base64')

// Available algorithms
console.log(getHashes()) // ['sha1', 'sha256', 'sha384', 'sha512', 'sha512-256']
```

### HMAC

```ts
import { createHmac } from '@lib/crypto'

const hmac = createHmac('sha256', 'my-secret-key')
hmac.update('Message to authenticate')
const macHex = hmac.digest('hex')
```

### PBKDF2

```ts
import { pbkdf2Sync, pbkdf2 } from '@lib/crypto'

// Synchronous PBKDF2
const derivedSync = pbkdf2Sync('password', 'salt', 10000, 32, 'sha256')

// Asynchronous PBKDF2
const derivedAsync = await pbkdf2('password', 'salt', 10000, 32, 'sha512')
```

### Argon2

```ts
import { argon2HashSync, argon2VerifySync, Algorithm, Version } from '@lib/crypto'

const hashStr = argon2HashSync('my-password', {
  algorithm: Algorithm.Argon2id,
  version: Version.V0x13,
  timeCost: 2,
  memoryCost: 19456,
})

const isValid = argon2VerifySync(hashStr, 'my-password')
```

### TLS Engine

```ts
import { TLS, CryptoProviderType } from '@lib/crypto'

const tlsDefault = new TLS() // Uses Ring
const tlsOpenSSL = new TLS(CryptoProviderType.OpenSSL)
const tlsBoring = new TLS(CryptoProviderType.BoringSSL)
const tlsMbed = new TLS(CryptoProviderType.MbedTLS)

console.log(tlsDefault.providerName) // 'ring'
```

## Development & Building

- Install dependencies:

```bash
npm install
```

- Build native binary:

```bash
npm run build
```

- Run unit tests:

```bash
npm test
```
