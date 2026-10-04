# Node:Crypto API Specifications & Compatibility Status

| API / Module                                             | Status    | Implementation Details                                                             |
| -------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------- |
| `crypto.getHashes()`                                     | Supported | Returns available digest hash algorithms (`crypto_hasher.rs`)                      |
| `crypto.Hash`                                            | Supported | Stream & one-shot hasher class (`crypto_hasher.rs`)                                |
| `crypto.createHmac()` / `crypto.Hmac`                    | Supported | HMAC calculation using Ring/native Rust (`hmac.rs`)                                |
| `crypto.argon2()` / `crypto.argon2Sync()`                | Supported | Argon2 key derivation (`argon2.rs`)                                                |
| `crypto.pbkdf2()` / `crypto.pbkdf2Sync()`                | Supported | PBKDF2 key derivation (`pbkdf2.rs`)                                                |
| `crypto.randomBytes()` / `crypto.randomFill()`           | Supported | Cryptographically secure random bytes generator (`rand.rs`)                        |
| `crypto.randomInt()` / `crypto.randomUUID()`             | Supported | RFC 4122 v4 & RFC 9562 v7 UUID generation (`rand.rs`)                              |
| `crypto.createCipheriv()` / `Cipher`                     | Supported | AEAD encryption/decryption (`aead.rs`)                                             |
| `crypto.createECDH()` / `ECDH`                           | Supported | Elliptic Curve Diffie-Hellman (`ecdh.rs`)                                          |
| `crypto.generateKeyPairSync()`                           | Supported | RSA / EC keypair generation (`rsa.rs`)                                             |
| `crypto.KeyObject` / `CryptoKeyPair` / `X509Certificate` | Supported | Key object representations & X.509 certificate parsing (`key_object.rs`)           |
| `crypto.createSign()` / `Sign` / `Verify`                | Supported | Digital signature generation and verification (`signature.rs`)                     |
| `crypto.encapsulate()` / `crypto.decapsulate()`          | Supported | Key agreement and KEM algorithms (`agreement.rs`)                                  |
| `TLS` Provider                                           | Supported | TLS provider selection defaulting to Ring, with Rustls/OpenSSL fallback (`tls.rs`) |
