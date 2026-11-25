# Crypto manual

This package provides a Rust cryptographic core and Node.js bindings:

- `crypto::core` owns master-key generation and deterministic Ed25519/X25519
  identity derivation in one module.
- The Node.js `MasterKey` and `sealEnvelope` exports expose signing and
  multi-recipient envelope encryption without exposing derived private keys.
- `CryptoKey` preserves the earlier SLIP-0010 Ed25519 signing API.

The envelope protocol is a custom construction. It has automated security tests,
but it has not received an independent cryptographic audit.

## Build and verify

The project requires Node.js, npm, Rust, and Cargo.

```sh
npm install
npm run build
npm run test
npm run check
```

Inside this repository, import the generated Node module from `dist`:

```ts
import { CryptoKey, MasterKey, sealEnvelope } from "../dist/index.js";
```

When consuming a published package, replace the relative path with its package
name.

## Master keys

For a process-local or otherwise ephemeral identity, let the binding generate a
master key directly with the operating system CSPRNG:

```ts
import { MasterKey } from "../dist/index.js";

const ephemeralMaster = MasterKey.generate();
```

`MasterKey.generate()` intentionally provides no method to export its secret.
For a persistent identity, generate and store exactly 32 bytes of high-entropy
secret material outside the binding, then reconstruct `MasterKey` when needed:

```ts
import { randomBytes } from "node:crypto";
import { MasterKey } from "../dist/index.js";

const masterBytes = randomBytes(32);
// Persist masterBytes in secure storage before releasing this Buffer.
const master = new MasterKey(masterBytes);
```

Generate the bytes once with a cryptographically secure random generator. Store
and back them up through a keyring, hardware-backed secret store, or equivalent
system. Do not pass a password directly to `MasterKey`. If a password must be
used, first derive a 32-byte key with a password-hardening function such as
Argon2id and record its salt and parameters.

The Rust `MasterKey` value and temporary Rust-derived keys are zeroized when
dropped. The original input `Buffer`, returned plaintext `Buffer`s, and other
JavaScript-managed memory remain the caller's responsibility.

## Rust core identity API

The Rust API is implemented in the single `crypto::core` module.

```rust
use repo::crypto::core::MasterKey;

let master = MasterKey::generate()?;
let identity = master.derive_identity("repo:01932a4f-7b10-7000", 1)?;

let signing_public = identity.signing_public_key();
let encryption_public = identity.encryption_public_key();
let signature = identity.sign(b"commit payload");
# Ok::<(), repo::crypto::core::CoreError>(())
```

Use `MasterKey::from_bytes([u8; 32])` to reconstruct a stored master key.
`derive_identity(purpose, version)` currently accepts version `1`; unsupported
versions return `CoreError::UnsupportedVersion` instead of silently selecting a
new derivation protocol. Empty or oversized purposes return
`CoreError::InvalidPurpose`, and operating-system randomness failures return
`CoreError::RandomFailure`.

`IdentityKeys` keeps both private keys private. It exposes only their public
keys and signing as public operations; the X25519 secret accessor is restricted
to the crate so envelope encryption can use it internally. Neither the master
secret nor derived private keys can be serialized through this API.

## Purpose strings and child keys

A purpose string selects a deterministic child key. The same master key and
purpose always produce the same child, while different purposes and key types
produce independent keys through domain-separated HKDF-SHA256.

The Node.js methods always use derivation protocol version 1. Rust callers pass
that protocol version explicitly to `derive_identity`. Version 1 uses the
master key as HKDF input key material, the UTF-8 purpose as HKDF `info`, and
these distinct HKDF salts:

- `alloy/master/ed25519/v1` for the Ed25519 signing seed;
- `alloy/master/x25519/v1` for the X25519 encryption secret.

The derivation protocol version is separate from an application's key version.
Keep the latter in the purpose string so an application can rotate identities
without changing the cryptographic derivation protocol.

Use an unambiguous, stable convention that includes the entity and key version:

```ts
const repositoryEncryptionPurpose = "repo:01932a4f-7b10-7000/encryption/key-version:1";
const deviceSigningPurpose = "device:01932a4f-7b10-7001/signing/key-version:1";
```

Purpose strings must contain between 1 and 4096 UTF-8 bytes. Store the purpose
identifiers as application metadata. The master secret alone cannot reconstruct
identifiers chosen by the application.

`encryptionPublicKey(purpose)` derives an X25519 key pair and returns its 32-byte
public key. `signingPublicKey(purpose)` and `signChild(purpose, message)` derive
an independent Ed25519 signing key.

```ts
const encryptionPublicKey = master.encryptionPublicKey(repositoryEncryptionPurpose);
const signingPublicKey = master.signingPublicKey(deviceSigningPurpose);
const signature = master.signChild(deviceSigningPurpose, Buffer.from("message"));
```

Distribute public keys through an authenticated channel. A public key supplied
by an attacker grants access to the attacker when included as an envelope
recipient.

## Seal and open an envelope

An envelope encrypts the payload once with a fresh random 32-byte data-encryption
key (DEK). It then wraps that DEK independently for each recipient using an
ephemeral X25519 exchange, HKDF-SHA256, and XChaCha20-Poly1305.

```ts
import { randomBytes } from "node:crypto";
import { MasterKey, sealEnvelope } from "../dist/index.js";

const alice = new MasterKey(randomBytes(32));
const bob = new MasterKey(randomBytes(32));

const purpose = "repo:01932a4f-7b10-7000/encryption/key-version:1";
const context = "repo:01932a4f-7b10-7000/path:config/prod.secrets";

const envelope = sealEnvelope(context, Buffer.from("DATABASE_URL=postgres://prod"), [
  alice.encryptionPublicKey(purpose),
  bob.encryptionPublicKey(purpose),
]);

const plaintext = alice.open(purpose, context, envelope);
console.log(plaintext.toString("utf8"));
```

`sealEnvelope` returns JSON suitable for storage or transport. The context,
recipient identifiers, sizes, and ciphertext are public metadata. Only the
plaintext and private keys are secret.

Opening requires the independently expected context. Never read a context from
an untrusted envelope and pass it back as the expected value.

```ts
alice.open(purpose, context, envelope); // succeeds
alice.open(purpose, "repo:other/path:config/prod.secrets", envelope); // throws
```

Build contexts from canonical values. Normalize paths before constructing the
context, and avoid identifiers that can be renamed or interpreted differently
on another platform. Context authentication prevents moving an envelope to a
different context; it does not prevent replaying an older valid envelope at the
same context. Applications that need rollback protection must keep a trusted
version, counter, or content reference outside the envelope.

## Add a recipient

An existing recipient can unwrap the DEK and create a slot for a new recipient
without changing the payload ciphertext:

```ts
const carolPublicKey = carol.encryptionPublicKey(purpose);
const withCarol = alice.addRecipient(purpose, context, envelope, carolPublicKey);
const plaintext = carol.open(purpose, context, withCarol);
```

Every existing recipient can perform this operation. The envelope MAC proves
that the recipient list was produced by someone holding the DEK; it does not
prove administrator approval or sender identity. Enforce collaboration policy
before calling `addRecipient`, and require a verified signed manifest when a
specific administrator must authorize membership changes.

## Authorize recipients with a signed manifest

A repository manifest binds a stable 32-byte repository ID, an unsigned 64-bit
generation, the exact recipient public-key set, and the SHA-256 hash of the
exact envelope string. It is signed with a separately derived Ed25519
administrator identity.

```ts
import { randomBytes } from "node:crypto";
import { verifyManifest } from "../dist/index.js";

// Generate once and retain as trusted repository metadata.
const repositoryId = randomBytes(32);
const administratorPurpose = "repo:01932a4f-7b10-7000/administrator/key-version:1";
const administratorPublicKey = alice.signingPublicKey(administratorPurpose);

const signedManifest = alice.signManifest(
  administratorPurpose,
  repositoryId,
  1n,
  [alice.encryptionPublicKey(purpose), bob.encryptionPublicKey(purpose)],
  envelope,
);

verifyManifest(
  signedManifest,
  repositoryId,
  1n, // independently trusted minimum generation
  [administratorPublicKey],
  envelope,
); // returns true or throws
```

The repository ID, minimum generation, and trusted administrator public keys
must come from trusted state outside the signed manifest. Reading those values
from the manifest itself would let an attacker choose the policy used to verify
their own data.

Both generation arguments are JavaScript `bigint` values so the complete Rust
`u64` range is represented without losing precision. `verifyManifest` rejects
an untrusted signer, a stale generation, a different repository, any signature
change, recipient differences, and even a byte-level change to the envelope
string. Preserve the envelope string exactly as signed.

The Rust equivalents are `RepositoryManifest::new`, `sign_manifest`,
`TrustPolicy::new`, and `verify_manifest` in `crypto::manifest`. Rust callers
receive typed `CryptoError` failures from `crypto::error`.

Signing a manifest does not itself publish data or stop a recipient from
creating an unauthorized envelope. Applications must verify the manifest
against trusted policy before accepting, storing, or opening an envelope.

## Rotate or remove recipients

`rotateRecipients` decrypts the payload and seals it with a fresh DEK for a
replacement recipient list:

```ts
const aliceOnly = alice.rotateRecipients(purpose, context, withCarol, [
  alice.encryptionPublicKey(purpose),
]);
```

Recipients omitted from the new list cannot decrypt the new envelope. They can
still decrypt historical envelope copies and any plaintext they previously
obtained. Rotation cannot revoke already disclosed information.

Changing the purpose string derives a new static recipient key version. To
rotate both recipient keys and the DEK, derive public keys with the new purpose,
seal or rotate to those keys, and persist the new purpose alongside the
application metadata.

## Signing

`MasterKey` derives Ed25519 signing keys independently from X25519 encryption
keys. The API returns raw 32-byte public keys and 64-byte signatures.

```ts
const purpose = "device:01932a4f-7b10-7001/signing/key-version:1";
const message = Buffer.from("commit payload");
const publicKey = master.signingPublicKey(purpose);
const signature = master.signChild(purpose, message);
```

Verification is performed by the receiving application's Ed25519 implementation.
Sign a canonical byte representation rather than ambiguous JSON or text.

Rust callers can perform the same operation on an `IdentityKeys` value with
`identity.sign(message)` and distribute `identity.signing_public_key()`.

## Legacy `CryptoKey`

`CryptoKey` derives one deterministic Ed25519 key and chain code through the
SLIP-0010 master path:

```ts
const key = new CryptoKey(Buffer.from(seedBytes));
const signature = Buffer.from(key.sign(Buffer.from("message")));
const valid = key.verify(Buffer.from("message"), signature);
const publicKey = Buffer.from(key.publicKey());
const chainCode = Buffer.from(key.chainCode());
```

The constructor also accepts a UTF-8 string, but SLIP-0010 is not a password
hardening function. Low-entropy strings are vulnerable to guessing. Prefer a
random seed, or use `MasterKey` for new domain-separated applications.

`CryptoKey` and `MasterKey.signChild` use different derivation protocols and do
not produce interchangeable keys from the same input.

## Envelope format and validation

The version 1 suite identifier is
`alloy-envelope-v1/x25519-hkdf-sha256-xchacha20poly1305-hmacsha256`.
The JSON envelope contains:

- protocol version and suite;
- public context;
- an ordered recipient-slot list;
- a 24-byte payload nonce;
- authenticated ciphertext;
- a 32-byte envelope authentication tag.

Each recipient slot contains a full domain-separated SHA-256 recipient ID, an
ephemeral X25519 public key, a 24-byte wrapping nonce, and the wrapped DEK.
Non-contributory X25519 exchanges are rejected.

Authentication uses an ordered binary transcript with unsigned 64-bit
big-endian length prefixes rather than the JSON byte representation. The parser
rejects unknown or duplicate fields, unsupported protocol identifiers, invalid
fixed lengths, empty or duplicate recipient lists, and unsorted recipients.

Current limits are:

| Item                  |            Limit |
| --------------------- | ---------------: |
| Recipients            |              256 |
| Context or purpose    | 4096 UTF-8 bytes |
| Plaintext             |           16 MiB |
| Encoded JSON envelope |           80 MiB |

The API buffers plaintext, ciphertext, and JSON in memory and is not suitable
for streaming files larger than these limits.

## Failure handling

The Node API throws on malformed input, unauthorized recipients, context
mismatch, authentication failure, invalid public keys, duplicate recipients,
unsupported protocols, and size-limit violations. Treat every failure as a
rejected envelope. Do not return partially decrypted data or retry with context
values taken from the envelope.

Rust APIs return typed `CryptoError` values; `CoreError` remains an alias for
core callers. Envelope protocol internals deliberately collapse decryption and
authentication failures before they cross the Node boundary.

Avoid exposing detailed decryption errors across a trust boundary. A single
generic failure prevents callers from using error differences to inspect
recipient membership or validation stages.

## Security properties and limits

The envelope protocol provides confidentiality and integrity for the payload,
context, and complete recipient list under the assumptions of the selected
primitives. A successfully verified manifest additionally authenticates the
administrator and authorized recipient set against caller-supplied trust
policy. The system does not provide:

- rollback protection for older valid envelopes;
- recovery when the master key or purpose metadata is lost;
- revocation of historical ciphertext or previously disclosed plaintext;
- forward secrecy after a recipient's static private key is compromised;
- streaming encryption.

Use a dedicated authenticated session protocol for IPC that requires forward
secrecy. Do not reuse the static envelope protocol as a session handshake.

## Operational checklist

Before deploying:

1. Generate and store each persistent 32-byte master key securely; use
   `MasterKey.generate()` only when an unexportable process-local key is
   appropriate.
2. Define stable, versioned purpose and context formats.
3. Authenticate every recipient public key.
4. Verify a signed manifest before accepting recipient additions or rotations.
5. Keep repository IDs, administrator keys, and latest accepted generations in
   trusted state for authorization and rollback protection.
6. Plan key backup, loss recovery, rotation, and historical-data retention.
7. Avoid logging master keys, plaintext, derived private keys, or decrypted
   buffers.
8. Obtain an independent cryptographic and implementation review for sensitive
   production use.

See `examples/envelope.ts` for an executable multi-recipient example.
