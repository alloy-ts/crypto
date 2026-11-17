# Crypto manual

This package provides two Node.js APIs backed by Rust:

- `MasterKey` and `sealEnvelope` implement deterministic child-key derivation,
  Ed25519 signing, and multi-recipient envelope encryption.
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

`MasterKey` accepts exactly 32 bytes of high-entropy secret material.

```ts
import { randomBytes } from "node:crypto";
import { MasterKey } from "../dist/index.js";

const masterBytes = randomBytes(32);
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

## Purpose strings and child keys

A purpose string selects a deterministic child key. The same master key and
purpose always produce the same child, while different purposes and key types
produce independent keys through domain-separated HKDF-SHA256.

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
before calling `addRecipient`, and use an application-level signature when a
specific administrator must authorize membership changes.

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

Avoid exposing detailed decryption errors across a trust boundary. A single
generic failure prevents callers from using error differences to inspect
recipient membership or validation stages.

## Security properties and limits

The protocol provides confidentiality and integrity for the payload, context,
and complete recipient list under the assumptions of the selected primitives.
It does not provide:

- sender identity or administrator authorization;
- rollback protection for older valid envelopes;
- recovery when the master key or purpose metadata is lost;
- revocation of historical ciphertext or previously disclosed plaintext;
- forward secrecy after a recipient's static private key is compromised;
- streaming encryption.

Use a dedicated authenticated session protocol for IPC that requires forward
secrecy. Do not reuse the static envelope protocol as a session handshake.

## Operational checklist

Before deploying:

1. Generate and store each 32-byte master key securely.
2. Define stable, versioned purpose and context formats.
3. Authenticate every recipient public key.
4. Enforce authorization around recipient additions and rotations.
5. Keep trusted state when rollback protection is required.
6. Plan key backup, loss recovery, rotation, and historical-data retention.
7. Avoid logging master keys, plaintext, derived private keys, or decrypted
   buffers.
8. Obtain an independent cryptographic and implementation review for sensitive
   production use.

See `examples/envelope.ts` for an executable multi-recipient example.
