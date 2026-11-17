# Starter Template

## Envelope encryption API

The Node API exports `MasterKey` and `sealEnvelope`. Existing `CryptoKey`
SLIP-0010 signing behavior is unchanged. The new HKDF derivation is a separate
protocol and produces different keys.

```ts
import { randomBytes } from "node:crypto";
import { MasterKey, sealEnvelope } from "./dist/index.js";

// Generate once, then back up securely. Never use a password directly.
const master = new MasterKey(randomBytes(32));
const purpose = "repo:immutable-id/encryption/key-version:1";
const context = "repo:immutable-id/path:secrets.env";
const publicKey = master.encryptionPublicKey(purpose);
const envelope = sealEnvelope(context, Buffer.from("secret"), [publicKey]);
const plaintext = master.open(purpose, context, envelope);
```

`signingPublicKey(purpose)` and `signChild(purpose, message)` use Ed25519.
Encryption keys use X25519. HKDF-SHA256 separates these domains. Use stable,
unambiguous purpose identifiers including entity and key version; store those
identifiers because restoring the master secret alone does not recover them.
Master secrets and temporary derived keys are zeroized on Rust drop; input
Buffers and returned plaintext remain under the caller's memory management.

Each envelope uses a fresh random DEK and a 24-byte XChaCha20-Poly1305 nonce.
Each recipient receives an independently wrapped DEK via ephemeral X25519,
HKDF-SHA256 and XChaCha20-Poly1305. Non-contributory exchanges are rejected.
The protocol is a custom construction, not RFC 9180 HPKE. A separate HKDF-derived
HMAC-SHA256 key authenticates the full ordered recipient list and ciphertext.
The version and suite are fixed and authenticated. Recipient IDs are full
domain-separated SHA-256 public-key hashes.

JSON is transport only: authentication uses an ordered binary transcript with
unsigned 64-bit big-endian length prefixes. Parsers reject unknown/duplicate
fields, invalid fixed lengths, unknown versions/suites, and duplicate or unsorted
recipients. Limits: 256 recipients, 4096 UTF-8 context bytes, 16 MiB plaintext,
80 MiB JSON. Parsing is bounded by total input size; this API is not streaming.

Always supply the independently expected context to `open`, `addRecipient`, and
`rotateRecipients`; never trust the context read from the envelope itself.
Context strings and recipient identifiers are public. Bind paths using your
application's canonical path rules. Context binding does not prevent replay of
an older valid envelope at the same path; use trusted version state if needed.

`master.addRecipient(purpose, context, envelope, publicKey)` preserves ciphertext
and recomputes the metadata MAC. Every recipient can delegate or rewrite the
envelope; this MAC authenticates membership to DEK holders, not sender identity
or administrator approval. Authenticate recipient public keys externally and
enforce collaboration policy in the application. Use trusted signatures if
sender identity or administrator authorization is required.

`master.rotateRecipients(purpose, context, envelope, publicKeys)` decrypts and
re-encrypts with a fresh DEK for the replacement recipient list. Removed members
cannot decrypt the new envelope but retain access to historical copies. Static
recipient key compromise permits decryption of recorded envelopes; there is no
forward secrecy. IPC sessions needing forward secrecy require a session protocol.

This implementation has security tests but has not had an independent audit.

Starter Template for Rust + TypeScript via NAPI-RS, Node-API (N-API) bindings.

## Getting Started

1. Clone the repo
2. Install dependencies
3. Run the application

```bash
git clone https://repo.chen.software/yumin-chen/repo.git
cd starter-template
npm install
npm run start
```

## Running the application

```bash
npm run start
```

## Testing the application

```bash
npm run test
```
