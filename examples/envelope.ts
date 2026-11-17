import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { MasterKey, sealEnvelope } from "../dist/index.js";

// Generate each master key once and keep its 32 bytes in secure storage.
// A password is not a master key; strengthen passwords with Argon2id first.
const alice = new MasterKey(randomBytes(32));
const bob = new MasterKey(randomBytes(32));
const carol = new MasterKey(randomBytes(32));

// Purpose selects a deterministic X25519 child key. Include a stable entity ID
// and key version so the same master key can derive independent children.
const purpose = "repo:01932a4f-7b10-7000/encryption/key-version:1";

// Context is authenticated but public. Build it from canonical, stable values.
// The caller must supply this expected value again when opening an envelope.
const context = "repo:01932a4f-7b10-7000/path:config/prod.secrets";

const alicePublicKey = alice.encryptionPublicKey(purpose);
const bobPublicKey = bob.encryptionPublicKey(purpose);
const carolPublicKey = carol.encryptionPublicKey(purpose);

// Encrypt the payload once with a fresh random DEK, then wrap that DEK for
// Alice and Bob independently.
const envelope = sealEnvelope(context, Buffer.from("DATABASE_URL=postgres://prod"), [
  alicePublicKey,
  bobPublicKey,
]);

assert.equal(
  alice.open(purpose, context, envelope).toString("utf8"),
  "DATABASE_URL=postgres://prod",
);
assert.equal(bob.open(purpose, context, envelope).toString("utf8"), "DATABASE_URL=postgres://prod");

// Supplying a different expected context rejects a copied envelope.
assert.throws(() => alice.open(purpose, "repo:other/path:config/prod.secrets", envelope));

// Any existing recipient can delegate access by adding another wrapped DEK.
// Enforce administrator authorization in the application before calling this.
const withCarol = alice.addRecipient(purpose, context, envelope, carolPublicKey);
assert.equal(
  carol.open(purpose, context, withCarol).toString("utf8"),
  "DATABASE_URL=postgres://prod",
);

// Rotation creates a new DEK and ciphertext for the replacement recipient set.
// Bob and Carol can still decrypt historical copies they previously received.
const aliceOnly = alice.rotateRecipients(purpose, context, withCarol, [alicePublicKey]);
assert.equal(
  alice.open(purpose, context, aliceOnly).toString("utf8"),
  "DATABASE_URL=postgres://prod",
);
assert.throws(() => bob.open(purpose, context, aliceOnly));
assert.throws(() => carol.open(purpose, context, aliceOnly));

console.log("Envelope example completed successfully.");
