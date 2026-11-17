import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { MasterKey, sealEnvelope } from "../../dist/index.js";

void test("envelopes enforce context, integrity, delegation and rotation through Node", () => {
  const alice = new MasterKey(Buffer.alloc(32, 1));
  const bob = new MasterKey(Buffer.alloc(32, 2));
  const purpose = "repo:1/encryption/v1";
  const context = "repo:1/secrets.env";
  const alicePublic = alice.encryptionPublicKey(purpose);
  const bobPublic = bob.encryptionPublicKey(purpose);
  const envelope = sealEnvelope(context, Buffer.from("secret"), [alicePublic]);
  assert.equal(alice.open(purpose, context, envelope).toString(), "secret");
  assert.throws(() => bob.open(purpose, context, envelope));
  assert.throws(() => alice.open(purpose, "repo:2/secrets.env", envelope));
  const added = alice.addRecipient(purpose, context, envelope, bobPublic);
  assert.equal(bob.open(purpose, context, added).toString(), "secret");
  const rotated = alice.rotateRecipients(purpose, context, added, [alicePublic]);
  assert.equal(alice.open(purpose, context, rotated).toString(), "secret");
  assert.throws(() => bob.open(purpose, context, rotated));
  assert.throws(() => sealEnvelope(context, Buffer.from("x"), [Buffer.alloc(32)]));
  assert.throws(() => sealEnvelope(context, Buffer.from("x"), [alicePublic, alicePublic]));
  assert.throws(() => new MasterKey(Buffer.alloc(31)));
  assert.throws(() => alice.open(purpose, context, "{}"));
});

void test("derived Ed25519 signatures verify with Node's independent implementation", () => {
  const master = new MasterKey(Buffer.alloc(32, 7));
  const purpose = "device:1/signing/v1";
  const message = Buffer.from("signed message");
  const publicKey = createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      master.signingPublicKey(purpose),
    ]),
    format: "der",
    type: "spki",
  });
  assert(verify(null, message, publicKey, master.signChild(purpose, message)));
  assert(!verify(null, Buffer.from("tampered"), publicKey, master.signChild(purpose, message)));
});
