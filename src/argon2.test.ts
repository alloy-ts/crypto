import assert from "node:assert/strict";
import { describe, test } from "node:test";
import crypto, { argon2, argon2Sync } from "../index.js";

const message = Buffer.alloc(32, 0x01);
const nonce = Buffer.alloc(16, 0x02);
const secret = Buffer.alloc(8, 0x03);
const associatedData = Buffer.alloc(12, 0x04);
const defaults = { message, nonce, parallelism: 1, tagLength: 64, memory: 8, passes: 3 };

function argon2Async(algorithm: string, parameters: Record<string, unknown>): Promise<Buffer> {
  return (crypto as any).argon2(algorithm, parameters);
}

// Test vectors generated against Node.js crypto.argon2 / crypto.argon2Sync
const vectors: [algorithm: string, overrides: Record<string, unknown>, expectedHex: string][] = [
  [
    "argon2d",
    { secret, associatedData, parallelism: 4, tagLength: 32, memory: 32 },
    "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
  ],
  [
    "argon2i",
    { secret, associatedData, parallelism: 4, tagLength: 32, memory: 32 },
    "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
  ],
  [
    "argon2id",
    { secret, associatedData, parallelism: 4, tagLength: 32, memory: 32 },
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
  ],
  [
    "argon2d",
    { message: "1234567890", nonce: "saltsalt" },
    "d16ad773b1c6400d3193bc3e66271603e9de72bace20af3f89c236f5434cdec9" +
      "9072ddfc6b9c77ea9f386c0e8d7cb0c37cec6ec3277a22c92d5be58ef67c7eaa",
  ],
  [
    "argon2id",
    { message: "", parallelism: 4, tagLength: 32, memory: 32 },
    "0a34f1abde67086c82e785eaf17c68382259a264f4e61b91cd2763cb75ac189a",
  ],
  [
    "argon2d",
    { message: "1234567890", nonce: "saltsalt", parallelism: 2, memory: 4096 },
    "491760c694fe6a7c94ab4e6a6344b55115565a6dbb3e078567b3f75c92a6dc5d" +
      "03e823078bfa9811e7be1cc94fa2d9d167ab316aada7d846845ac288aa7e07c7",
  ],
  [
    "argon2i",
    { parallelism: 4, tagLength: 32, memory: 32 },
    "a9a7510e6db4d588ba3414cd0e094d480d683f97b9ccb612a544fe8ef65ba8e0",
  ],
  [
    "argon2id",
    { parallelism: 4, tagLength: 32, memory: 32 },
    "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e",
  ],
  ["argon2id", { passes: 1, tagLength: 4 }, "6e76a640"],
];

describe("crypto.argon2", () => {
  test("exports match node's shape", () => {
    assert.equal(typeof (crypto as any).argon2, "function");
    assert.equal(typeof (crypto as any).argon2Sync, "function");
  });

  test("crypto.argon2 accepts callback (err, derivedKey)", (done) => {
    argon2("argon2id", defaults, (err: Error | null, derivedKey: Buffer) => {
      assert.equal(err, null);
      assert.equal(Buffer.isBuffer(derivedKey), true);
      assert.equal(derivedKey.length, 64);
      done();
    });
  });

  describe("derives node's expected output", () => {
    for (const [algorithm, overrides, expected] of vectors) {
      const label = `${algorithm} ${JSON.stringify(overrides).slice(0, 70)}`;
      test(label, async () => {
        const parameters = { ...defaults, ...overrides };

        const syncResult = (crypto as any).argon2Sync(algorithm, parameters);
        assert.equal(Buffer.isBuffer(syncResult), true);
        assert.equal(syncResult.toString("hex"), expected);
        assert.equal(syncResult.length, (parameters.tagLength as number) ?? 64);

        const asyncResult = await argon2Async(algorithm, parameters);
        assert.equal(Buffer.isBuffer(asyncResult), true);
        assert.equal(asyncResult.toString("hex"), expected);
      });
    }
  });

  test("omitted secret/associatedData equals explicit empty", () => {
    const omitted = (crypto as any).argon2Sync("argon2id", defaults);
    const explicitEmpty = (crypto as any).argon2Sync("argon2id", {
      ...defaults,
      secret: Buffer.alloc(0),
      associatedData: Buffer.alloc(0),
    });
    assert.deepEqual(omitted, explicitEmpty);
  });

  test("accepts ArrayBuffer and string inputs for secret and associatedData", () => {
    const res = (crypto as any).argon2Sync("argon2id", {
      ...defaults,
      secret: "pepper",
      associatedData: "extra-data",
    });
    assert.equal(Buffer.isBuffer(res), true);
  });

  test("validates required parameters and throws error on missing or invalid fields", () => {
    // Missing message
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, message: undefined });
    });

    // Missing nonce
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, nonce: undefined });
    });

    // Short nonce (< 8 bytes)
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, nonce: Buffer.alloc(4) });
    });

    // Invalid parallelism (< 1)
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, parallelism: 0 });
    });

    // Invalid tagLength (< 4)
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, tagLength: 2 });
    });

    // Invalid memory (< 8 * parallelism)
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, parallelism: 4, memory: 16 });
    });

    // Invalid passes (< 1)
    assert.throws(() => {
      (crypto as any).argon2Sync("argon2id", { ...defaults, passes: 0 });
    });
  });
});
