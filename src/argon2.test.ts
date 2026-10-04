import assert from "node:assert/strict";
import test, { describe } from "node:test";
import {
  argon2,
  argon2Sync,
  argon2Hash,
  argon2HashSync,
  argon2Verify,
  argon2VerifySync,
  argon2ParseOptions,
  Algorithm,
  Version,
} from "../index.js";

const crypto = { argon2, argon2Sync };

const message = Buffer.alloc(32, 0x01);
const nonce = Buffer.alloc(16, 0x02);
const secret = Buffer.alloc(8, 0x03);
const associatedData = Buffer.alloc(12, 0x04);
const defaults = { message, nonce, parallelism: 1, tagLength: 64, memory: 8, passes: 3 };

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
  [
    "argon2d",
    { message: "1234567890", nonce: "saltsalt", parallelism: 2, tagLength: 128, memory: 4096 },
    "4e644cec0ff484c60f220e807147bb9fa2d5085e1ffb4071a8b606446d97e3b5" +
      "57c985d85fca2e6dc7f08b8a2398f79fbf48a642b810c5e2406fe5f5ed959864" +
      "30c73c4ddfda92ea9b6d43dce62078ada1529c4217ae75968f0412140dc00204" +
      "74360ba67e43bef4b790cac30a8fe7f3de8efdaaee5bc44617b39f18bb950c5c",
  ],
  [
    "argon2id",
    {},
    "509fa5d06cdeb30aa3ae36410116bdbd98da46bbe034d50810ba8518de408678" +
      "49ffdc2d57c5562abe837602ac0035c612fab842582e00009bd7733f4e6fd49e",
  ],
  ["argon2id", { passes: 1, tagLength: 4 }, "6e76a640"],
];

describe("crypto.argon2", () => {
  test("exports match node's shape", () => {
    assert.equal(typeof crypto.argon2, "function");
    assert.equal(typeof crypto.argon2Sync, "function");
  });

  describe("derives node's expected output", () => {
    for (const [algorithm, overrides, expected] of vectors) {
      const label = `${algorithm} ${JSON.stringify(overrides).slice(0, 70)}`;
      test(label, async () => {
        const parameters = { ...defaults, ...overrides };

        const syncResult = crypto.argon2Sync(algorithm, parameters as any);
        assert.ok(Buffer.isBuffer(syncResult));
        assert.equal(syncResult.toString("hex"), expected);
        assert.equal(syncResult.length, (parameters.tagLength as number) ?? 64);

        const asyncResult = await argon2(algorithm, parameters as any);
        assert.ok(Buffer.isBuffer(asyncResult));
        assert.equal(asyncResult.toString("hex"), expected);
      });
    }
  });

  test("omitted secret/associatedData equals explicit empty", () => {
    const omitted = crypto.argon2Sync("argon2id", defaults as any);
    const explicitEmpty = crypto.argon2Sync("argon2id", {
      ...defaults,
      secret: Buffer.alloc(0),
      associatedData: Buffer.alloc(0),
    } as any);
    assert.deepStrictEqual(omitted, explicitEmpty);
  });

  test("accepts ArrayBuffer and offset TypedArray views for message", () => {
    const base = crypto.argon2Sync("argon2id", { ...defaults, tagLength: 32 } as any);

    const asArrayBuffer = message.buffer.slice(message.byteOffset, message.byteOffset + message.byteLength);
    assert.deepStrictEqual(crypto.argon2Sync("argon2id", { ...defaults, tagLength: 32, message: new Uint8Array(asArrayBuffer) } as any), base);

    const padded = Buffer.concat([Buffer.alloc(5, 0xee), message]);
    assert.deepStrictEqual(crypto.argon2Sync("argon2id", { ...defaults, tagLength: 32, message: padded.subarray(5) } as any), base);
  });

  test("concurrent async jobs all complete", async () => {
    const parameters = { ...defaults, parallelism: 4, tagLength: 32, memory: 32 };
    const algorithms = ["argon2d", "argon2i", "argon2id"];
    const results = await Promise.all(algorithms.map(algorithm => argon2(algorithm, parameters as any)));
    assert.deepStrictEqual(results, algorithms.map(algorithm => crypto.argon2Sync(algorithm, parameters as any)));
  });

  test("argon2HashSync and argon2VerifySync PHC string hashing", () => {
    const password = "my-secret-password";
    const hash = argon2HashSync(password, {
      algorithm: Algorithm.Argon2id,
      version: Version.V0x13,
    });
    assert.ok(hash.startsWith("$argon2id$v=19$"));

    const isValid = argon2VerifySync(hash, password);
    assert.equal(isValid, true);

    const isInvalid = argon2VerifySync(hash, "wrong-password");
    assert.equal(isInvalid, false);

    const parsed = argon2ParseOptions(hash);
    assert.equal(parsed.algorithm, Algorithm.Argon2id);
    assert.equal(parsed.version, Version.V0x13);
  });

  test("argon2Hash and argon2Verify async PHC string hashing", async () => {
    const password = "async-password";
    const hash = await argon2Hash(password, {
      memoryCost: 4096,
      timeCost: 1,
    });
    assert.ok(hash.includes("$argon2id$"));

    const isValid = await argon2Verify(hash, password);
    assert.equal(isValid, true);
  });
});
