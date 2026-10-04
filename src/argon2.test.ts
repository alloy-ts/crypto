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

const message = Buffer.alloc(32, 0x01);
const nonce = Buffer.alloc(16, 0x02);
const secret = Buffer.alloc(8, 0x03);
const associatedData = Buffer.alloc(12, 0x04);
const defaults = { message, nonce, parallelism: 1, tagLength: 32, memory: 32, passes: 3 };

describe("crypto.argon2 native module tests", () => {
  test("argon2Sync returns raw digest buffer", () => {
    const raw = argon2Sync("argon2id", defaults);
    assert.ok(Buffer.isBuffer(raw));
    assert.equal(raw.length, 32);
  });

  test("argon2 async returns raw digest buffer", async () => {
    const raw = await argon2("argon2id", defaults);
    assert.ok(Buffer.isBuffer(raw));
    assert.equal(raw.length, 32);
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
