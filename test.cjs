const assert = require("node:assert/strict");
const test = require("node:test");

const { createHash, createHmac, pbkdf2Sync, TLS, Certificate } = require("./index.js");

test("test.cjs re-exports work", () => {
  const hash = createHash("sha256").update("hello").digest("hex");
  assert.equal(typeof hash, "string");

  const hmac = createHmac("sha256", "key").update("data").digest("hex");
  assert.equal(typeof hmac, "string");

  const key = pbkdf2Sync("password", "salt", 10, 16, "sha256");
  assert.equal(key.length, 16);

  const tls = new TLS();
  assert.equal(tls.providerName, "ring");

  assert.equal(typeof Certificate.exportChallenge, "function");
  assert.equal(typeof Certificate.exportPublicKey, "function");
  assert.equal(typeof Certificate.verifySpkac, "function");
});
