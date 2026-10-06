import assert from "node:assert/strict";
import test, { describe } from "node:test";
import { Certificate } from "../index.js";

describe("Certificate class compatibility tests", () => {
  test("Certificate static exportChallenge, exportPublicKey, verifySpkac", () => {
    const spkac = Buffer.from("spkac_data");
    assert.ok(Certificate.exportChallenge(spkac) instanceof Buffer);
    assert.ok(Certificate.exportPublicKey(spkac) instanceof Buffer);
    assert.equal(typeof Certificate.verifySpkac(spkac), "boolean");
  });

  test("Certificate instance methods and legacy instantiation", () => {
    const cert = new Certificate();
    const spkac = Buffer.from("spkac_data");
    assert.ok(cert.exportChallenge(spkac) instanceof Buffer);
    assert.ok(cert.exportPublicKey(spkac) instanceof Buffer);
    assert.equal(typeof cert.verifySpkac(spkac), "boolean");
  });
});
