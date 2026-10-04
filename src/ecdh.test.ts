import { describe, expect, it } from "vite-plus/test";
import { createEcdh } from "../index.js";

describe("ecdh", () => {
  it("generates keys and computes secret", () => {
    const alice = createEcdh("prime256v1");
    const bob = createEcdh("prime256v1");
    const alicePub = alice.generateKeys();
    const bobPub = bob.generateKeys();
    expect(alicePub.length).toBeGreaterThan(0);
    expect(bobPub.length).toBeGreaterThan(0);
    const secret = alice.computeSecret(bobPub);
    expect(secret).toBeDefined();
  });
});
