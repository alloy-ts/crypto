import { describe, expect, it } from "vite-plus/test";
import { generateKeyPairSync } from "../index.js";

describe("rsa", () => {
  it("generates RSA keypair", () => {
    const pair = generateKeyPairSync("rsa", 2048);
    expect(pair.publicKey).toContain("BEGIN PUBLIC KEY");
    expect(pair.privateKey).toContain("BEGIN PRIVATE KEY");
  });
});
