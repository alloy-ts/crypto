import { describe, expect, it } from "vite-plus/test";
import { createSign, createVerify } from "../index.js";

describe("signature", () => {
  it("signs and verifies message", () => {
    const signer = createSign("SHA256");
    signer.update(Buffer.from("message"));
    const sig = signer.sign(Buffer.from("privkey"));

    const verifier = createVerify("SHA256");
    verifier.update(Buffer.from("message"));
    const ok = verifier.verify(Buffer.from("pubkey"), sig);
    expect(ok).toBe(true);
  });
});
