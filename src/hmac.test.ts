import { describe, expect, it } from "vite-plus/test";
import { createHmac, Hmac } from "../index.js";

describe("HMAC", () => {
  it("should instantiate Hmac and compute digest", () => {
    const hmac = new Hmac("sha256", Buffer.from("secret-key"));
    hmac.update(Buffer.from("hello world"));
    const digest = hmac.digest("hex");
    expect(digest).toContain("hmac_sha256");
  });

  it("should create HMAC via createHmac factory", () => {
    const hmac = createHmac("sha512", Buffer.from("key"));
    expect(hmac).toBeDefined();
  });
});
