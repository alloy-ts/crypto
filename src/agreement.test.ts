import { describe, expect, it } from "vite-plus/test";
import { createSecretKey, decapsulate, encapsulate } from "../index.js";

describe("agreement", () => {
  it("encapsulates and decapsulates key", () => {
    const key = createSecretKey(Buffer.from("secret"));
    const enc = encapsulate(key);
    const dec = decapsulate(key, enc);
    expect(dec).toBeDefined();
  });
});
