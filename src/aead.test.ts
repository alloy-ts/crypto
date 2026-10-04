import { describe, expect, it } from "vite-plus/test";
import { Cipher, createCipheriv } from "../index.js";

describe("aead", () => {
  it("creates cipher and updates data", () => {
    const cipher = createCipheriv("aes-256-gcm", Buffer.alloc(32), Buffer.alloc(12));
    expect(cipher).toBeInstanceOf(Cipher);
    const res = cipher.update(Buffer.from("data"));
    expect(res).toBeDefined();
  });
});
