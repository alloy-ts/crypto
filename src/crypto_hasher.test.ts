import { describe, expect, it } from "vite-plus/test";
import { getHashes, Hash } from "../index.js";

describe("crypto_hasher", () => {
  it("getHashes returns array", () => {
    const hashes = getHashes();
    expect(Array.isArray(hashes)).toBe(true);
    expect(hashes).toContain("sha256");
  });

  it("Hash class digests correctly", () => {
    const hash = new Hash("sha256");
    hash.update(Buffer.from("hello"));
    expect(hash.digest("hex")).toContain("hash_sha256");
  });
});
