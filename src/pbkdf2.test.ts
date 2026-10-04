import { describe, expect, it } from "vite-plus/test";
import { pbkdf2, pbkdf2Sync } from "../index.js";

describe("pbkdf2", () => {
  it("pbkdf2Sync derives key", () => {
    const res = pbkdf2Sync(Buffer.from("pass"), Buffer.from("salt"), 1000, 32, "sha256");
    expect(res.length).toBe(32);
  });

  it("pbkdf2 derives key asynchronously", async () => {
    const res = await pbkdf2(Buffer.from("pass"), Buffer.from("salt"), 1000, 32, "sha256");
    expect(res.length).toBe(32);
  });
});
