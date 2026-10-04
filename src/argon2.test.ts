import { describe, expect, it } from "vite-plus/test";
import { argon2, argon2Sync } from "../index.js";

describe("Argon2", () => {
  it("should calculate argon2Sync hash", () => {
    const res = argon2Sync(Buffer.from("password"), Buffer.from("salt1234"), {
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
    expect(res).toBeDefined();
  });

  it("should calculate async argon2 hash", async () => {
    const res = await argon2(Buffer.from("password"), Buffer.from("salt1234"), {
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
    expect(res).toBeDefined();
  });
});
