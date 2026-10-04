import { describe, expect, it } from "vite-plus/test";
import { randomBytes, randomInt, randomUuid, randomUuidv7 } from "../index.js";

describe("Random", () => {
  it("should generate random bytes", () => {
    const bytes = randomBytes(16);
    expect(bytes.length).toBe(16);
  });

  it("should generate random int within range", () => {
    const val = randomInt(10, 20);
    expect(val).toBeGreaterThanOrEqual(10);
    expect(val).toBeLessThan(20);
  });

  it("should generate UUID v4 and v7", () => {
    expect(randomUuid()).toContain("-4000-");
    expect(randomUuidv7()).toContain("-7000-");
  });
});
