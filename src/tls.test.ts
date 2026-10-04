import { describe, expect, it } from "vite-plus/test";
import { TLS } from "../index.js";

describe("tls", () => {
  it("defaults to ring provider", () => {
    const tls = new TLS();
    expect(tls.getProvider()).toBe("ring");
  });
});
