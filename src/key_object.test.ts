import { describe, expect, it } from "vite-plus/test";
import { KeyObject, X509Certificate } from "../index.js";

describe("key_object", () => {
  it("exports key object material", () => {
    const key = new KeyObject("secret");
    const bytes = key.export();
    expect(bytes).toBeDefined();
  });

  it("parses X509 certificate subject", () => {
    const cert = new X509Certificate(Buffer.from("cert-data"));
    expect(cert.subject()).toContain("CN=Subject_");
  });
});
