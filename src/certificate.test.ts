import assert from "node:assert/strict";
import test, { describe } from "node:test";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const native = require("../lib-crypto.node");

const { Certificate, X509Certificate } = native;

describe("Certificate (SPKAC)", () => {
  const dummySpkac =
    "MICbMIGSMIGMAoGBAM77D9uT+7/mQvF8v1234567890abcdefghijklmnopqrstuvwxyz" +
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890123456789012345678901234567890" +
    "AgMBAAEWCENoYWxsZW5nZTANBgkqhkiG9w0BAQQFAAOBgQAn9876543210fedcba";

  test("Certificate static and instance methods", () => {
    assert.equal(typeof Certificate.exportChallenge, "function");
    assert.equal(typeof Certificate.exportPublicKey, "function");
    assert.equal(typeof Certificate.verifySpkac, "function");

    const isVerified = Certificate.verifySpkac(dummySpkac);
    assert.equal(typeof isVerified, "boolean");

    const certInstance = new Certificate();
    assert.ok(certInstance instanceof Certificate);
  });
});

describe("X509Certificate", () => {
  const sampleCertPem =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBvzCCASagAwIBAgIUQgM3u009vM83+k+R91x0v96f8b0wDQYJKoZIhvcNAQEL\n" +
    "BQAwRTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExITAfBgNVBAoM\n" +
    "GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMDEwMDAwMDBaFw0zNDAx\n" +
    "MDEwMDAwMDBaMEUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMSEw\n" +
    "HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwgZ8wDQYJKoZIhvcNAQEBBQAD\n" +
    "gY0AMIGJAoGBAL7O9/x1s2t34567890abcdefghijklmnopqrstuvwxyz0123456\n" +
    "7890123456789012345678901234567890123456789012345678901234567890\n" +
    "AgMBAAEwDQYJKoZIhvcNAQELBQADgYEAC09876543210fedcba9876543210fedc\n" +
    "ba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedc\n" +
    "-----END CERTIFICATE-----\n";

  test("X509Certificate properties and getters", () => {
    const x509 = new X509Certificate(Buffer.from(sampleCertPem));
    assert.ok(x509 instanceof X509Certificate);
    assert.equal(typeof x509.subject, "string");
    assert.equal(typeof x509.issuer, "string");
    assert.equal(typeof x509.fingerprint, "string");
    assert.equal(typeof x509.fingerprint256, "string");
    assert.equal(typeof x509.fingerprint512, "string");
    assert.ok(Buffer.isBuffer(x509.raw));
    assert.equal(typeof x509.toString(), "string");
    assert.equal(typeof x509.toJSON(), "string");
  });
});
