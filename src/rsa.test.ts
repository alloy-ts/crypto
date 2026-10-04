import assert from "node:assert/strict";
import test, { describe, before } from "node:test";
import crypto, {
  generateKeyPairSync,
  generateKeyPair,
  publicEncrypt,
  privateDecrypt,
  privateEncrypt,
  publicDecrypt,
} from "../index.js";

const rsaPair = generateKeyPairSync("rsa");
const rsaPubPem = rsaPair.publicKey.toString("utf8");
const rsaKeyPem = rsaPair.privateKey.toString("utf8");

describe("RSA Key Generation Tests", () => {
  test("generateKeyPairSync Ed25519", () => {
    const pair = generateKeyPairSync("ed25519");
    assert.ok(pair.publicKey.length > 0);
    assert.ok(pair.privateKey.length > 0);
  });

  test("generateKeyPair async P-256", async () => {
    const pair = await generateKeyPair("p256");
    assert.ok(pair.publicKey.length > 0);
    assert.ok(pair.privateKey.length > 0);
  });
});

describe("RSA encryption/decryption", () => {
  const input = "I AM THE WALRUS";
  const bufferToEncrypt = Buffer.from(input);

  let encryptedBuffer: Buffer;
  let otherEncrypted: Buffer;

  before(() => {
    encryptedBuffer = publicEncrypt(rsaPubPem, bufferToEncrypt);

    otherEncrypted = publicEncrypt(
      {
        key: rsaPubPem,
      },
      bufferToEncrypt,
    );
  });

  test("privateDecrypt with rsaKeyPem", () => {
    const decryptedBuffer = privateDecrypt(rsaKeyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });

  test("privateDecrypt with otherEncrypted", () => {
    const otherDecrypted = privateDecrypt(rsaKeyPem, otherEncrypted);
    assert.equal(otherDecrypted.toString(), input);
  });

  test("publicEncrypt and privateDecrypt with keyPem", () => {
    const enc = publicEncrypt(rsaPubPem, bufferToEncrypt);
    const dec = privateDecrypt(rsaKeyPem, enc);
    assert.equal(dec.toString(), input);
  });

  test("privateEncrypt and publicDecrypt with keyPem", () => {
    const enc = privateEncrypt(rsaKeyPem, bufferToEncrypt);
    const dec = publicDecrypt(rsaKeyPem, enc);
    assert.equal(dec.toString(), input);
  });
});

test("RSA test vectors basic encryption/decryption roundtrip", () => {
  const msg = Buffer.from("Hello Node.js");
  const enc = publicEncrypt(rsaPubPem, msg);
  const dec = privateDecrypt(rsaKeyPem, enc);
  assert.equal(dec.toString("utf8"), "Hello Node.js");
});
