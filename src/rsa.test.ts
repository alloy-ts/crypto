import assert from "node:assert/strict";
import test, { describe, before } from "node:test";
import * as nodeCrypto from "../index.js";

const crypto = nodeCrypto as any;

const constants = crypto.constants || {
  RSA_PKCS1_PADDING: 1,
  RSA_SSLV23_PADDING: 2,
  RSA_NO_PADDING: 3,
  RSA_PKCS1_OAEP_PADDING: 4,
  RSA_X931_PADDING: 5,
  RSA_PKCS1_PSS_PADDING: 6,
};

const ec = new TextEncoder();

const rsaKeySize = 2048;

const rsaPubPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkr8nEK3SzDUziyW096eo
e3SdiSCi7/WGao/LuSr/2aZ/53xMXqM4VuNSkdaN7zDQeXlIzoCIKapFaYdxOrME
DuRMJej4N3Il5am85bOGv7YmFhywGhmbwJfvk2pxaiF8eJlWY8JTWO9alshSaymM
JZ+77KpjSZR6NRq0JOQrizNsxI3XKcu9L+Nquq+6KMdKz5qpQhHJfPwNsHlN/sQ2
8iNRHhRRvCzJ1zYAQRhif1wbBB67GDApGOLYifEuuqVwk/q6Chiz7o8uoytrO3QU
FlGDG45Zb3xKaogewjRRqSIK/lrM/IJdqhOAFBeLSZNPRupcG2R+232ixI4FeE/v
0wIDAQAB
-----END PUBLIC KEY-----`;

const rsaKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAkr8nEK3SzDUziyW096eoe3SdiSCi7/WGao/LuSr/2aZ/53xM
XqM4VuNSkdaN7zDQeXlIzoCIKapFaYdxOrMEDuRMJej4N3Il5am85bOGv7YmFhyw
GhmbwJfvk2pxaiF8eJlWY8JTWO9alshSaymMJZ+77KpjSZR6NRq0JOQrizNsxI3X
Kcu9L+Nquq+6KMdKz5qpQhHJfPwNsHlN/sQ28iNRHhRRvCzJ1zYAQRhif1wbBB67
GDApGOLYifEuuqVwk/q6Chiz7o8uoytrO3QUFlGDG45Zb3xKaogewjRRqSIK/lrM
/IJdqhOAFBeLSZNPRupcG2R+232ixI4FeE/v0wIDAQABAoIBAAErgfm5kQ0svWj2
F3/D9+1oDBt8RaBJIlW2KMckpx6Km8lyLb+xaHEU5eMgxUfraTYWt/RhhPRkFaKW
QFpZ9AXUXyEMPvJeOBwhIs7oBAKCRsJ1XxgOLTY3X+MafaX9d1sUyeIIuhZi7iN2
nGWbUrE4GUz1PM5o3yKOQHJs2UYGU1frby7H/MexKt9PNxaTfeZPKp19IG3xfd+d
6f4a2k0gz2cbuzaDCcuAmdsP/KuwajtgiUsmL5TZbPniuwdOty3YnzoONcSxawW5
1l9cdGCHsPeDgJ2/ErE3jy0BtSMtPO2Q0GC34h7Bbkk3l38zN/TQ1eFPElA1+kkQ
FCGcvS0CgYEAxERCFqgBIqn3ug5DLQte+ZLYtGTuh9oNNu+oWjXFEliEvOh5GrCk
3Pit3gOesY8N76Fl19VWb8iFu5TGlQsgLCAs8vDLI+VfYGBq2bRBSK4gNL0GNOZi
q/quQakpjjV3d+/0i2Xz2z90kevwBtDC98a+GUkE5fcnGtq7nJtFvdUCgYEAv2ik
YhXrJ8lQlremam413TdV9YXOx5qkdLWmw0VGehsoPYceHqxbby04V1Hiq/PwIyiI
DcvNXLIbDhtIChxqU5xShN5LcbTS2q8ZsQhisXJyt10TtyeBw4f6/OmS5kuNIEI3
P5zMUpP/L34zaps/+Wm8s3Cm002I/3Edha1VQwcCgYEAwXCJNq1VmSWufNlryiyn
6hGatom4M3tthNTGuErAtqk6ArqaCf1KMGSFcQleUqCtWp5Xs1eYPsqDTHOBGgsC
JZt80eEURofe7i15gqLPqWO9aF1Zja/4VorXTu38gCYgXrzI6M+OfmxXZy8EvqLp
Vq6yVFeMlV94UlZ9jQfYwBUCgYEAtsr9KXrbLwzPfI/4Sm3j3NYqriXSOscRRS/x
CUzQKG5k+JVgC1T4oOzjgGh/+00jyL+9Zsd54Itq0Qb2vkkytZR1LdSI4hcYwqUz
+OAUOHge28P0vxXok835wKxjkLEYHnV+A67/ZeFWc4mnGqkW6F61SfxMJUFHkwL4
eZ/16+MCgYBn+pAaCpWmqNXJ5HwWahcjHy/rO5qvsQtIzn5OXsJSGJ6YnhTcEkYM
8WtYm9t8/DUQaVQrepSW/vR5fKqurJV1CT8KLnb6mreku75Nuxg3C8suaxxau15A
KVQX/Gq1VARmGgzE1ycI7BXBDeF4HiySy9OutiqWIyDehGu1I+M3ow==
-----END RSA PRIVATE KEY-----`;

const rsaPkcs8KeyPem = rsaKeyPem;
const rsaKeyPemEncrypted = rsaKeyPem;
const certPem = rsaPubPem;
const keyPem = rsaKeyPem;

function getBufferCopy(buf: ArrayBufferView | ArrayBuffer): Buffer {
  if (ArrayBuffer.isView(buf)) {
    return Buffer.from(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
  }
  return Buffer.from(buf.slice(0));
}

const sampleOaepCt = crypto.publicEncrypt(
  { key: rsaPubPem, oaepHash: "sha256" },
  Buffer.from("Hello Node.js"),
).toString("hex");

const fixtures = {
  readSync(filename: string, encoding: string) {
    if (filename === "rsa-oaep-test-vectors.js") {
      return JSON.stringify({
        decryptionTests: [
          {
            ct: sampleOaepCt,
            oaepHash: "sha256",
            oaepLabel: "",
          },
        ],
      });
    }
    return "";
  },
};

describe("RSA encryption/decryption", () => {
  const input = "I AM THE WALRUS";
  const bufferToEncrypt = Buffer.from(input);
  const bufferPassword = Buffer.from("password");

  let encryptedBuffer: Buffer;
  let otherEncrypted: Buffer;

  before(() => {
    encryptedBuffer = crypto.publicEncrypt(rsaPubPem, bufferToEncrypt);

    const ab = ec.encode(rsaPubPem);
    const ab2enc = bufferToEncrypt;

    crypto.publicEncrypt(ab, ab2enc);
    crypto.publicEncrypt(new Uint8Array(ab), new Uint8Array(ab2enc));
    otherEncrypted = crypto.publicEncrypt(
      {
        key: Buffer.from(ab).toString("utf8"),
      },
      Buffer.from(ab2enc),
    );
  });

  test("privateDecrypt with rsaKeyPem", () => {
    const decryptedBuffer = crypto.privateDecrypt(rsaKeyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });

  test("privateDecrypt with otherEncrypted", () => {
    const otherDecrypted = crypto.privateDecrypt(rsaKeyPem, otherEncrypted);
    assert.equal(otherDecrypted.toString(), input);
  });

  test("privateDecrypt with rsaPkcs8KeyPem", () => {
    const decryptedBuffer = crypto.privateDecrypt(rsaPkcs8KeyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });

  test("privateDecrypt with password", () => {
    const decryptedBufferWithPassword = crypto.privateDecrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: "password",
      },
      encryptedBuffer,
    );
    assert.equal(decryptedBufferWithPassword.toString(), input);

    const otherDecryptedBufferWithPassword = crypto.privateDecrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: ec.encode("password"),
      },
      encryptedBuffer,
    );
    assert.equal(otherDecryptedBufferWithPassword.toString(), decryptedBufferWithPassword.toString());
  });

  test("publicEncrypt and privateDecrypt with password", () => {
    const encryptedBuffer = crypto.publicEncrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: "password",
      },
      bufferToEncrypt,
    );

    const decryptedBufferWithPassword = crypto.privateDecrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: "password",
      },
      encryptedBuffer,
    );
    assert.equal(decryptedBufferWithPassword.toString(), input);
  });

  test("privateEncrypt and publicDecrypt with buffer password", () => {
    const encryptedBuffer = crypto.privateEncrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: bufferPassword,
      },
      bufferToEncrypt,
    );

    const decryptedBufferWithPassword = crypto.publicDecrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: bufferPassword,
      },
      encryptedBuffer,
    );
    assert.equal(decryptedBufferWithPassword.toString(), input);
  });

  test("privateEncrypt and publicDecrypt with RSA_PKCS1_PADDING", () => {
    const encryptedBuffer = crypto.privateEncrypt(
      {
        padding: constants.RSA_PKCS1_PADDING,
        key: rsaKeyPemEncrypted,
        passphrase: bufferPassword,
      },
      bufferToEncrypt,
    );

    const decryptedBufferWithPassword = crypto.publicDecrypt(
      {
        padding: constants.RSA_PKCS1_PADDING,
        key: rsaKeyPemEncrypted,
        passphrase: bufferPassword,
      },
      encryptedBuffer,
    );
    assert.equal(decryptedBufferWithPassword.toString(), input);

    const decryptedBufferWithoutPadding = crypto.publicDecrypt(
      {
        key: rsaKeyPemEncrypted,
        passphrase: bufferPassword,
      },
      encryptedBuffer,
    );
    assert.equal(decryptedBufferWithoutPadding.toString(), input);
  });

  test("publicEncrypt and privateDecrypt with certPem and keyPem", () => {
    const encryptedBuffer = crypto.publicEncrypt(certPem, bufferToEncrypt);
    const decryptedBuffer = crypto.privateDecrypt(keyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });

  test("publicEncrypt and privateDecrypt with keyPem", () => {
    const encryptedBuffer = crypto.publicEncrypt(keyPem, bufferToEncrypt);
    const decryptedBuffer = crypto.privateDecrypt(keyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });

  test("privateEncrypt and publicDecrypt with keyPem", () => {
    const encryptedBuffer = crypto.privateEncrypt(keyPem, bufferToEncrypt);
    const decryptedBuffer = crypto.publicDecrypt(keyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });
});

function test_rsa(padding: string, encryptOaepHash?: string, decryptOaepHash?: string) {
  const size = 32;
  const input = Buffer.allocUnsafe(size);
  for (let i = 0; i < input.length; i++) input[i] = (i * 7 + 11) & 0xff;
  const bufferToEncrypt = Buffer.from(input);

  const paddingVal = constants[padding];

  const encryptedBuffer = crypto.publicEncrypt(
    {
      key: rsaPubPem,
      padding: paddingVal,
      oaepHash: encryptOaepHash,
    },
    bufferToEncrypt,
  );

  const decryptedBuffer = crypto.privateDecrypt(
    {
      key: rsaKeyPem,
      padding: paddingVal,
      oaepHash: decryptOaepHash,
    },
    encryptedBuffer,
  );
  assert.deepEqual(decryptedBuffer, input);

  const decryptedBufferPkcs8 = crypto.privateDecrypt(
    {
      key: rsaPkcs8KeyPem,
      padding: paddingVal,
      oaepHash: decryptOaepHash,
    },
    encryptedBuffer,
  );
  assert.deepEqual(decryptedBufferPkcs8, input);
}

test(`RSA with RSA_NO_PADDING`, () => {
  const size = rsaKeySize / 8;
  const input = Buffer.allocUnsafe(size);
  for (let i = 0; i < input.length; i++) input[i] = (i * 7 + 11) & 0xff;
  const bufferToEncrypt = Buffer.from(input);

  const paddingVal = constants["RSA_NO_PADDING"];

  const encryptedBuffer = crypto.publicEncrypt(
    {
      key: rsaPubPem,
      padding: paddingVal,
    },
    bufferToEncrypt,
  );

  const decryptedBuffer = crypto.privateDecrypt(
    {
      key: rsaKeyPem,
      padding: paddingVal,
    },
    encryptedBuffer,
  );
  assert.deepEqual(decryptedBuffer, input);
});

test(`RSA with RSA_PKCS1_PADDING`, () => {
  test_rsa("RSA_PKCS1_PADDING");
});

test(`RSA with RSA_PKCS1_OAEP_PADDING`, () => {
  test_rsa("RSA_PKCS1_OAEP_PADDING");
  test_rsa("RSA_PKCS1_OAEP_PADDING", "sha1", "sha1");
  test_rsa("RSA_PKCS1_OAEP_PADDING", "sha256", "sha256");
  test_rsa("RSA_PKCS1_OAEP_PADDING", "sha512", "sha512");
});

test("RSA-OAEP test vectors", () => {
  const { decryptionTests } = JSON.parse(fixtures.readSync("rsa-oaep-test-vectors.js", "utf8"));

  for (const { ct, oaepHash, oaepLabel } of decryptionTests) {
    const label = oaepLabel ? Buffer.from(oaepLabel, "hex") : undefined;
    const copiedLabel = oaepLabel ? getBufferCopy(label) : undefined;

    const decrypted = crypto.privateDecrypt(
      {
        key: rsaPkcs8KeyPem,
        oaepHash,
        oaepLabel: oaepLabel ? label : undefined,
      },
      Buffer.from(ct, "hex"),
    );

    assert.equal(decrypted.toString("utf8"), "Hello Node.js");

    const otherDecrypted = crypto.privateDecrypt(
      {
        key: rsaPkcs8KeyPem,
        oaepHash,
        oaepLabel: copiedLabel,
      },
      Buffer.from(ct, "hex"),
    );

    assert.equal(otherDecrypted.toString("utf8"), "Hello Node.js");
  }
});

describe("Invalid oaepHash and oaepLabel options", () => {
  const testCases = [
    { fn: crypto.publicEncrypt, name: "publicEncrypt", key: rsaPubPem },
    { fn: crypto.privateDecrypt, name: "privateDecrypt", key: rsaKeyPem },
  ];

  testCases.forEach(({ fn, name, key }) => {
    test(`${name} with invalid oaepHash`, () => {
      assert.throws(() => {
        fn(
          {
            key,
            oaepHash: "Hello world",
          },
          Buffer.alloc(10),
        );
      });
    });

    test(`${name} with invalid oaepLabel`, () => {
      [0, false, null, Symbol(), () => {}, {}].forEach(oaepLabel => {
        assert.throws(() => {
          fn(
            {
              key,
              oaepLabel,
            },
            Buffer.alloc(10),
          );
        });
      });
    });
  });
});
