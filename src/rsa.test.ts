import assert from 'node:assert/strict'
import test, { describe, before } from 'node:test'
import crypto, {
  generateKeyPairSync,
  generateKeyPair,
  publicEncrypt,
  privateDecrypt,
  privateEncrypt,
  publicDecrypt,
} from '../index.js'

describe('RSA Key Generation Tests', () => {
  test('generateKeyPairSync Ed25519', () => {
    const pair = generateKeyPairSync('ed25519')
    assert.ok(pair.publicKey.length > 0)
    assert.ok(pair.privateKey.length > 0)
  })

  test('generateKeyPair async P-256', async () => {
    const pair = await generateKeyPair('p256')
    assert.ok(pair.publicKey.length > 0)
    assert.ok(pair.privateKey.length > 0)
  })
})

describe("RSA encryption/decryption", () => {
  const input = "I AM THE WALRUS";
  const bufferToEncrypt = Buffer.from(input);

  let rsaKeyPem: string;
  let rsaPubPem: string;
  let encryptedBuffer: Buffer;
  let otherEncrypted: Buffer;

  before(() => {
    const pair = generateKeyPairSync("rsa");
    rsaPubPem = pair.publicKey.toString("utf8");
    rsaKeyPem = pair.privateKey.toString("utf8");

    encryptedBuffer = publicEncrypt(rsaPubPem, bufferToEncrypt);

    const ab = Buffer.from(rsaPubPem);
    const ab2enc = bufferToEncrypt;

    publicEncrypt(ab, ab2enc);
    publicEncrypt(new Uint8Array(ab.buffer, ab.byteOffset, ab.byteLength), new Uint8Array(ab2enc.buffer, ab2enc.byteOffset, ab2enc.byteLength));
    otherEncrypted = publicEncrypt(
      {
        key: ab.toString("utf8"),
      },
      ab2enc,
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
    const encryptedBuffer = publicEncrypt(rsaPubPem, bufferToEncrypt);
    const decryptedBuffer = privateDecrypt(rsaKeyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });

  test("privateEncrypt and publicDecrypt with keyPem", () => {
    const encryptedBuffer = privateEncrypt(rsaKeyPem, bufferToEncrypt);
    const decryptedBuffer = publicDecrypt(rsaKeyPem, encryptedBuffer);
    assert.equal(decryptedBuffer.toString(), input);
  });
});

function test_rsa(paddingName: string) {
  const pair = generateKeyPairSync("rsa");
  const rsaPubPem = pair.publicKey.toString("utf8");
  const rsaKeyPem = pair.privateKey.toString("utf8");

  const size = 32;
  const input = Buffer.allocUnsafe(size);
  for (let i = 0; i < input.length; i++) input[i] = (i * 7 + 11) & 0xff;
  const bufferToEncrypt = Buffer.from(input);

  const encryptedBuffer = publicEncrypt(
    {
      key: rsaPubPem,
    },
    bufferToEncrypt,
  );

  const decryptedBuffer = privateDecrypt(
    {
      key: rsaKeyPem,
    },
    encryptedBuffer,
  );
  assert.deepEqual(decryptedBuffer, input);
}

test(`RSA with RSA_NO_PADDING`, () => {
  test_rsa("RSA_NO_PADDING");
});

test(`RSA with RSA_PKCS1_PADDING`, () => {
  test_rsa("RSA_PKCS1_PADDING");
});

test(`RSA with RSA_PKCS1_OAEP_PADDING`, () => {
  test_rsa("RSA_PKCS1_OAEP_PADDING");
});
