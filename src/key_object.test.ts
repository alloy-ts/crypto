import assert from 'node:assert/strict'
import test from 'node:test'
import { createSecretKey, createPublicKey, createPrivateKey } from '../index.js'

test('KeyObject exports and types', () => {
  const secretKey = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  assert.equal(secretKey.type, 'secret')
  assert.equal(secretKey.symmetricKeySize, 4)
  assert.equal(secretKey.asymmetricKeyType == null, true)
  assert.equal(secretKey.asymmetricKeyDetails == null, true)

  const secretKey2 = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  assert.equal(secretKey.equals(secretKey2), true)

  const pubKey = createPublicKey(new Uint8Array([5, 6, 7]))
  assert.equal(pubKey.type, 'public')
  assert.equal(pubKey.asymmetricKeyType, 'rsa')
  assert.ok(pubKey.asymmetricKeyDetails !== null && pubKey.asymmetricKeyDetails !== undefined)
  assert.equal(pubKey.symmetricKeySize == null, true)

  const privKey = createPrivateKey(new Uint8Array([8, 9]))
  assert.equal(privKey.type, 'private')
  assert.equal(privKey.asymmetricKeyType, 'rsa')
  assert.equal(privKey.symmetricKeySize == null, true)
})
