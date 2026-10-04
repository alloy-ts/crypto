import assert from 'node:assert/strict'
import test from 'node:test'
import { createSecretKey, createPublicKey, createPrivateKey, KeyType, KeyObject } from '../index.js'

test('KeyObject exports and types', () => {
  const secretKey = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  assert.equal(secretKey.keyTypeName, 'secret')
  assert.equal(secretKey.keyType, KeyType.Secret)
  assert.deepEqual(Array.from(secretKey.export()), [1, 2, 3, 4])

  const pubKey = createPublicKey(new Uint8Array([5, 6, 7]))
  assert.equal(pubKey.keyTypeName, 'public')
  assert.equal(pubKey.keyType, KeyType.Public)

  const privKey = createPrivateKey(new Uint8Array([8, 9]))
  assert.equal(privKey.keyTypeName, 'private')
  assert.equal(privKey.keyType, KeyType.Private)

  const direct = new KeyObject(KeyType.Secret, new Uint8Array([10, 20]))
  assert.equal(direct.keyTypeName, 'secret')
  assert.deepEqual(Array.from(direct.export()), [10, 20])
})
