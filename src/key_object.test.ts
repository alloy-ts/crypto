import assert from 'node:assert/strict'
import test from 'node:test'
import { createSecretKey, createPublicKey, createPrivateKey, KeyType } from '../index.js'

test('KeyObject exports and types', () => {
  const secretKey = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  assert.equal(secretKey.keyTypeName, 'secret')
  assert.deepEqual(Array.from(secretKey.export()), [1, 2, 3, 4])

  const pubKey = createPublicKey(new Uint8Array([5, 6, 7]))
  assert.equal(pubKey.keyTypeName, 'public')

  const privKey = createPrivateKey(new Uint8Array([8, 9]))
  assert.equal(privKey.keyTypeName, 'private')
})
