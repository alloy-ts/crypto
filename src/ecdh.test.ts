import assert from 'node:assert/strict'
import test from 'node:test'
import { createECDH, ECDH } from '../index.js'

test('ECDH key exchange between two parties', () => {
  const alice = createECDH('p256')
  const bob = new ECDH('p256')

  const alicePub = alice.getPublicKey()
  const bobPub = bob.getPublicKey()

  assert.ok(alicePub.length > 0)
  assert.ok(bobPub.length > 0)

  const aliceSecret = alice.computeSecret(bobPub)
  const bobSecret = bob.computeSecret(alicePub)

  assert.deepEqual(Array.from(aliceSecret), Array.from(bobSecret))
})
