import assert from 'node:assert/strict'
import test from 'node:test'
import { Verify, createVerify, verify, createMac } from '../index.js'

test('createVerify and Verify update/verify flow', () => {
  const verifier = createVerify('sha256')
  verifier.update('test data')
  assert.ok(verifier)
})

test('verify function return type', () => {
  const dummyPub = new Uint8Array(32)
  const dummySig = new Uint8Array(64)
  const res = verify('ed25519', 'test data', dummyPub, dummySig)
  assert.equal(typeof res, 'boolean')
})

test('createMac creates a valid Hmac instance', () => {
  const mac = createMac('sha256', new Uint8Array([1, 2, 3, 4]))
  mac.update('hello')
  const digest = mac.digest('hex')
  assert.equal(typeof digest, 'string')
})
