import assert from 'node:assert/strict'
import test, { describe } from 'node:test'
import { generateKeyPairSync, generateKeyPair } from '../index.js'

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
