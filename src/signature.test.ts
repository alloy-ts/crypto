import assert from 'node:assert/strict'
import test from 'node:test'
import { createSign, sign, createVerify, verify, generateKeyPairSync } from '../index.js'

test('Sign and verify with Ed25519', () => {
  const pair = generateKeyPairSync('ed25519')
  const message = 'Message to sign'

  const sig = sign('ed25519', message, pair.privateKey)
  assert.ok(sig.length > 0)

  const isValid = verify('ed25519', message, pair.publicKey, sig)
  assert.equal(isValid, true)

  const invalidSig = Buffer.from(sig)
  invalidSig[0] ^= 0xff
  const isInvalid = verify('ed25519', message, pair.publicKey, invalidSig)
  assert.equal(isInvalid, false)
})

test('Sign and Verify class interface', () => {
  const pair = generateKeyPairSync('ed25519')
  const chunk1 = 'Data stream part 1'
  const chunk2 = 'Data stream part 2'

  const signer = createSign('ed25519')
  signer.update(chunk1).update(chunk2)
  const sig = signer.sign(pair.privateKey)

  const verifier = createVerify('ed25519')
  verifier.update(chunk1).update(chunk2)
  const isValid = verifier.verify(pair.publicKey, sig)

  assert.equal(isValid, true)
})
