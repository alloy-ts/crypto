import assert from 'node:assert/strict'
import test from 'node:test'
import {
  argon2Hash,
  argon2HashSync,
  argon2Verify,
  argon2VerifySync,
  argon2ParseOptions,
  Algorithm,
  Version,
} from '../index.js'

test('argon2HashSync and argon2VerifySync', () => {
  const password = 'my-secret-password'
  const hash = argon2HashSync(password, {
    algorithm: Algorithm.Argon2id,
    version: Version.V0x13,
  })
  assert.ok(hash.startsWith('$argon2id$v=19$'))

  const isValid = argon2VerifySync(hash, password)
  assert.equal(isValid, true)

  const isInvalid = argon2VerifySync(hash, 'wrong-password')
  assert.equal(isInvalid, false)

  const parsed = argon2ParseOptions(hash)
  assert.equal(parsed.algorithm, Algorithm.Argon2id)
  assert.equal(parsed.version, Version.V0x13)
})

test('argon2Hash and argon2Verify async', async () => {
  const password = 'async-password'
  const hash = await argon2Hash(password, {
    memoryCost: 4096,
    timeCost: 1,
  })
  assert.ok(hash.includes('$argon2id$'))

  const isValid = await argon2Verify(hash, password)
  assert.equal(isValid, true)
})
