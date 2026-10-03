import assert from 'node:assert/strict'
import test from 'node:test'
import crypto from 'node:crypto'
import { pbkdf2Sync, pbkdf2 } from '../index.js'

test('pbkdf2Sync compatibility with node:crypto', () => {
  const password = 'password'
  const salt = 'salt'
  const iterations = 1000
  const keylen = 32
  const digest = 'sha256'

  const expected = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex')
  const actual = pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex')

  assert.equal(actual, expected)
})

test('pbkdf2 async compatibility with node:crypto', async () => {
  const password = 'password'
  const salt = 'salt'
  const iterations = 1000
  const keylen = 32
  const digest = 'sha512'

  const expected = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex')
  const derived = await pbkdf2(password, salt, iterations, keylen, digest)
  const actual = derived.toString('hex')

  assert.equal(actual, expected)
})
