import assert from 'node:assert/strict'
import test from 'node:test'
import crypto from 'node:crypto'
import { createHash, hash, getHashes, Hash } from '../index.js'

test('Hash sha256 compatibility with node:crypto', () => {
  const data = 'Hello, world!'
  const expected = crypto.createHash('sha256').update(data).digest('hex')

  const h = createHash('sha256')
  h.update(data)
  const actual = h.digest('hex')

  assert.equal(actual, expected)
})

test('Hash multiple updates and base64 digest', () => {
  const chunk1 = 'Hello, '
  const chunk2 = 'world!'
  const expected = crypto
    .createHash('sha512')
    .update(chunk1)
    .update(chunk2)
    .digest('base64')

  const h = new Hash('sha512')
  h.update(chunk1).update(chunk2)
  const actual = h.digest('base64')

  assert.equal(actual, expected)
})

test('hash one-shot utility', () => {
  const data = 'Hello, world!'
  const expected = crypto.createHash('sha512').update(data).digest('base64')

  const actual = hash('sha512', data, 'base64')

  assert.equal(actual, expected)
})

test('getHashes', () => {
  const hashes = getHashes()
  assert.ok(hashes.includes('sha256'))
  assert.ok(hashes.includes('sha512'))
})
