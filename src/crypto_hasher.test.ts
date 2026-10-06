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

test('Hash copy', () => {
  const h = createHash('sha256')
  h.update('one')
  const h2 = h.copy()
  h2.update('two')

  const d1 = h.digest('hex')
  const d2 = h2.digest('hex')

  assert.notEqual(d1, d2)
  assert.equal(d1, crypto.createHash('sha256').update('one').digest('hex'))
  assert.equal(d2, crypto.createHash('sha256').update('one').update('two').digest('hex'))
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
