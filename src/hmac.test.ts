import assert from 'node:assert/strict'
import test from 'node:test'
import crypto from 'node:crypto'
import { createHmac, Hmac } from '../index.js'

test('HMAC sha256 compatibility with node:crypto', () => {
  const secret = 'secret-key'
  const message = 'Hello World!'

  const expected = crypto.createHmac('sha256', secret).update(message).digest('hex')

  const hmac = createHmac('sha256', secret)
  hmac.update(message)
  const actual = hmac.digest('hex')

  assert.equal(actual, expected)
})

test('HMAC sha512 base64 digest', () => {
  const secret = 'secret-key-512'
  const message = 'Test payload'

  const expected = crypto.createHmac('sha512', secret).update(message).digest('base64')

  const hmac = new Hmac('sha512', secret)
  hmac.update(message)
  const actual = hmac.digest('base64')

  assert.equal(actual, expected)
})

test('HMAC with binary Uint8Array key and multi-chunk update', () => {
  const secret = new Uint8Array([10, 20, 30, 40, 50])
  const chunk1 = 'Part 1 - '
  const chunk2 = 'Part 2'

  const expected = crypto
    .createHmac('sha256', secret)
    .update(chunk1)
    .update(chunk2)
    .digest('hex')

  const hmac = createHmac('sha256', secret)
  hmac.update(chunk1).update(chunk2)
  const actual = hmac.digest('hex')

  assert.equal(actual, expected)
})
