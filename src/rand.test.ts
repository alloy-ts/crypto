import assert from 'node:assert/strict'
import test from 'node:test'
import { randomBytes, randomFillSync, randomInt, randomUUID } from '../index.js'

test('randomBytes generates requested length', () => {
  const bytes = randomBytes(16)
  assert.equal(bytes.length, 16)
})

test('randomFillSync fills Uint8Array', () => {
  const arr = new Uint8Array(10)
  const filled = randomFillSync(arr, 0, 10)
  assert.ok(filled.some((b) => b !== 0))
})

test('randomInt returns integer within range', () => {
  const val = randomInt(1, 10)
  assert.ok(val >= 1 && val < 10)
})

test('randomUUID returns valid UUID string', () => {
  const uuid = randomUUID()
  assert.equal(typeof uuid, 'string')
  assert.equal(uuid.length, 36)
})
