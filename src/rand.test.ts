import assert from 'node:assert/strict'
import test from 'node:test'
import { randomBytes, randomFillSync, randomInt, randomUUID } from '../index.js'

test('randomBytes generates requested length', () => {
  const bytes = randomBytes(16)
  assert.equal(bytes.length, 16)
  assert.equal(randomBytes(0).length, 0)
})

test('randomFillSync fills Uint8Array', () => {
  const arr = new Uint8Array(10)
  const filled = randomFillSync(arr, 0, 10)
  assert.ok(filled.some((b) => b !== 0))
})

test('randomFillSync with offset and size', () => {
  const arr = new Uint8Array(10)
  randomFillSync(arr, 3, 4)
  assert.equal(arr[0], 0)
  assert.equal(arr[1], 0)
  assert.equal(arr[2], 0)
  assert.equal(arr[7], 0)
  assert.equal(arr[8], 0)
  assert.equal(arr[9], 0)
})

test('randomInt returns integer within range', () => {
  for (let i = 0; i < 50; i++) {
    const val = randomInt(1, 10)
    assert.ok(val >= 1 && val < 10)
  }
})

test('randomUUID returns valid UUID string', () => {
  const uuid = randomUUID()
  assert.equal(typeof uuid, 'string')
  assert.equal(uuid.length, 36)
  const uuidV4Regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  assert.ok(uuidV4Regex.test(uuid))
})
