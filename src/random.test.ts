import assert from 'node:assert/strict'
import test from 'node:test'
import {
  randomBytes,
  randomFill,
  randomFillSync,
  randomInt,
  randomUUID,
  randomUUIDv7,
} from '../index.js'

test('randomBytes - synchronous', () => {
  const bytes = randomBytes(16)
  assert.ok(Buffer.isBuffer(bytes))
  assert.equal(bytes.length, 16)

  const empty = randomBytes(0)
  assert.equal(empty.length, 0)
})

test('randomBytes - asynchronous callback', (t, done) => {
  randomBytes(32, (err: Error | null, buf: Buffer) => {
    assert.equal(err, null)
    assert.ok(Buffer.isBuffer(buf))
    assert.equal(buf.length, 32)
    done()
  })
})

test('randomBytes - invalid size throws', () => {
  assert.throws(() => randomBytes(-1), /out of range/i)
  assert.throws(() => randomBytes(2147483648), /out of range/i)
})

test('randomFillSync - Uint8Array', () => {
  const arr = new Uint8Array(10)
  const filled = randomFillSync(arr, 0, 10)
  assert.equal(filled, arr)
  assert.ok(arr.some((b) => b !== 0))
})

test('randomFillSync - Buffer with offset and size', () => {
  const buf = Buffer.alloc(20)
  randomFillSync(buf, 5, 10)
  assert.equal(buf.subarray(0, 5).every((b) => b === 0), true)
  assert.equal(buf.subarray(5, 15).some((b) => b !== 0), true)
  assert.equal(buf.subarray(15, 20).every((b) => b === 0), true)
})

test('randomFillSync - Uint32Array', () => {
  const arr = new Uint32Array(5)
  randomFillSync(arr, 1, 3)
  assert.equal(arr[0], 0)
  assert.equal(arr[4], 0)
  assert.ok(arr[1] !== 0 || arr[2] !== 0 || arr[3] !== 0)
})

test('randomFillSync - DataView and ArrayBuffer', () => {
  const ab = new ArrayBuffer(16)
  const dv = new DataView(ab)
  randomFillSync(dv, 2, 8)
  const u8 = new Uint8Array(ab)
  assert.equal(u8[0], 0)
  assert.equal(u8[1], 0)
  assert.ok(u8.slice(2, 10).some((b) => b !== 0))
  assert.equal(u8[10], 0)
})

test('randomFill - asynchronous callback overloads', (t, done) => {
  const buf = Buffer.alloc(16)
  randomFill(buf, (err1: Error | null, res1: Buffer) => {
    assert.equal(err1, null)
    assert.ok(buf.some((b) => b !== 0))

    const buf2 = Buffer.alloc(16)
    randomFill(buf2, 4, (err2: Error | null, res2: Buffer) => {
      assert.equal(err2, null)
      assert.equal(buf2.subarray(0, 4).every((b) => b === 0), true)
      assert.ok(buf2.subarray(4, 16).some((b) => b !== 0))

      const buf3 = Buffer.alloc(16)
      randomFill(buf3, 4, 8, (err3: Error | null, res3: Buffer) => {
        assert.equal(err3, null)
        assert.equal(buf3.subarray(0, 4).every((b) => b === 0), true)
        assert.ok(buf3.subarray(4, 12).some((b) => b !== 0))
        assert.equal(buf3.subarray(12, 16).every((b) => b === 0), true)
        done()
      })
    })
  })
})

test('randomFill - missing callback throws', () => {
  const buf = Buffer.alloc(10)
  // @ts-expect-error testing missing callback
  assert.throws(() => randomFill(buf), /callback/i)
})

test('randomInt - synchronous', () => {
  const val1 = randomInt(10)
  assert.ok(typeof val1 === 'number')
  assert.ok(val1 >= 0 && val1 < 10)

  const val2 = randomInt(5, 15)
  assert.ok(val2 >= 5 && val2 < 15)

  for (let i = 0; i < 100; i++) {
    const v = randomInt(1, 4)
    assert.ok(v >= 1 && v < 4)
  }
})

test('randomInt - asynchronous callback', (t, done) => {
  randomInt(1, 100, (err: Error | null, n?: number) => {
    assert.equal(err, null)
    assert.ok(typeof n === 'number')
    assert.ok(n >= 1 && n < 100)
    done()
  })
})

test('randomInt - validation errors', () => {
  assert.throws(() => randomInt(10, 5), /min must be less than max/i)
  assert.throws(() => randomInt(5, 5), /min must be less than max/i)
  assert.throws(() => randomInt(Number.MAX_SAFE_INTEGER + 1), /safe integer/i)
})

test('randomUUID - returns valid v4 UUID', () => {
  const uuid1 = randomUUID()
  assert.equal(typeof uuid1, 'string')
  assert.equal(uuid1.length, 36)
  assert.match(
    uuid1,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  )

  const uuid2 = randomUUID({ disableEntropyCache: true })
  assert.equal(uuid2.length, 36)
  assert.notEqual(uuid1, uuid2)
})

test('randomUUIDv7 - returns valid v7 UUID with timestamp', () => {
  const before = Date.now()
  const uuid = randomUUIDv7()
  const after = Date.now()

  assert.equal(typeof uuid, 'string')
  assert.equal(uuid.length, 36)
  assert.match(
    uuid,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  )

  const hexTime = uuid.replace(/-/g, '').slice(0, 12)
  const timestamp = parseInt(hexTime, 16)
  assert.ok(timestamp >= before && timestamp <= after + 1000)

  const uuidWithOpts = randomUUIDv7({ disableEntropyCache: true })
  assert.equal(uuidWithOpts.length, 36)
})
