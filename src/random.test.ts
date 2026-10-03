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

test('randomBytes synchronous', () => {
  const bytes = randomBytes(16) as unknown as Buffer
  assert.equal(bytes.length, 16)
  assert.ok(Buffer.isBuffer(bytes))

  const zeroBytes = randomBytes(0) as unknown as Buffer
  assert.equal(zeroBytes.length, 0)
})

test('randomBytes asynchronous', async () => {
  await new Promise<void>((resolve, reject) => {
    randomBytes(32, (err, buf) => {
      try {
        assert.equal(err, null)
        assert.ok(buf)
        assert.equal(buf.length, 32)
        resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
})

test('randomBytes invalid size throws', () => {
  assert.throws(() => {
    randomBytes(-1)
  })
  assert.throws(() => {
    randomBytes(2147483648)
  })
  assert.throws(() => {
    randomBytes(NaN)
  })
})

test('randomFillSync fills Uint8Array', () => {
  const arr = new Uint8Array(10)
  const filled = randomFillSync(arr, 0, 10)
  assert.equal(filled, arr)
  assert.ok(arr.some((b) => b !== 0))
})

test('randomFillSync with offset and size', () => {
  const arr = new Uint8Array(10)
  randomFillSync(arr, 5, 5)
  assert.ok(arr.slice(0, 5).every((b) => b === 0))
  assert.ok(arr.slice(5).some((b) => b !== 0))
})

test('randomFillSync invalid bounds throw', () => {
  const arr = new Uint8Array(10)
  assert.throws(() => {
    randomFillSync(arr, 5, 10)
  })
  assert.throws(() => {
    randomFillSync(arr, -1, 5)
  })
})

test('randomFill asynchronous (buf, cb)', async () => {
  await new Promise<void>((resolve, reject) => {
    const buf = new Uint8Array(10)
    randomFill(buf, (err, filled) => {
      try {
        assert.equal(err, null)
        assert.equal(filled, buf)
        assert.ok(buf.some((b) => b !== 0))
        resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
})

test('randomFill asynchronous (buf, offset, cb)', async () => {
  await new Promise<void>((resolve, reject) => {
    const buf = new Uint8Array(10)
    randomFill(buf, 5, (err, filled) => {
      try {
        assert.equal(err, null)
        assert.equal(filled, buf)
        assert.ok(buf.slice(0, 5).every((b) => b === 0))
        assert.ok(buf.slice(5).some((b) => b !== 0))
        resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
})

test('randomFill asynchronous (buf, offset, size, cb)', async () => {
  await new Promise<void>((resolve, reject) => {
    const buf = new Uint8Array(10)
    randomFill(buf, 2, 4, (err, filled) => {
      try {
        assert.equal(err, null)
        assert.equal(filled, buf)
        assert.ok(buf.slice(2, 6).some((b) => b !== 0))
        resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
})

test('randomFill missing callback throws', () => {
  const buf = new Uint8Array(10)
  assert.throws(() => {
    // @ts-expect-error testing missing callback
    randomFill(buf)
  })
})

test('randomInt synchronous with max argument', () => {
  for (let i = 0; i < 50; i++) {
    const val = randomInt(5) as unknown as number
    assert.ok(Number.isInteger(val))
    assert.ok(val >= 0 && val < 5)
  }
})

test('randomInt synchronous with min and max arguments', () => {
  for (let i = 0; i < 50; i++) {
    const val = randomInt(10, 20) as unknown as number
    assert.ok(Number.isInteger(val))
    assert.ok(val >= 10 && val < 20)
  }
})

test('randomInt asynchronous with callback', async () => {
  await new Promise<void>((resolve, reject) => {
    randomInt(1, 10, (err, val) => {
      try {
        assert.equal(err, null)
        assert.ok(typeof val === 'number')
        assert.ok(val >= 1 && val < 10)
        resolve()
      } catch (e) {
        reject(e)
      }
    })
  })
})

test('randomInt invalid ranges throw', () => {
  assert.throws(() => {
    randomInt(10, 5)
  })
  assert.throws(() => {
    randomInt(5, 5)
  })
  assert.throws(() => {
    randomInt(0, 281474976710656) // >= 2**48
  })
})

test('randomUUID returns valid v4 UUID string', () => {
  const uuid = randomUUID()
  assert.equal(typeof uuid, 'string')
  assert.equal(uuid.length, 36)
  assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)

  const uuidWithOpts = randomUUID({ disableEntropyCache: true })
  assert.equal(uuidWithOpts.length, 36)
})

test('randomUUIDv7 returns valid v7 UUID string', () => {
  const uuid = randomUUIDv7()
  assert.equal(typeof uuid, 'string')
  assert.equal(uuid.length, 36)
  assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)

  const uuidWithOpts = randomUUIDv7({ disableEntropyCache: true })
  assert.equal(uuidWithOpts.length, 36)
})
