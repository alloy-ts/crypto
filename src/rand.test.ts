import assert from "node:assert/strict";
import test from "node:test";
import {
  randomBytes,
  randomBytesAsync,
  randomFill,
  randomFillSync,
  randomInt,
  randomUUID,
  randomUUIDv7,
} from "../index.js";

test("randomBytes generates requested length synchronously", () => {
  const bytes = randomBytes(16);
  assert.equal(Buffer.isBuffer(bytes), true);
  assert.equal(bytes.length, 16);
});

test("randomBytesAsync generates requested length asynchronously", async () => {
  const bytes = await randomBytesAsync(32);
  assert.equal(Buffer.isBuffer(bytes), true);
  assert.equal(bytes.length, 32);
});

test("randomFillSync fills Uint8Array synchronously", () => {
  const arr = new Uint8Array(10);
  const filled = randomFillSync(arr, 0, 10);
  assert.ok(filled.some((b) => b !== 0));
});

test("randomFill fills Uint8Array asynchronously", async () => {
  const arr = new Uint8Array(10);
  const filled = await randomFill(arr, 0, 10);
  assert.ok(filled.some((b) => b !== 0));
});

test("randomInt returns integer within range", () => {
  const val = randomInt(1, 10);
  assert.ok(val >= 1 && val < 10);

  const valSingle = randomInt(5);
  assert.ok(valSingle >= 0 && valSingle < 5);
});

test("randomUUID returns valid v4 UUID string", () => {
  const uuid = randomUUID();
  assert.equal(typeof uuid, "string");
  assert.equal(uuid.length, 36);
  assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
});

test("randomUUIDv7 returns valid v7 UUID string", () => {
  const uuid = randomUUIDv7();
  assert.equal(typeof uuid, "string");
  assert.equal(uuid.length, 36);
  assert.match(uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
});

test("validates error cases", () => {
  assert.throws(() => {
    randomBytes(0x80000000);
  });

  assert.throws(() => {
    randomInt(10, 5);
  });
});
