import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "../index.js";

test("crypto exports work in ts", () => {
  const hash = createHash("sha256").update("test").digest("hex");
  assert.equal(typeof hash, "string");
});
