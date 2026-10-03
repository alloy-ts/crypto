import assert from 'node:assert/strict'
import test from 'node:test'
import { encryptAead, decryptAead } from '../index.js'

test('AEAD AES-256-GCM encryption and decryption', () => {
  const key = new Uint8Array(32).fill(1)
  const nonce = new Uint8Array(12).fill(2)
  const plaintext = new TextEncoder().encode('Secret message')

  const ciphertext = encryptAead('aes256gcm', key, nonce, plaintext, undefined)
  assert.ok(ciphertext.length > plaintext.length)

  const decrypted = decryptAead('aes256gcm', key, nonce, ciphertext, undefined)
  assert.equal(new TextDecoder().decode(decrypted), 'Secret message')
})
