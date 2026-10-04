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

test('AEAD AES-256-GCM with associated data (AAD)', () => {
  const key = new Uint8Array(32).fill(3)
  const nonce = new Uint8Array(12).fill(4)
  const plaintext = new TextEncoder().encode('Authenticated payload')
  const aad = new TextEncoder().encode('additional-data')

  const ciphertext = encryptAead('aes256gcm', key, nonce, plaintext, aad)
  assert.ok(ciphertext.length > plaintext.length)

  const decrypted = decryptAead('aes256gcm', key, nonce, ciphertext, aad)
  assert.equal(new TextDecoder().decode(decrypted), 'Authenticated payload')

  // Corrupting AAD fails decryption
  const wrongAad = new TextEncoder().encode('wrong-aad')
  assert.throws(() => {
    decryptAead('aes256gcm', key, nonce, ciphertext, wrongAad)
  })
})
