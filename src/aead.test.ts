import assert from 'node:assert/strict'
import test from 'node:test'
import { encryptAead, decryptAead, createCipheriv, createDecipheriv } from '../index.js'

test('AEAD AES-256-GCM encryption and decryption', () => {
  const key = new Uint8Array(32).fill(1)
  const nonce = new Uint8Array(12).fill(2)
  const plaintext = new TextEncoder().encode('Secret message')

  const ciphertext = encryptAead('aes256gcm', key, nonce, plaintext, undefined)
  assert.ok(ciphertext.length > plaintext.length)

  const decrypted = decryptAead('aes256gcm', key, nonce, ciphertext, undefined)
  assert.equal(new TextDecoder().decode(decrypted), 'Secret message')
})

test('Cipheriv and Decipheriv streaming/update/final', () => {
  const key = new Uint8Array(32).fill(1)
  const iv = new Uint8Array(12).fill(2)
  const plaintext = 'Secret stream message'

  const cipher = createCipheriv('aes-256-gcm', key, iv)
  cipher.update(plaintext, 'utf8')
  const encrypted = cipher.final('hex')
  const tag = cipher.getAuthTag()

  assert.ok(typeof encrypted === 'string' && encrypted.length > 0)
  assert.equal(tag.length, 16)

  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(tag)
  decipher.update(encrypted, 'hex')
  const decrypted = decipher.final('utf8')

  assert.equal(decrypted, plaintext)
})
