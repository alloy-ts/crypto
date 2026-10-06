import assert from 'node:assert/strict'
import test from 'node:test'
import { createSecretKey, createPublicKey, createPrivateKey, KeyObject } from '../index.js'

test('KeyObject exports and types', () => {
  const secretKey = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  assert.equal(secretKey.type, 'secret')
  assert.equal(secretKey.keyTypeName, 'secret')
  assert.equal(secretKey.symmetricKeySize, 4)
  assert.ok(secretKey.asymmetricKeyType == null)
  assert.ok(secretKey.asymmetricKeyDetails == null)
  assert.deepEqual(Array.from(secretKey.export()), [1, 2, 3, 4])

  const pubKey = createPublicKey(new Uint8Array([5, 6, 7]))
  assert.equal(pubKey.type, 'public')
  assert.equal(pubKey.keyTypeName, 'public')
  assert.ok(pubKey.symmetricKeySize == null)

  const privKey = createPrivateKey(new Uint8Array([8, 9]))
  assert.equal(privKey.type, 'private')
  assert.equal(privKey.keyTypeName, 'private')
  assert.ok(privKey.symmetricKeySize == null)
})

test('KeyObject.equals', () => {
  const key1 = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  const key2 = createSecretKey(new Uint8Array([1, 2, 3, 4]))
  const key3 = createSecretKey(new Uint8Array([1, 2, 3, 5]))
  const pubKey = createPublicKey(new Uint8Array([1, 2, 3, 4]))

  assert.equal(key1.equals(key2), true)
  assert.equal(key1.equals(key3), false)
  assert.equal(key1.equals(pubKey), false)
})

test('KeyObject.export formats', () => {
  const secretKey = createSecretKey(new Uint8Array([10, 20, 30]))

  // Buffer format (default for secret key)
  const bufExport = secretKey.export({ format: 'buffer' })
  assert.deepEqual(Array.from(bufExport), [10, 20, 30])

  // JWK format for secret key
  const jwkExport = secretKey.export({ format: 'jwk' }) as { kty: string; k?: string }
  assert.equal(jwkExport.kty, 'oct')
  assert.ok(jwkExport.k)

  // PEM export for public key
  const pubKey = createPublicKey('1.3.101.112 (Ed25519 OID)')
  const pemExport = pubKey.export({ format: 'pem' })
  assert.equal(typeof pemExport, 'string')
  assert.ok((pemExport as string).includes('PUBLIC KEY'))
})

test('KeyObject.from and toCryptoKey', () => {
  const secretKey = createSecretKey(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]))

  const cryptoKey = secretKey.toCryptoKey({ name: 'HMAC' }, true, ['sign', 'verify']) as {
    type: string
    extractable: boolean
    usages: string[]
  }
  assert.equal(cryptoKey.type, 'secret')
  assert.equal(cryptoKey.extractable, true)
  assert.deepEqual(cryptoKey.usages, ['sign', 'verify'])

  // KeyObject.from from CryptoKey representation
  const reconstructed = KeyObject.from(cryptoKey)
  assert.equal(reconstructed.type, 'secret')

  // Reject non-extractable keys
  assert.throws(() => {
    KeyObject.from({ extractable: false })
  }, /non-extractable/i)
})

test('KeyObject asymmetricKeyType and details detection', () => {
  const edPubKey = createPublicKey('OID 1.3.101.112 ed25519 key')
  assert.equal(edPubKey.asymmetricKeyType, 'ed25519')

  const ecPubKey = createPublicKey('-----BEGIN EC PUBLIC KEY-----\n...\n-----END EC PUBLIC KEY-----')
  assert.equal(ecPubKey.asymmetricKeyType, 'ec')
  assert.equal(ecPubKey.asymmetricKeyDetails?.namedCurve, 'prime256v1')
})
