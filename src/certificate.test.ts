import assert from 'node:assert/strict'
import test from 'node:test'
import { Certificate } from '../index.js'

const VALID_SPKAC_RAW = `SPKAC=MIICVDCCATwwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCY2S/f8aZn/Tj7evkEtAD+zvYYm6/IGPNtl9FJirMpiiXwNhDeL90FKyVPlH2NHCtEQGErgUGsGLDcUkG5TwjbeQ8yE9ZX9eiTZsn8W+c4AKbZWeaW85Lys2QM+YeAQftUJ1qjeG0RllcoXppE8Ke+XtZm68aocpjEhB65vRkaVkb64qnzphhQ6eZgsALhNei4UqP48hfmGrRdl554ddiLCV+3P5QYda32ff83hcOBYlBiPKKFXHFCxv15FoxUsQdevAvkXlq8cDjt9gblt8bLdKDctD+Bp37QG1FxVY/wzAuNOFdYhtusJR5k14Vhpl59C9Yrg5nnvCky9APzgEwrAgMBAAEWFHRlc3RfY2hhbGxlbmdlXzEyMzQ1MA0GCSqGSIb3DQEBBAUAA4IBAQA71ULsOHx/VajIy6/O37ZwpXLJKh9Gz4/rMnWGaEcBHjyq2YcVnr5y0x4aD+r/iVqCkMTnYK3JquGSSgsy4rF2tlXCs6ZG5l2mNiiplxc3lWjon9QjI79G8s5Vc7UxqwRJWB9f6U3zfWXNUR659VWb2QTP5Nv2nugwL9R1l2AEUM+YRqVLOYiE6K5INTijvCGsVM1XO1rzS7BvxXQvRi8ztsDuYYHF6GVke0yLIurtM/Bp/+lp9IyBsLsAOM7uas4KKuXt2UwosCY0lwQGxFp/vXWydSqOEgZjyrv7fEWIF9nuS6T2FmgX665w1J7sIbPLXVGBIUQsJy0Ome5Pt5/2`

const VALID_SPKAC_B64 = VALID_SPKAC_RAW.replace(/^SPKAC=/, '').replace(/\s+/g, '')

test('Certificate static methods with string input', () => {
  const challengeBuf = Certificate.exportChallenge(VALID_SPKAC_B64)
  assert.equal(challengeBuf.toString('utf8'), 'test_challenge_12345')

  const pubKeyBuf = Certificate.exportPublicKey(VALID_SPKAC_B64)
  assert.ok(pubKeyBuf.toString('utf8').includes('-----BEGIN PUBLIC KEY-----'))
  assert.ok(pubKeyBuf.toString('utf8').includes('-----END PUBLIC KEY-----'))

  const isValid = Certificate.verifySpkac(VALID_SPKAC_B64)
  assert.equal(isValid, true)
})

test('Certificate static methods with Buffer input', () => {
  const buf = Buffer.from(VALID_SPKAC_B64, 'utf8')

  const challengeBuf = Certificate.exportChallenge(buf)
  assert.equal(challengeBuf.toString('utf8'), 'test_challenge_12345')

  const pubKeyBuf = Certificate.exportPublicKey(buf)
  assert.ok(pubKeyBuf.toString('utf8').includes('-----BEGIN PUBLIC KEY-----'))

  const isValid = Certificate.verifySpkac(buf)
  assert.equal(isValid, true)
})

test('Certificate static methods with SPKAC= prefix and encodings', () => {
  const challengeBuf = Certificate.exportChallenge(VALID_SPKAC_RAW, 'utf8')
  assert.equal(challengeBuf.toString('utf8'), 'test_challenge_12345')

  const isValid = Certificate.verifySpkac(VALID_SPKAC_RAW, 'utf8')
  assert.equal(isValid, true)
})

test('Certificate legacy API (new Certificate and Certificate())', () => {
  const cert1 = new (Certificate as any)()
  assert.equal(typeof cert1.exportChallenge, 'function')
  assert.equal(typeof cert1.exportPublicKey, 'function')
  assert.equal(typeof cert1.verifySpkac, 'function')

  const challenge1 = cert1.exportChallenge(VALID_SPKAC_B64)
  assert.equal(challenge1.toString('utf8'), 'test_challenge_12345')
  assert.equal(cert1.verifySpkac(VALID_SPKAC_B64), true)

  const cert2 = (Certificate as any)()
  assert.equal(typeof cert2.exportChallenge, 'function')
  assert.equal(typeof cert2.exportPublicKey, 'function')
  assert.equal(typeof cert2.verifySpkac, 'function')

  const challenge2 = cert2.exportChallenge(VALID_SPKAC_B64)
  assert.equal(challenge2.toString('utf8'), 'test_challenge_12345')
  assert.equal(cert2.verifySpkac(VALID_SPKAC_B64), true)
})

test('Certificate handling of invalid or corrupted input', () => {
  const invalid = 'invalid_spkac_data_string'

  const challenge = Certificate.exportChallenge(invalid)
  assert.equal(challenge.length, 0)

  const pubKey = Certificate.exportPublicKey(invalid)
  assert.equal(pubKey.length, 0)

  const isValid = Certificate.verifySpkac(invalid)
  assert.equal(isValid, false)
})
