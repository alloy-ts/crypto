import assert from 'node:assert/strict'
import test from 'node:test'
import { Certificate } from '../index.js'

test('Certificate static and instance methods', () => {
  // Test valid SPKAC base64 string
  const validSpkacBase64 =
    'MIICTjCCATYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ7b5l5EUbgoBs' +
    'ICaY+GRPfHUgpd2WfRfp4Ynk59t/pCk0VIhkW1MBDAG5sRNeE7k8sfyc1v94omQCWki0' +
    'Dwk4SPFlmqFB2c4LR68HxWLh92Ns11RYG8aNGoHJnghcttsNFeG/CT/ZKqCxXf6eT/zk' +
    'BZ08MZSH/cCeC5Qm8YosjAI/lD79UIIe4cu8P93Sd2POMLvbwOcDmglpUfKxYIR8ggSv' +
    'P01lfgHXRKPnoDnlw1lTbTre+KMvCMLEh3pIrLq4CtETyMWory/QmQYyRWGStPs140cf' +
    '+xeVVNpHPQdygZ53izHDos6yJ2JIC7pbDoK3WIyWpb0c1icTAFIsdVEPAgMBAAEWDnRlc3Qt' +
    'Y2hhbGxlbmdlMA0GCSqGSIb3DQEBBAUAA4IBAQC7I1O/zyHceNqJWgZQsWximdE6Wp1q' +
    'h9BKZxvJhBEgaP54Zq1OJ/95t7LALrLQ5AcecuC6C+tNJ5b3wdn5LfwCvMOz5Lej66PN' +
    'BF+CTTpqHXrdzoLg2ymE0rkhLDIZgLRcQu5TMRGpBkCTtO9mHysw77Zk5OtDtPTbzq55' +
    'FgXGdNSQXOEPPpXPx39dhZAvbDgpw7EfQhn/gc3GjmHhURY7F2EkTIgCz0WrfdW9Pnu+' +
    'ziDvjqupnquYGU1ixofIKeSXHpiAmsvZqelTPuI4kgbBgwE7pr3mewlKB+4kiSEVxrJf' +
    'PBgJrMxYLSGdUdBoyjEfZ1+4E1VXYofPV0f7iQQ+'

  const spkacWithPrefix = `SPKAC=${validSpkacBase64}`
  const spkacBuffer = Buffer.from(validSpkacBase64, 'utf8')

  // Static methods tests
  assert.equal(Certificate.verifySpkac(validSpkacBase64), true)
  assert.equal(Certificate.verifySpkac(spkacWithPrefix), true)
  assert.equal(Certificate.verifySpkac(spkacBuffer), true)

  const challenge = Certificate.exportChallenge(validSpkacBase64)
  assert.equal(challenge.toString('utf8'), 'test-challenge')

  const pubKey = Certificate.exportPublicKey(validSpkacBase64)
  assert.equal(pubKey.toString('utf8').startsWith('-----BEGIN PUBLIC KEY-----'), true)
  assert.equal(pubKey.toString('utf8').includes('-----END PUBLIC KEY-----'), true)

  // Legacy instance API tests
  const cert = new Certificate()
  assert.equal(cert.verifySpkac(validSpkacBase64), true)
  assert.equal(cert.exportChallenge(validSpkacBase64).toString('utf8'), 'test-challenge')
  assert.equal(cert.exportPublicKey(validSpkacBase64).toString('utf8').startsWith('-----BEGIN PUBLIC KEY-----'), true)

  // Tampered/Invalid SPKAC inputs
  const tamperedSpkac = validSpkacBase64.slice(0, -10) + 'AAAAAAA='
  assert.equal(Certificate.verifySpkac(tamperedSpkac), false)
  assert.equal(Certificate.verifySpkac('invalid-spkac-data'), false)
  assert.equal(Certificate.exportChallenge('invalid-spkac-data').length, 0)
  assert.equal(Certificate.exportPublicKey('invalid-spkac-data').length, 0)
})
