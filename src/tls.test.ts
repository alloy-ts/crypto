import assert from 'node:assert/strict'
import test from 'node:test'
import { TLS, CryptoProviderType } from '../index.js'

test('TLS default and provider selection', () => {
  const tlsDefault = new TLS()
  assert.equal(tlsDefault.providerName, 'ring')

  const tlsOpenssl = new TLS(CryptoProviderType.OpenSSL)
  assert.equal(tlsOpenssl.providerName, 'openssl')

  const tlsBoring = new TLS(CryptoProviderType.BoringSSL)
  assert.equal(tlsBoring.providerName, 'boringssl')

  const tlsMbed = new TLS(CryptoProviderType.MbedTLS)
  assert.equal(tlsMbed.providerName, 'mbedtls')

  assert.equal(tlsDefault.isSupported(), true)
})
