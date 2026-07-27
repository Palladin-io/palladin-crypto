import { describe, expect, it } from 'vitest'
import type { CanonicalEnvelopeAad, EncodedSuitePayload } from './envelope'
import {
  MAX_ENCODED_SUITE_PAYLOAD_BYTES,
  requireCryptoSuite,
  VAULT_XCHACHA20_POLY1305_V1,
} from './crypto-suite'

const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)?.map((value) => Number.parseInt(value, 16)) ?? [])
const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')

const key = bytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
const aad = bytes('70616c6c6164696e2d63726f73732d636c69656e742d616164') as CanonicalEnvelopeAad
const plaintext = bytes('7b2274797065223a302c2276616c7565223a22766563746f72227d')
const vectorPayload = bytes(
  '000102030405060708090a0b0c0d0e0f1011121314151617' +
  'e5e07b06e0b7af94036804b8aa3edd8d697d0ad398b569840d384210567b2301ffade0f918350b114b08bb',
) as EncodedSuitePayload

describe('palladin-vault-xchacha-v1', () => {
  it('opens the deterministic cross-client primitive vector', async () => {
    const suite = requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1)
    expect(hex(vectorPayload.slice(0, 24))).toBe('000102030405060708090a0b0c0d0e0f1011121314151617')
    await expect(suite.open({ payload: vectorPayload, key, aad })).resolves.toEqual(plaintext)
  })

  it('always seals with a fresh random nonce', async () => {
    const suite = requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1)
    const first = await suite.seal({ plaintext, key, aad })
    const second = await suite.seal({ plaintext, key, aad })
    expect(first.slice(0, 24)).not.toEqual(second.slice(0, 24))
    await expect(suite.open({ payload: first, key, aad })).resolves.toEqual(plaintext)
  })

  it('rejects tampering and the wrong AAD', async () => {
    const suite = requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1)
    const payload = await suite.seal({ plaintext, key, aad })
    const tampered = new Uint8Array(payload) as EncodedSuitePayload
    tampered[tampered.length - 1] ^= 1

    await expect(suite.open({ payload: tampered, key, aad })).rejects.toThrow()
    await expect(
      suite.open({ payload, key, aad: bytes('00') as CanonicalEnvelopeAad }),
    ).rejects.toThrow()
  })

  it('fails closed for unknown suites and malformed payload sizes', () => {
    expect(() => requireCryptoSuite('legacy-xsalsa20-poly1305')).toThrow(/Unsupported/)
    const suite = requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1)
    expect(() => suite.validateEncodedPayload(new Uint8Array(39))).toThrow(RangeError)
    expect(() => suite.validateEncodedPayload(new Uint8Array(MAX_ENCODED_SUITE_PAYLOAD_BYTES + 1))).toThrow(RangeError)
  })
})

