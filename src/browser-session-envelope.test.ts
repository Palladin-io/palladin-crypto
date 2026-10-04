import { describe, expect, it, vi } from 'vitest'

import {
  BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION,
  openBrowserSessionEnvelope,
  parseBrowserSessionEnvelope,
  sealBrowserSessionEnvelope,
  type BrowserSessionEnvelopeContext,
} from './browser-session-envelope'
import { fromBase64Url } from './encoding'
import { wipe } from './sodium'
import webCryptoFixture from './fixtures/browser-session-webcrypto-v1.json'

const context: BrowserSessionEnvelopeContext = {
  apiUrl: 'https://api.palladin.io',
  accountId: '00112233-4455-4677-8899-aabbccddeeff',
  clientId: 'abcdefghijklmnopabcdefghijklmnop',
  identitySecurityVersion: 1,
  minimumIdentitySecurityVersion: 1,
  kdfProfileId: 'identity-argon2id-password-v1',
  kdfSalt: 'AAECAwQFBgcICQoLDA0ODw',
  encryptedPrivateKey: 'AQIDBA',
  issuedAt: 1_700_000_000_000,
  expiresAt: 1_702_592_000_000,
}
const validTime = { now: () => context.issuedAt + 1_000 }

describe('browser durable-session envelope', () => {
  it('decrypts the previous WebCrypto implementation fixture without changing wire bytes', async () => {
    // Generated with the pre-portable implementation and synthetic key 0x4a × 32.
    const key = new Uint8Array(32).fill(0x4a)
    try {
      const plaintext = await openBrowserSessionEnvelope(webCryptoFixture, key, validTime)
      try { expect(new TextDecoder().decode(plaintext)).toBe('compatibility fixture') }
      finally { wipe(plaintext) }
    } finally { wipe(key) }
  })
  it('requires independent approval for the exact HTTP API URL when sealing, parsing and opening', async () => {
    const key = new Uint8Array(32).fill(0x48)
    const plaintext = new TextEncoder().encode('session')
    const httpContext = { ...context, apiUrl: 'http://vault.example.test:8080/api' }
    const policy = { allowHttpApiUrls: [httpContext.apiUrl] }
    try {
      await expect(sealBrowserSessionEnvelope(plaintext, key, httpContext)).rejects.toThrow('approved HTTP')
      const envelope = await sealBrowserSessionEnvelope(plaintext, key, httpContext, policy)
      expect(parseBrowserSessionEnvelope(envelope, policy).context).toEqual(httpContext)
      expect(() => parseBrowserSessionEnvelope(envelope)).toThrow('approved HTTP')
      await expect(openBrowserSessionEnvelope(envelope, key, validTime)).rejects.toThrow('approved HTTP')
      await expect(openBrowserSessionEnvelope(envelope, key, {
        ...validTime, transportPolicy: policy,
      })).resolves.toEqual(plaintext)
      for (const apiUrl of [
        'http://vault.example.test:8081/api',
        'http://vault.example.test:8080/other',
        'http://sibling.example.test:8080/api',
      ]) {
        const differentPolicy = { allowHttpApiUrls: [apiUrl] }
        expect(() => parseBrowserSessionEnvelope(envelope, differentPolicy)).toThrow('approved HTTP')
        await expect(openBrowserSessionEnvelope(envelope, key, {
          ...validTime, transportPolicy: differentPolicy,
        })).rejects.toThrow('approved HTTP')
      }
      expect(() => parseBrowserSessionEnvelope({ ...envelope, transportPolicy: policy })).toThrow('unexpected fields')
    } finally {
      wipe(key)
      wipe(plaintext)
    }
  })

  it('round-trips without SubtleCrypto', async () => {
    const key = new Uint8Array(32).fill(0x49)
    const plaintext = new TextEncoder().encode('session')
    const subtle = vi.spyOn(globalThis.crypto, 'subtle', 'get').mockReturnValue(undefined as unknown as SubtleCrypto)
    try {
      const envelope = await sealBrowserSessionEnvelope(plaintext, key, context)
      await expect(openBrowserSessionEnvelope(envelope, key, validTime)).resolves.toEqual(plaintext)
    } finally {
      subtle.mockRestore()
      wipe(key)
      wipe(plaintext)
    }
  })

  it('round-trips under a domain-separated master-key subkey', async () => {
    const key = new Uint8Array(32).fill(0x41)
    const plaintext = new TextEncoder().encode('{"refreshToken":"secret"}')
    const envelope = await sealBrowserSessionEnvelope(plaintext, key, context)
    try {
      expect(envelope.protocolVersion).toBe(BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION)
      expect(JSON.stringify(envelope)).not.toContain('refreshToken')
      expect(JSON.stringify(envelope)).not.toContain('secret')
      await expect(openBrowserSessionEnvelope(envelope, key, validTime)).resolves.toEqual(plaintext)
    } finally {
      wipe(key)
      wipe(plaintext)
    }
  })

  it('rejects ciphertext, origin, account, client, protocol, and expiry tampering', async () => {
    const key = new Uint8Array(32).fill(0x42)
    const plaintext = new TextEncoder().encode('session')
    const envelope = await sealBrowserSessionEnvelope(plaintext, key, context)
    const payload = fromBase64Url(envelope.encodedSuitePayload)
    payload[payload.length - 1] ^= 1
    const tamperedPayload = btoa(String.fromCharCode(...payload))
      .replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
    const cases: unknown[] = [
      { ...envelope, encodedSuitePayload: tamperedPayload },
      { ...envelope, context: { ...context, apiUrl: 'https://api.stage.palladin.io' } },
      { ...envelope, context: { ...context, accountId: '11111111-2222-4333-8444-555555555555' } },
      { ...envelope, context: { ...context, clientId: 'different-extension-client' } },
      { ...envelope, protocolVersion: 2 },
      { ...envelope, context: { ...context, expiresAt: context.issuedAt } },
    ]
    try {
      for (const candidate of cases) {
        await expect(openBrowserSessionEnvelope(candidate, key, validTime)).rejects.toThrow()
      }
    } finally {
      wipe(key)
      wipe(plaintext)
      wipe(payload)
    }
  })

  it('rejects a wrong master key and unknown fields', async () => {
    const key = new Uint8Array(32).fill(0x43)
    const wrong = new Uint8Array(32).fill(0x44)
    const plaintext = new TextEncoder().encode('session')
    const envelope = await sealBrowserSessionEnvelope(plaintext, key, context)
    try {
      await expect(openBrowserSessionEnvelope(envelope, wrong, validTime)).rejects.toThrow()
      expect(() => parseBrowserSessionEnvelope({ ...envelope, downgrade: true })).toThrow(
        'unexpected fields',
      )
    } finally {
      wipe(key)
      wipe(wrong)
      wipe(plaintext)
    }
  })

  it('requires the canonical lowercase account ID in sealed and parsed contexts', async () => {
    const key = new Uint8Array(32).fill(0x47)
    const plaintext = new TextEncoder().encode('session')
    const uppercaseAccountId = context.accountId.toUpperCase()
    const envelope = await sealBrowserSessionEnvelope(plaintext, key, context)
    try {
      await expect(sealBrowserSessionEnvelope(plaintext, key, {
        ...context,
        accountId: uppercaseAccountId,
      })).rejects.toThrow('account ID')
      expect(() => parseBrowserSessionEnvelope({
        ...envelope,
        context: { ...envelope.context, accountId: uppercaseAccountId },
      })).toThrow('account ID')
    } finally {
      wipe(key)
      wipe(plaintext)
    }
  })

  it('accepts a canonical Firefox WebExtension runtime ID but rejects controls', async () => {
    const key = new Uint8Array(32).fill(0x45)
    const plaintext = new TextEncoder().encode('session')
    try {
      await expect(sealBrowserSessionEnvelope(plaintext, key, {
        ...context,
        clientId: 'browser-extension@palladin.io',
      })).resolves.toMatchObject({
        context: { clientId: 'browser-extension@palladin.io' },
      })
      await expect(sealBrowserSessionEnvelope(plaintext, key, {
        ...context,
        clientId: 'browser-extension@palladin.io\nforged',
      })).rejects.toThrow('client ID')
    } finally {
      wipe(key)
      wipe(plaintext)
    }
  })

  it('rejects authenticated sessions before issuance and at or after expiry', async () => {
    const key = new Uint8Array(32).fill(0x46)
    const plaintext = new TextEncoder().encode('session')
    const envelope = await sealBrowserSessionEnvelope(plaintext, key, context)
    try {
      await expect(openBrowserSessionEnvelope(envelope, key, {
        now: () => context.issuedAt - 1,
      })).rejects.toThrow('validity window')
      await expect(openBrowserSessionEnvelope(envelope, key, {
        now: () => context.expiresAt,
      })).rejects.toThrow('validity window')
      await expect(openBrowserSessionEnvelope(envelope, key, {
        now: () => context.expiresAt - 1,
      })).resolves.toEqual(plaintext)
    } finally {
      wipe(key)
      wipe(plaintext)
    }
  })
})
