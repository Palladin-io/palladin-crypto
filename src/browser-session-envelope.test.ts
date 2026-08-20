import { describe, expect, it } from 'vitest'

import {
  BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION,
  openBrowserSessionEnvelope,
  parseBrowserSessionEnvelope,
  sealBrowserSessionEnvelope,
  type BrowserSessionEnvelopeContext,
} from './browser-session-envelope'
import { fromBase64Url } from './encoding'
import { wipe } from './sodium'

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
