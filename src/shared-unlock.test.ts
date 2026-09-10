import { afterEach, describe, expect, it, vi } from 'vitest'
import rawFixture from './fixtures/shared-unlock-v1/fixtures.json'
import { loadSodium } from './sodium-loader'
import { fromBase64Url, toBase64Url } from './encoding'
import { createSharedUnlockParticipant, encodeSharedUnlockTranscript } from './shared-unlock'
import type { SharedUnlockContext, SharedUnlockEnvelope } from './shared-unlock'

const fixture = rawFixture as {
  positive: { name: string; nowMs: number; synthetic: { sourcePrivateKey: string; recipientPrivateKey: string; masterKey: string }; transcript: string; envelope: SharedUnlockEnvelope }[]
  negative: { name: string; mutation?: string; field?: string }[]
}
afterEach(() => vi.restoreAllMocks())
const bytes = fromBase64Url
const rejection = 'Shared unlock operation rejected'
for (const vector of fixture.positive) {
  const expected = vector.envelope.context
  const create = async (role: 'source' | 'recipient', extra: Partial<Parameters<typeof createSharedUnlockParticipant>[0]> = {}) => {
    const sodium = await loadSodium()
    const privateKey = bytes(role === 'source' ? vector.synthetic.sourcePrivateKey : vector.synthetic.recipientPrivateKey)
    // Production calls the byte-output overload; test-only deterministic keypair.
    vi.spyOn(sodium, 'crypto_kx_keypair').mockImplementationOnce((() => ({ privateKey, publicKey: sodium.crypto_scalarmult_base(privateKey), keyType: 'x25519' })) as typeof sodium.crypto_kx_keypair)
    return createSharedUnlockParticipant({ role, expected, assertCurrent: () => {}, now: () => vector.nowMs, ...extra })
  }
  describe(vector.name, () => {
    it('matches independently generated transcript and opens Node X25519/HKDF fixture', async () => {
      expect(toBase64Url(encodeSharedUnlockTranscript(expected, vector.envelope.sourcePublicKey, vector.envelope.recipientPublicKey))).toBe(vector.transcript)
      const recipient = await create('recipient')
      const masterKey = await recipient.open(vector.envelope, vector.envelope.sourcePublicKey)
      expect(toBase64Url(masterKey)).toBe(vector.synthetic.masterKey)
      masterKey.fill(0)
    })
    it('seals interoperable ciphertext and wipes its own keys without changing the caller MK', async () => {
      const source = await create('source')
      const recipient = await create('recipient')
      const masterKey = bytes(vector.synthetic.masterKey)
      const envelope = await source.seal(masterKey, recipient.publicKey)
      expect(masterKey).toEqual(bytes(vector.synthetic.masterKey))
      expect(await recipient.open(envelope, source.publicKey)).toEqual(masterKey)
      await expect(source.seal(masterKey, recipient.publicKey)).rejects.toThrow(rejection)
    })
    for (const mutation of fixture.negative.filter(item => item.mutation)) {
      it(`rejects ${mutation.name} and burns the attempted operation`, async () => {
        const recipient = await create('recipient')
        const envelope = structuredClone(vector.envelope)
        const target = (mutation.mutation === 'context' ? envelope.context : envelope) as unknown as Record<string, unknown>
        const field = mutation.field!
        const old = target[field]
        if (typeof old === 'number') target[field] = old + 1
        else if (field === 'direction') target[field] = vector.name === 'web-to-extension' ? 'extension-to-web' : 'web-to-extension'
        else if (['protocol', 'suite'].includes(field)) target[field] = `${old}x`
        else if (field.endsWith('Origin')) target[field] = 'https://foreign.example.test'
        else if (['operationId', 'accountId', 'organizationId', 'linkId'].includes(field)) target[field] = `9${String(old).slice(1)}`
        else if (['extensionId', 'documentBinding'].includes(field)) target[field] = `foreign-${old}`
        else { const changed = bytes(String(old)); changed[0] ^= 1; target[field] = toBase64Url(changed) }
        await expect(recipient.open(envelope, vector.envelope.sourcePublicKey)).rejects.toThrow(rejection)
        await expect(recipient.open(vector.envelope, vector.envelope.sourcePublicKey)).rejects.toThrow(rejection)
      })
    }
    for (const part of ['context', 'envelope'] as const) {
      it(`rejects unknown-${part}-field`, async () => {
        const recipient = await create('recipient')
        const envelope = structuredClone(vector.envelope)
        Object.assign(part === 'context' ? envelope.context : envelope, { extra: true })
        await expect(recipient.open(envelope, vector.envelope.sourcePublicKey)).rejects.toThrow(rejection)
      })
    }
    it('rejects replay, including concurrent consume', async () => {
      const recipient = await create('recipient')
      const first = recipient.open(vector.envelope, vector.envelope.sourcePublicKey)
      const second = recipient.open(vector.envelope, vector.envelope.sourcePublicKey)
      const results = await Promise.allSettled([first, second])
      expect(results.every(result => result.status === 'rejected')).toBe(true)
      await expect(recipient.open(vector.envelope, vector.envelope.sourcePublicKey)).rejects.toThrow(rejection)
    })
    it('rejects reflection into the opposite direction', async () => {
      const other = fixture.positive.find(item => item.name !== vector.name)!
      const recipient = await create('recipient', { expected: other.envelope.context })
      await expect(recipient.open(vector.envelope, vector.envelope.sourcePublicKey)).rejects.toThrow(rejection)
    })
    for (const [name, time] of [['expiry', expected.expiresAtMs], ['future', expected.issuedAtMs - 1]] as const) {
      it(`rejects ${name} before key creation completes`, async () => {
        await expect(create('recipient', { now: () => time })).rejects.toThrow(rejection)
      })
    }
    it('rejects wrong-key from a different verified source', async () => {
      const recipient = await create('recipient')
      await expect(recipient.open(vector.envelope, toBase64Url(new Uint8Array(32).fill(8)))).rejects.toThrow(rejection)
    })
    it('rejects low-order-key', async () => {
      const source = await create('source')
      await expect(source.seal(bytes(vector.synthetic.masterKey), toBase64Url(new Uint8Array(32)))).rejects.toThrow(rejection)
    })
    it('rejects cancel-during-derive', async () => {
      const recipient = await create('recipient')
      const opening = recipient.open(vector.envelope, vector.envelope.sourcePublicKey)
      recipient.dispose()
      await expect(opening).rejects.toThrow(rejection)
    })
    it('rejects authority-revoked during async key derivation', async () => {
      let revoked = false
      const recipient = await create('recipient', { assertCurrent: () => { if (revoked) throw new Error('synthetic revocation') } })
      const opening = recipient.open(vector.envelope, vector.envelope.sourcePublicKey)
      revoked = true
      await expect(opening).rejects.toThrow(rejection)
    })
    it('rejects expiry while deriving', async () => {
      let time = vector.nowMs
      const recipient = await create('recipient', { now: () => time })
      const opening = recipient.open(vector.envelope, vector.envelope.sourcePublicKey)
      time = expected.expiresAtMs
      await expect(opening).rejects.toThrow(rejection)
    })
    it('snapshots authority and untrusted input before yielding', async () => {
      const authority = structuredClone(expected)
      const recipient = await create('recipient', { expected: authority })
      const envelope = structuredClone(vector.envelope)
      const opening = recipient.open(envelope, vector.envelope.sourcePublicKey)
      authority.accountId = fixture.positive[0].envelope.context.organizationId
      envelope.ciphertext = ''
      expect(toBase64Url(await opening)).toBe(vector.synthetic.masterKey)
    })
    it('rejects excessive TTL, expired inherited deadline and noncanonical fields', async () => {
      const patches: Partial<SharedUnlockContext>[] = [
        { expiresAtMs: expected.issuedAtMs + 30_001 }, { idleDeadlineMs: expected.issuedAtMs },
        { absoluteDeadlineMs: expected.issuedAtMs }, { offlineDeadlineMs: expected.issuedAtMs },
        { webOrigin: 'http://example.test' }, { apiOrigin: `${expected.apiOrigin}/` },
        { linkEpoch: Number.MAX_SAFE_INTEGER + 1 }, { webGeneration: `${expected.webGeneration}=` },
      ]
      for (const patch of patches) await expect(createSharedUnlockParticipant({ role: 'recipient', expected: { ...expected, ...patch }, assertCurrent: () => {} })).rejects.toThrow(rejection)
    })
    it('requires the final authority check after decryption', async () => {
      let checks = 0
      const recipient = await create('recipient', { assertCurrent: () => { if (++checks === 4) throw new Error('synthetic final revocation') } })
      await expect(recipient.open(vector.envelope, vector.envelope.sourcePublicKey)).rejects.toThrow(rejection)
      expect(checks).toBe(4)
    })
  })
}
