import { afterEach, expect, it, vi } from 'vitest'
import rawFixture from './fixtures/shared-unlock-v1/identity-proof-fixtures.json'
import { loadSodium } from './sodium-loader'
import { fromBase64Url, toBase64Url } from './encoding'
import { createSharedUnlockIdentityProofSigner, encodeSharedUnlockIdentityProof } from './shared-unlock-identity-proof'
import type { SharedUnlockProofPurpose, SharedUnlockIdentityProofContext } from './shared-unlock-identity-proof'

const fixture = rawFixture as typeof rawFixture & { positive: { purpose: SharedUnlockProofPurpose }[] }
afterEach(() => vi.restoreAllMocks())
async function signer(extra: Partial<Parameters<typeof createSharedUnlockIdentityProofSigner>[0]> = {}) {
  const sodium = await loadSodium()
  const pair = sodium.crypto_sign_seed_keypair(fromBase64Url(fixture.syntheticSeed))
  vi.spyOn(sodium, 'crypto_sign_keypair').mockImplementationOnce((() => pair) as typeof sodium.crypto_sign_keypair)
  return { participant: await createSharedUnlockIdentityProofSigner({ assertCurrent: () => {}, now: () => fixture.positive[0].context.issuedAtMs, ...extra }), privateKey: pair.privateKey }
}
for (const vector of fixture.positive) {
  it(`matches independent Node Ed25519 bytes: ${vector.name}`, async () => {
    const { participant, privateKey } = await signer()
    expect(participant.publicKey).toBe(vector.recipientProofPublicKey)
    expect(toBase64Url(encodeSharedUnlockIdentityProof(vector.context, participant.publicKey, vector.purpose))).toBe(vector.message)
    if (vector.purpose === 'commit') participant.sign(vector.context, 'consume')
    expect(participant.sign(vector.context, vector.purpose)).toBe(vector.signature)
    if (vector.purpose === 'commit') expect(privateKey.every(value => value === 0)).toBe(true)
    participant.dispose()
    expect(privateKey.every(value => value === 0)).toBe(true)
  })
}
const context = fixture.positive[0].context
const rejection = 'Shared unlock Identity proof rejected'
it('rejects commit-before-consume and destroys the attempted signer', async () => {
  const { participant, privateKey } = await signer()
  expect(() => participant.sign(context, 'commit')).toThrow(rejection)
  expect(() => participant.sign(context, 'consume')).toThrow(rejection)
  expect(privateKey.every(value => value === 0)).toBe(true)
})
it('rejects replay of consume or commit', async () => {
  for (const purpose of ['consume', 'commit'] as const) {
    const { participant } = await signer()
    participant.sign(context, 'consume')
    if (purpose === 'commit') participant.sign(context, 'commit')
    expect(() => participant.sign(context, purpose)).toThrow(rejection)
  }
})
for (const field of ['operationId', 'challenge', 'transcriptHash', 'issuedAtMs', 'expiresAtMs'] as const) {
  it(`rejects ${field} substitution between consume and commit`, async () => {
    const { participant } = await signer()
    participant.sign(context, 'consume')
    const changed = { ...context }
    if (field === 'operationId') changed[field] = `9${changed[field].slice(1)}`
    else if (field === 'issuedAtMs') changed[field] += 1
    else if (field === 'expiresAtMs') changed[field] -= 1
    else changed[field] = toBase64Url(new Uint8Array(32).fill(3))
    expect(() => participant.sign(changed, 'commit')).toThrow(rejection)
  })
}
it('rejects unknown fields, purposes, malformed encodings and excessive lifetime', async () => {
  const changes = [
    { extra: true }, { challenge: `${context.challenge}=` }, { transcriptHash: '' },
    { operationId: '00000000-0000-0000-0000-000000000000' },
    { expiresAtMs: context.issuedAtMs + 30_001 }, { issuedAtMs: 1.5 },
  ]
  for (const change of changes) {
    const { participant } = await signer()
    expect(() => participant.sign({ ...context, ...change }, 'consume')).toThrow(rejection)
  }
  const { participant } = await signer()
  expect(() => participant.sign(context, 'unknown' as SharedUnlockProofPurpose)).toThrow(rejection)
})
for (const time of [context.issuedAtMs - 1, context.expiresAtMs, Number.NaN]) {
  it(`rejects invalid current time ${time}`, async () => {
    const { participant } = await signer({ now: () => time })
    expect(() => participant.sign(context, 'consume')).toThrow(rejection)
  })
}
it('rejects revocation between consume and commit and wipes private key', async () => {
  let revoked = false
  const { participant, privateKey } = await signer({ assertCurrent: () => { if (revoked) throw new Error('synthetic revocation') } })
  participant.sign(context, 'consume')
  revoked = true
  expect(() => participant.sign(context, 'commit')).toThrow(rejection)
  expect(privateKey.every(value => value === 0)).toBe(true)
})
it('freezes a separate authority snapshot', async () => {
  let received: Readonly<SharedUnlockIdentityProofContext> | undefined
  const { participant } = await signer({ assertCurrent: expected => { received = expected } })
  const mutable = { ...context }
  participant.sign(mutable, 'consume')
  mutable.operationId = `9${mutable.operationId.slice(1)}`
  expect(received!.operationId).toBe(context.operationId)
  expect(Object.isFrozen(received)).toBe(true)
  expect(() => participant.sign(mutable, 'commit')).toThrow(rejection)
})
for (const replacement of [false, true]) {
  it(`burns a reentrant consume attempt with ${replacement ? 'another' : 'the same'} context`, async () => {
    let nested = false
    let invoke = () => {}
    const signatures: string[] = []
    const { participant, privateKey } = await signer({ assertCurrent: () => {
      if (nested) return
      nested = true
      try { invoke() } catch { /* An adapter may catch cancellation; the outer attempt must still fail. */ }
    } })
    const other = replacement ? { ...context, operationId: `9${context.operationId.slice(1)}` } : context
    invoke = () => { signatures.push(participant.sign(other, 'consume')) }
    expect(() => participant.sign(context, 'consume')).toThrow(rejection)
    expect(signatures).toEqual([])
    expect(() => participant.sign(context, 'commit')).toThrow(rejection)
    expect(privateKey.every(value => value === 0)).toBe(true)
  })
}
