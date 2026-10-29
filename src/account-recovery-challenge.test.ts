import { afterEach, describe, expect, it, vi } from 'vitest'
import vectors from './fixtures/account-recovery-challenge-v1/vectors.json'
import {
  ACCOUNT_RECOVERY_CHALLENGE_MAGIC,
  ACCOUNT_RECOVERY_CHALLENGE_PLAINTEXT_BYTES,
  ACCOUNT_RECOVERY_CHALLENGE_SEALED_BYTES,
  ACCOUNT_RECOVERY_PROOF_BYTES,
  AccountRecoveryChallengeError,
  openAccountRecoveryChallenge,
} from './account-recovery-challenge'
import { fromBase64Url, toBase64Url } from './encoding'
import { loadSodium } from './sodium-loader'
import * as publicApi from './index'

const privateKey = () => fromBase64Url(vectors.recipientPrivateKey)
afterEach(() => vi.restoreAllMocks())

describe('openAccountRecoveryChallenge', () => {
  it('returns the 32-byte secret of a valid challenge bound to the caller', async () => {
    const proof = await openAccountRecoveryChallenge(vectors.valid.sealedChallenge, vectors.userId, privateKey())
    expect(proof).toHaveLength(ACCOUNT_RECOVERY_PROOF_BYTES)
    expect(toBase64Url(proof)).toBe(vectors.valid.recoveryProof)
  })

  it('pins the registered layout constants', async () => {
    expect(ACCOUNT_RECOVERY_CHALLENGE_MAGIC).toBe('PLDNRCV1')
    expect(ACCOUNT_RECOVERY_CHALLENGE_PLAINTEXT_BYTES).toBe(56)
    expect(ACCOUNT_RECOVERY_CHALLENGE_SEALED_BYTES).toBe(104)
    const sodium = await loadSodium()
    expect(toBase64Url(sodium.crypto_scalarmult_base(privateKey()))).toBe(vectors.recipientPublicKey)
    expect(vectors.plaintextHex).toHaveLength(ACCOUNT_RECOVERY_CHALLENGE_PLAINTEXT_BYTES * 2)
  })

  for (const vector of vectors.negative) {
    it(`rejects ${vector.name} with one error type`, async () => {
      await expect(openAccountRecoveryChallenge(vector.sealedChallenge, vectors.userId, privateKey()))
        .rejects.toThrow(AccountRecoveryChallengeError)
    })
  }

  it('rejects a valid challenge opened on behalf of another user', async () => {
    await expect(openAccountRecoveryChallenge(
      vectors.valid.sealedChallenge,
      '7d4c3b2a-1f0e-4a9b-8c7d-6e5f4a3b2c1d',
      privateKey(),
    )).rejects.toThrow(AccountRecoveryChallengeError)
  })

  it('rejects malformed caller input with the same error type', async () => {
    for (const [sealed, userId, key] of [
      [vectors.valid.sealedChallenge, vectors.userId.toUpperCase(), privateKey()],
      [vectors.valid.sealedChallenge, 'not-a-uuid', privateKey()],
      [vectors.valid.sealedChallenge, vectors.userId, new Uint8Array(31)],
      ['', vectors.userId, privateKey()],
    ] as const) {
      await expect(openAccountRecoveryChallenge(sealed, userId, key)).rejects.toThrow(AccountRecoveryChallengeError)
    }
  })

  it('wipes the opened plaintext on success and rejection', async () => {
    const sodium = await loadSodium()
    const opened: Uint8Array[] = []
    const original = sodium.crypto_box_seal_open.bind(sodium)
    vi.spyOn(sodium, 'crypto_box_seal_open').mockImplementation(((...args: Parameters<typeof original>) => {
      const result = original(...args)
      opened.push(result as unknown as Uint8Array)
      return result
    }) as typeof sodium.crypto_box_seal_open)

    await openAccountRecoveryChallenge(vectors.valid.sealedChallenge, vectors.userId, privateKey())
    const other = vectors.negative.find((vector) => vector.name === 'other-user-id')!
    await expect(openAccountRecoveryChallenge(other.sealedChallenge, vectors.userId, privateKey()))
      .rejects.toThrow(AccountRecoveryChallengeError)

    expect(opened).toHaveLength(2)
    for (const buffer of opened) expect(buffer.every((byte) => byte === 0)).toBe(true)
  })

  it('is exported from the package entry', () => {
    expect(publicApi.openAccountRecoveryChallenge).toBe(openAccountRecoveryChallenge)
    expect(publicApi.AccountRecoveryChallengeError).toBe(AccountRecoveryChallengeError)
  })
})
