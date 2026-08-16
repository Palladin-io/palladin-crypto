import { describe, expect, it } from 'vitest'

import { fromBase64Url, toBase64Url } from './encoding'
import {
  assertIdentityKdfProfile,
  deriveIdentityV1,
  IDENTITY_KDF_PROFILE,
  IDENTITY_KDF_PROFILE_ID,
  IDENTITY_SECURITY_VERSION,
} from './identity-kdf'
import { wipe } from './sodium'

const vector = {
  password: 'Pąssw🔐rd-密碼-v1',
  accountId: '00112233-4455-4677-8899-aabbccddeeff',
  kdfSalt: 'AAECAwQFBgcICQoLDA0ODw',
  authCredential: 'aRKTmLFcaSbzQy83MTRpf5PfLSjeBLGQP4HVpEudV7I',
  masterKey: 'HtGyf-Z7BvE39e66VcP2bztQ0BBKmfzvBGCp_nLiXbk',
} as const

describe('Identity password KDF v1', () => {
  it('matches the frozen backend and web vector', async () => {
    const salt = fromBase64Url(vector.kdfSalt)
    const result = await deriveIdentityV1(vector.password, vector.accountId, salt)
    try {
      expect(toBase64Url(result.authCredential)).toBe(vector.authCredential)
      expect(toBase64Url(result.masterKey)).toBe(vector.masterKey)
    } finally {
      wipe(salt)
      wipe(result.authCredential)
      wipe(result.masterKey)
    }
  })

  it('accepts only the exact frozen profile', () => {
    expect(() => assertIdentityKdfProfile({
      profileId: IDENTITY_KDF_PROFILE_ID,
      securityVersion: IDENTITY_SECURITY_VERSION,
      kdfSalt: vector.kdfSalt,
      memoryKiB: IDENTITY_KDF_PROFILE.memoryKiB,
      iterations: IDENTITY_KDF_PROFILE.iterations,
      parallelism: IDENTITY_KDF_PROFILE.parallelism,
    })).not.toThrow()

    expect(() => assertIdentityKdfProfile({
      profileId: IDENTITY_KDF_PROFILE_ID,
      securityVersion: IDENTITY_SECURITY_VERSION + 1,
      kdfSalt: vector.kdfSalt,
      memoryKiB: IDENTITY_KDF_PROFILE.memoryKiB,
      iterations: IDENTITY_KDF_PROFILE.iterations,
      parallelism: IDENTITY_KDF_PROFILE.parallelism,
    })).toThrow('upgrade-required')
  })

  it('rejects overlong UTF-8 passwords before Argon2id', async () => {
    await expect(deriveIdentityV1(
      '🔐'.repeat(257),
      vector.accountId,
      fromBase64Url(vector.kdfSalt),
    )).rejects.toThrow('password-too-long')
  })
})
