import { describe, expect, it } from 'vitest'
import { fromBase64Url, toBase64Url } from './encoding'
import derivation from './fixtures/identity-kdf-v2/derivation-vectors.json'
import v3 from './fixtures/identity-kdf-v3/vectors.json'
import {
  accountSecretPasswordPrehash,
  assertIdentityAccountSecretProfile,
  deriveAccountSecretOutputsFromRoot,
  deriveIdentityV2,
  encodeEmergencyKitQr,
  formatSecretKey,
  generateAccountSecret,
  IDENTITY_ACCOUNT_SECRET_PROFILE,
  identityKdfProfileVersion,
  parseEmergencyKitQr,
  parseSecretKey,
  SecretKeyError,
} from './identity-account-secret'
import { deriveIdentityV1, IDENTITY_KDF_PROFILE } from './identity-kdf'
import { getCryptoProvider } from './provider/active-provider'
import { decodeHex, encodeUtf8 } from './vault-v2-bytes'

const input = derivation.input
const secret = fromBase64Url(input.accountSecretBase64url)
const salt = fromBase64Url(input.kdfSaltBase64url)

function secretKeyErrorCode(action: () => unknown): string | undefined {
  try {
    action()
  } catch (error) {
    return error instanceof SecretKeyError ? error.code : `unexpected: ${String(error)}`
  }
  return undefined
}

describe('Identity Account Secret KDF v2', () => {
  it('matches the identity-kdf v2 framing vector', () => {
    const password = encodeUtf8(input.password)
    expect(password).toEqual(decodeHex(input.passwordUtf8Hex))
    expect(toBase64Url(accountSecretPasswordPrehash(password, secret))).toBe(derivation.expected.passwordPrehashBase64url)

    const outputs = deriveAccountSecretOutputsFromRoot(fromBase64Url(input.syntheticAccountRootBase64url), input.accountId, salt)
    expect(toBase64Url(outputs.authCredential)).toBe(derivation.expected.authCredentialBase64url)
    expect(toBase64Url(outputs.masterKey)).toBe(derivation.expected.masterKeyBase64url)
  })

  it('derives the account root with the registered Argon2id profile over the prehash', async () => {
    const outputs = await deriveIdentityV2(input.password, secret, input.accountId, salt)
    const root = await getCryptoProvider().deriveKey(
      accountSecretPasswordPrehash(encodeUtf8(input.password), secret),
      salt,
      { memorySize: 32_768, iterations: 2, parallelism: 1, hashLength: 32 },
    )
    expect(outputs).toEqual(deriveAccountSecretOutputsFromRoot(root, input.accountId, salt))

    const otherSecret = await deriveIdentityV2(input.password, new Uint8Array(32).fill(1), input.accountId, salt)
    expect(otherSecret.authCredential).not.toEqual(outputs.authCredential)
    const legacy = await deriveIdentityV1(input.password, input.accountId, salt)
    expect(legacy.authCredential).not.toEqual(outputs.authCredential)
  })

  it('requires the Account Secret and a bounded password before any KDF', async () => {
    await expect(deriveIdentityV2(input.password, new Uint8Array(16), input.accountId, salt)).rejects.toThrow('account-secret-required')
    await expect(deriveIdentityV2('🔐'.repeat(257), secret, input.accountId, salt)).rejects.toThrow('password-too-long')
  })

  it('selects only the two registered profiles and rejects tuned parameters', () => {
    const v2 = {
      profileId: IDENTITY_ACCOUNT_SECRET_PROFILE.id,
      securityVersion: 2,
      kdfSalt: input.kdfSaltBase64url,
      memoryKiB: 32_768,
      iterations: 2,
      parallelism: 1,
    }
    expect(identityKdfProfileVersion(v2)).toBe(2)
    expect(identityKdfProfileVersion({ ...v2, profileId: IDENTITY_KDF_PROFILE.id, securityVersion: 1 })).toBe(1)
    expect(() => assertIdentityAccountSecretProfile({ ...v2, iterations: 1 })).toThrow('unsupported-kdf-profile')
    expect(() => identityKdfProfileVersion({ ...v2, securityVersion: 3 })).toThrow('upgrade-required')
  })

  it('generates 32 random bytes', async () => {
    const [first, second] = [await generateAccountSecret(), await generateAccountSecret()]
    expect(first).toHaveLength(32)
    expect(first).not.toEqual(second)
  })
})

describe('Secret Key display (PSK2)', () => {
  const vector = v3.secretKeyDisplay
  const accountSecret = fromBase64Url(vector.accountSecretBase64url)

  it('formats and parses the vector and its equivalent inputs', () => {
    expect(formatSecretKey(vector.accountId, accountSecret)).toBe(vector.display)
    for (const value of [vector.display, ...vector.equivalentInputs]) {
      expect(parseSecretKey(vector.accountId, value)).toEqual(accountSecret)
    }
  })

  it.each(vector.negative)('rejects $input as $error', ({ input: value, accountId, error }) => {
    expect(secretKeyErrorCode(() => parseSecretKey(accountId ?? vector.accountId, value))).toBe(error)
  })

  it('rejects non-zero padding bits', () => {
    const symbols = vector.display.replaceAll('-', '').slice(4)
    const padded = `PSK2${symbols.slice(0, 51)}1${symbols.slice(52)}`
    expect(secretKeyErrorCode(() => parseSecretKey(vector.accountId, padded))).toBe('secret-key-malformed')
  })
})

describe('Emergency Kit QR payload', () => {
  const vector = v3.emergencyKitQr
  const accountSecret = fromBase64Url(v3.secretKeyDisplay.accountSecretBase64url)

  it('encodes and parses the vector for the account being unlocked', () => {
    expect(encodeEmergencyKitQr(vector.accountId, accountSecret)).toBe(vector.payload)
    expect(parseEmergencyKitQr(vector.accountId, vector.payload)).toEqual(accountSecret)
  })

  it.each([
    ['another account', '00112233-4455-6677-8899-aabbccddeef0', vector.payload, 'account-mismatch'],
    ['a wrong prefix', vector.accountId, vector.payload.replace('kit:v1', 'kit:v2'), 'secret-key-malformed'],
    ['padded base64url', vector.accountId, `${vector.payload}=`, 'secret-key-malformed'],
    ['a short secret', vector.accountId, vector.payload.slice(0, -2), 'secret-key-malformed'],
    ['an extra part', vector.accountId, `${vector.payload}.AA`, 'secret-key-malformed'],
  ])('rejects %s', (_case, accountId, payload, code) => {
    expect(secretKeyErrorCode(() => parseEmergencyKitQr(accountId, payload))).toBe(code)
  })
})
