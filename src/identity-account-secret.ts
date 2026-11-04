import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { fromBase64Url, toBase64Url } from './encoding'
import { assertIdentityKdfProfile, type IdentityKdfMetadata, type IdentityKdfOutputs, IDENTITY_KDF_SALT_BYTES, IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES } from './identity-kdf'
import { deriveHkdfSha256, sha256Digest } from './portable-sha256'
import { getCryptoProvider } from './provider/active-provider'
import { wipe } from './sodium'
import { concatBytes, decodeUuid, encodeU16, encodeU32, encodeUtf8 } from './vault-v2-bytes'

/** palladin-protocol `identity-kdf/v2` (derivation) and `identity-kdf/v3` (encodings). */
export const IDENTITY_ACCOUNT_SECRET_PROFILE = Object.freeze({
  id: 'identity-argon2id-account-secret-v2',
  securityVersion: 2,
  memoryKiB: 32_768,
  iterations: 2,
  parallelism: 1,
  outputBytes: 32,
})

export const ACCOUNT_SECRET_BYTES = 32

export type SecretKeyErrorCode = 'secret-key-malformed' | 'secret-key-checksum-mismatch' | 'account-mismatch'

/** Carries only a contract error code; never the input or any secret. */
export class SecretKeyError extends Error {
  readonly code: SecretKeyErrorCode

  constructor(code: SecretKeyErrorCode) {
    super(code)
    this.name = 'SecretKeyError'
    this.code = code
  }
}

const PREHASH_MAGIC = encodeUtf8('PLDNID2PW')
const OUTPUT_SALT_MAGIC = encodeUtf8('PLDNID2HK')
const AUTH_INFO = encodeUtf8('palladin:identity:v2:auth-credential')
const MASTER_KEY_INFO = encodeUtf8('palladin:identity:v2:master-key')
const CHECKSUM_MAGIC = encodeUtf8('PLDNSK2CHK')
const SECURITY_VERSION = encodeU16(IDENTITY_ACCOUNT_SECRET_PROFILE.securityVersion)
const SECRET_KEY_PREFIX = 'PSK2'
const EMERGENCY_KIT_PREFIX = 'palladin-kit:v1:'

export const CROCKFORD_BASE32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** Most-significant-bit-first Crockford base32 of the first `bitLength` bits, zero-padded to whole symbols. */
export function encodeCrockfordBits(bytes: Uint8Array, bitLength: number): string {
  let output = ''
  for (let offset = 0; offset < bitLength; offset += 5) {
    let symbol = 0
    for (let bit = offset; bit < offset + 5; bit++) {
      const value = bit < bitLength ? (bytes[bit >> 3] >> (7 - (bit & 7))) & 1 : 0
      symbol = (symbol << 1) | value
    }
    output += CROCKFORD_BASE32[symbol]
  }
  return output
}

/**
 * Throws `upgrade-required` for an unknown newer profile and
 * `unsupported-kdf-profile` for any parameter mismatch, before any KDF runs.
 */
export function assertIdentityAccountSecretProfile(metadata: IdentityKdfMetadata): void {
  const profile = IDENTITY_ACCOUNT_SECRET_PROFILE
  const matches = metadata.profileId === profile.id
    && metadata.securityVersion === profile.securityVersion
    && metadata.memoryKiB === profile.memoryKiB
    && metadata.iterations === profile.iterations
    && metadata.parallelism === profile.parallelism
  if (!matches) {
    throw new Error(metadata.securityVersion > profile.securityVersion ? 'upgrade-required' : 'unsupported-kdf-profile')
  }
  if (fromBase64Url(metadata.kdfSalt, IDENTITY_KDF_SALT_BYTES).length !== IDENTITY_KDF_SALT_BYTES) {
    throw new TypeError('Invalid Identity KDF salt length')
  }
}

/** Accepts the production password-only profile or the Account Secret profile; anything else fails before the KDF. */
export function identityKdfProfileVersion(metadata: IdentityKdfMetadata): 1 | 2 {
  if (metadata.securityVersion === IDENTITY_ACCOUNT_SECRET_PROFILE.securityVersion) {
    assertIdentityAccountSecretProfile(metadata)
    return 2
  }
  assertIdentityKdfProfile(metadata)
  return 1
}

export async function generateAccountSecret(): Promise<Uint8Array> {
  const provider = getCryptoProvider()
  await provider.ready()
  return provider.randomBytes(ACCOUNT_SECRET_BYTES)
}

export function accountSecretPasswordPrehash(password: Uint8Array, accountSecret: Uint8Array): Uint8Array {
  return hmac(sha256, accountSecret, concatBytes(PREHASH_MAGIC, SECURITY_VERSION, encodeU32(password.length), password))
}

export function deriveAccountSecretOutputsFromRoot(
  accountRoot: Uint8Array,
  accountId: string,
  kdfSalt: Uint8Array,
): IdentityKdfOutputs {
  if (accountRoot.length !== IDENTITY_ACCOUNT_SECRET_PROFILE.outputBytes || kdfSalt.length !== IDENTITY_KDF_SALT_BYTES) {
    throw new TypeError('Invalid Identity KDF input length')
  }
  const outputSalt = sha256Digest(concatBytes(OUTPUT_SALT_MAGIC, SECURITY_VERSION, decodeUuid(accountId), kdfSalt))
  try {
    return {
      authCredential: deriveHkdfSha256(accountRoot, outputSalt, AUTH_INFO),
      masterKey: deriveHkdfSha256(accountRoot, outputSalt, MASTER_KEY_INFO),
    }
  } finally {
    outputSalt.fill(0)
  }
}

/**
 * Identity KDF security version 2: Argon2id over an HMAC of the exact UTF-8
 * password keyed by the 32-byte Account Secret (Secret Key).
 */
export async function deriveIdentityV2(
  password: string,
  accountSecret: Uint8Array,
  accountId: string,
  kdfSalt: Uint8Array,
): Promise<IdentityKdfOutputs> {
  if (accountSecret.length !== ACCOUNT_SECRET_BYTES) throw new Error('account-secret-required')
  if (kdfSalt.length !== IDENTITY_KDF_SALT_BYTES) throw new TypeError('Invalid Identity KDF input length')
  decodeUuid(accountId)
  // Every UTF-16 code unit encodes to at least one UTF-8 byte; this bound
  // stops TextEncoder from allocating an attacker-sized buffer.
  if (password.length > IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES) throw new RangeError('password-too-long')
  const provider = getCryptoProvider()
  await provider.ready()
  const passwordBytes = encodeUtf8(password)
  let prehash: Uint8Array | undefined
  let accountRoot: Uint8Array | undefined
  try {
    if (passwordBytes.length > IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES) throw new RangeError('password-too-long')
    prehash = accountSecretPasswordPrehash(passwordBytes, accountSecret)
    accountRoot = await provider.deriveKey(prehash, kdfSalt, {
      memorySize: IDENTITY_ACCOUNT_SECRET_PROFILE.memoryKiB,
      iterations: IDENTITY_ACCOUNT_SECRET_PROFILE.iterations,
      parallelism: IDENTITY_ACCOUNT_SECRET_PROFILE.parallelism,
      hashLength: IDENTITY_ACCOUNT_SECRET_PROFILE.outputBytes,
    })
    return deriveAccountSecretOutputsFromRoot(accountRoot, accountId, kdfSalt)
  } finally {
    wipe(passwordBytes)
    if (prehash) wipe(prehash)
    if (accountRoot) wipe(accountRoot)
  }
}

function secretKeyChecksum(accountId: Uint8Array, accountSecret: Uint8Array): string {
  const digest = sha256Digest(concatBytes(CHECKSUM_MAGIC, accountId, accountSecret))
  try {
    return encodeCrockfordBits(digest, 10)
  } finally {
    digest.fill(0)
  }
}

/** `PSK2-` + nine dash-separated groups of six Crockford base32 symbols with an account-bound checksum. */
export function formatSecretKey(accountId: string, accountSecret: Uint8Array): string {
  if (accountSecret.length !== ACCOUNT_SECRET_BYTES) throw new SecretKeyError('secret-key-malformed')
  const symbols = encodeCrockfordBits(accountSecret, 256) + secretKeyChecksum(decodeUuid(accountId), accountSecret)
  return `${SECRET_KEY_PREFIX}-${symbols.match(/.{6}/g)!.join('-')}`
}

/**
 * Parses user input for the account being unlocked. Accepts any case, spaces,
 * dashes and the O→0, I/L→1 substitutions; rejects before any derivation.
 */
export function parseSecretKey(accountId: string, display: string): Uint8Array {
  const id = decodeUuid(accountId)
  if (typeof display !== 'string' || display.length > 128) throw new SecretKeyError('secret-key-malformed')
  const normalized = display.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1')
  if (!normalized.startsWith(SECRET_KEY_PREFIX)) throw new SecretKeyError('secret-key-malformed')
  const symbols = normalized.slice(SECRET_KEY_PREFIX.length)
  if (symbols.length !== 54) throw new SecretKeyError('secret-key-malformed')
  const values = Array.from(symbols, (symbol) => CROCKFORD_BASE32.indexOf(symbol))
  if (values.some((value) => value < 0) || (values[51] & 0b1111) !== 0) throw new SecretKeyError('secret-key-malformed')

  const secret = new Uint8Array(ACCOUNT_SECRET_BYTES)
  for (let bit = 0; bit < 256; bit++) {
    const value = (values[Math.floor(bit / 5)] >> (4 - (bit % 5))) & 1
    secret[bit >> 3] |= value << (7 - (bit & 7))
  }
  if (secretKeyChecksum(id, secret) !== symbols.slice(52)) {
    secret.fill(0)
    throw new SecretKeyError('secret-key-checksum-mismatch')
  }
  return secret
}

export function encodeEmergencyKitQr(accountId: string, accountSecret: Uint8Array): string {
  if (accountSecret.length !== ACCOUNT_SECRET_BYTES) throw new SecretKeyError('secret-key-malformed')
  return `${EMERGENCY_KIT_PREFIX}${toBase64Url(decodeUuid(accountId))}.${toBase64Url(accountSecret)}`
}

/** Returns the Account Secret only when the kit belongs to `accountId`, the account being unlocked. */
export function parseEmergencyKitQr(accountId: string, payload: string): Uint8Array {
  const expectedId = decodeUuid(accountId)
  if (typeof payload !== 'string' || !payload.startsWith(EMERGENCY_KIT_PREFIX)) throw new SecretKeyError('secret-key-malformed')
  const parts = payload.slice(EMERGENCY_KIT_PREFIX.length).split('.')
  const decoded = parts.length === 2 ? decodeKitParts(parts[0], parts[1]) : undefined
  if (!decoded) throw new SecretKeyError('secret-key-malformed')
  if (toBase64Url(decoded.accountId) !== toBase64Url(expectedId)) {
    decoded.secret.fill(0)
    throw new SecretKeyError('account-mismatch')
  }
  return decoded.secret
}

function decodeKitParts(encodedAccountId: string, encodedSecret: string): { accountId: Uint8Array, secret: Uint8Array } | undefined {
  try {
    const accountId = fromBase64Url(encodedAccountId, 16)
    const secret = fromBase64Url(encodedSecret, ACCOUNT_SECRET_BYTES)
    if (accountId.length === 16 && secret.length === ACCOUNT_SECRET_BYTES) return { accountId, secret }
    secret.fill(0)
  } catch { /* malformed */ }
  return undefined
}
