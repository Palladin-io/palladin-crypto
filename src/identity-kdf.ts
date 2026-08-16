import { fromBase64Url } from './encoding'
import { getCryptoProvider } from './provider/active-provider'
import { wipe } from './sodium'

export const IDENTITY_SECURITY_VERSION = 1
export const IDENTITY_KDF_PROFILE_ID = 'identity-argon2id-password-v1'
export const IDENTITY_KDF_SALT_BYTES = 16
export const IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES = 1_024

export const IDENTITY_KDF_PROFILE = Object.freeze({
  id: IDENTITY_KDF_PROFILE_ID,
  securityVersion: IDENTITY_SECURITY_VERSION,
  memoryKiB: 32_768,
  iterations: 2,
  parallelism: 1,
  outputBytes: 32,
})

export interface IdentityKdfMetadata {
  profileId: string
  securityVersion: number
  kdfSalt: string
  memoryKiB: number
  iterations: number
  parallelism: number
}

export interface IdentityKdfOutputs {
  authCredential: Uint8Array
  masterKey: Uint8Array
}

const AUTH_INFO = 'palladin/identity/password-v1/auth-credential'
const MASTER_KEY_INFO = 'palladin/identity/password-v1/master-key'
const HKDF_HASH = 'SHA-256'
const OUTPUT_BITS = 256

function accountIdBytes(accountId: string): Uint8Array {
  const match = /^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$/.exec(accountId)
  if (!match) throw new TypeError('Identity account ID must be an RFC 4122 UUID')
  const hex = match.slice(1).join('')
  return new Uint8Array(hex.match(/../g)!.map(value => Number.parseInt(value, 16)))
}

async function hkdfSha256(
  root: Uint8Array,
  salt: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const rootCopy = new Uint8Array(root)
  const saltCopy = new Uint8Array(salt)
  const infoBytes = new TextEncoder().encode(info)
  try {
    const key = await crypto.subtle.importKey('raw', rootCopy, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: HKDF_HASH, salt: saltCopy, info: infoBytes },
      key,
      OUTPUT_BITS,
    )
    return new Uint8Array(bits)
  } finally {
    wipe(rootCopy)
    wipe(saltCopy)
    wipe(infoBytes)
  }
}

export function assertIdentityKdfProfile(metadata: IdentityKdfMetadata): void {
  const matches = metadata.profileId === IDENTITY_KDF_PROFILE.id
    && metadata.securityVersion === IDENTITY_KDF_PROFILE.securityVersion
    && metadata.memoryKiB === IDENTITY_KDF_PROFILE.memoryKiB
    && metadata.iterations === IDENTITY_KDF_PROFILE.iterations
    && metadata.parallelism === IDENTITY_KDF_PROFILE.parallelism
  if (!matches) {
    throw new Error(
      metadata.securityVersion > IDENTITY_SECURITY_VERSION
        ? 'upgrade-required'
        : 'unsupported-kdf-profile',
    )
  }
  if (fromBase64Url(metadata.kdfSalt, IDENTITY_KDF_SALT_BYTES).length !== IDENTITY_KDF_SALT_BYTES) {
    throw new TypeError('Invalid Identity KDF salt length')
  }
}

export async function deriveIdentityOutputsFromRoot(
  accountRoot: Uint8Array,
  accountId: string,
  kdfSalt: Uint8Array,
): Promise<IdentityKdfOutputs> {
  if (accountRoot.length !== IDENTITY_KDF_PROFILE.outputBytes
    || kdfSalt.length !== IDENTITY_KDF_SALT_BYTES) {
    throw new TypeError('Invalid Identity KDF input length')
  }
  await getCryptoProvider().ready()
  const id = accountIdBytes(accountId)
  let authCredential: Uint8Array | null = null
  try {
    authCredential = await hkdfSha256(accountRoot, id, AUTH_INFO)
    const masterKey = await hkdfSha256(accountRoot, id, MASTER_KEY_INFO)
    return { authCredential, masterKey }
  } catch (error) {
    if (authCredential) wipe(authCredential)
    throw error
  } finally {
    wipe(id)
  }
}

export async function deriveIdentityV1(
  password: string,
  accountId: string,
  kdfSalt: Uint8Array,
): Promise<IdentityKdfOutputs> {
  if (kdfSalt.length !== IDENTITY_KDF_SALT_BYTES) {
    throw new TypeError('Invalid Identity KDF input length')
  }
  // Every UTF-16 code unit encodes to at least one UTF-8 byte. This cheap
  // bound prevents TextEncoder from allocating an attacker-sized buffer; the
  // encoded-length check below remains authoritative for multibyte input.
  if (password.length > IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES) {
    throw new RangeError('password-too-long')
  }
  const provider = getCryptoProvider()
  await provider.ready()
  const passwordBytes = new TextEncoder().encode(password)
  if (passwordBytes.length > IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES) {
    wipe(passwordBytes)
    throw new RangeError('password-too-long')
  }
  let accountRoot: Uint8Array | null = null
  try {
    accountRoot = await provider.deriveKey(password, kdfSalt, {
      memorySize: IDENTITY_KDF_PROFILE.memoryKiB,
      iterations: IDENTITY_KDF_PROFILE.iterations,
      parallelism: IDENTITY_KDF_PROFILE.parallelism,
      hashLength: IDENTITY_KDF_PROFILE.outputBytes,
    })
    return await deriveIdentityOutputsFromRoot(accountRoot, accountId, kdfSalt)
  } finally {
    wipe(passwordBytes)
    if (accountRoot) wipe(accountRoot)
  }
}
