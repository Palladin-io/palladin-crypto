import { fromBase64Url, toBase64Url } from './encoding'
import type { CanonicalEnvelopeAad, EncodedSuitePayload } from './envelope'
import { requireCryptoSuite, VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { wipe } from './sodium'

export const BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION = 1
export const BROWSER_SESSION_ENVELOPE_PURPOSE = 'palladin/browser-extension/durable-session-v1'

const AAD_MAGIC = new TextEncoder().encode('PLDNBSE1')
const KDF_MAGIC = new TextEncoder().encode('PLDNBSDK1')
const HKDF_HASH = 'SHA-256'
const KEY_BYTES = 32
const ABSENT_SALT = new Uint8Array(32)
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const PROFILE_ID = /^[A-Za-z0-9._/-]{1,128}$/
// Chromium IDs are lowercase alphanumeric; Firefox commonly uses an e-mail-like
// Gecko ID. Keep the alphabet ASCII-only while supporting both stable forms.
const CLIENT_ID = /^[A-Za-z0-9._@-]{1,128}$/
const MAX_API_URL_BYTES = 2_048
const MAX_ENCRYPTED_PRIVATE_KEY_BYTES = 4_096
const MAX_SESSION_PLAINTEXT_BYTES = 64 * 1_024

export interface BrowserSessionEnvelopeContext {
  readonly apiUrl: string
  readonly accountId: string
  readonly clientId: string
  readonly identitySecurityVersion: number
  readonly minimumIdentitySecurityVersion: number
  readonly kdfProfileId: string
  readonly kdfSalt: string
  readonly encryptedPrivateKey: string
  readonly issuedAt: number
  readonly expiresAt: number
}

export interface BrowserSessionEnvelope {
  readonly protocolVersion: typeof BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION
  readonly purpose: typeof BROWSER_SESSION_ENVELOPE_PURPOSE
  readonly cryptoSuiteId: typeof VAULT_XCHACHA20_POLY1305_V1
  readonly context: BrowserSessionEnvelopeContext
  readonly encodedSuitePayload: string
}

export interface BrowserSessionEnvelopeOpenOptions {
  /** Injectable wall clock used only to enforce the authenticated validity window. */
  readonly now?: () => number
}

class BinaryWriter {
  private readonly chunks: Uint8Array[] = []
  private length = 0

  bytes(value: Uint8Array): void {
    const copy = new Uint8Array(value)
    this.chunks.push(copy)
    this.length += copy.length
  }

  u16(value: number): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
      throw new RangeError('u16 out of range')
    }
    const bytes = new Uint8Array(2)
    new DataView(bytes.buffer).setUint16(0, value)
    this.bytes(bytes)
  }

  u32(value: number): void {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
      throw new RangeError('u32 out of range')
    }
    const bytes = new Uint8Array(4)
    new DataView(bytes.buffer).setUint32(0, value)
    this.bytes(bytes)
  }

  u64(value: number): void {
    if (!Number.isSafeInteger(value) || value < 0) throw new RangeError('u64 out of range')
    const bytes = new Uint8Array(8)
    new DataView(bytes.buffer).setBigUint64(0, BigInt(value))
    this.bytes(bytes)
  }

  text(value: string, maximumBytes: number, label: string): void {
    const encoded = new TextEncoder().encode(value)
    try {
      if (encoded.length === 0 || encoded.length > maximumBytes) {
        throw new RangeError(`${label} has an invalid encoded length`)
      }
      this.u16(encoded.length)
      this.bytes(encoded)
    } finally {
      wipe(encoded)
    }
  }

  finish(): Uint8Array {
    const result = new Uint8Array(this.length)
    let offset = 0
    for (const chunk of this.chunks) {
      result.set(chunk, offset)
      offset += chunk.length
      wipe(chunk)
    }
    return result
  }
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} has unexpected fields`)
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`)
  }
  return value as Record<string, unknown>
}

function integer(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`)
  }
  return value
}

function string(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new TypeError(`${label} must be a string`)
  return value
}

function canonicalApiUrl(value: string): string {
  if (value.length > MAX_API_URL_BYTES) {
    throw new RangeError('Browser session API URL is too long')
  }
  if (new TextEncoder().encode(value).length > MAX_API_URL_BYTES) {
    throw new RangeError('Browser session API URL is too long')
  }
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new TypeError('Browser session API URL is invalid')
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new TypeError('Browser session API URL contains forbidden components')
  }
  const loopback = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1'
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
    throw new TypeError('Browser session API URL must use HTTPS or loopback HTTP')
  }
  const path = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/+$/, '')
  const canonical = `${parsed.origin}${path}`
  if (canonical !== value) throw new TypeError('Browser session API URL is not canonical')
  return canonical
}

function parseContext(value: unknown): BrowserSessionEnvelopeContext {
  const input = record(value, 'Browser session context')
  exactKeys(input, [
    'apiUrl',
    'accountId',
    'clientId',
    'identitySecurityVersion',
    'minimumIdentitySecurityVersion',
    'kdfProfileId',
    'kdfSalt',
    'encryptedPrivateKey',
    'issuedAt',
    'expiresAt',
  ], 'Browser session context')

  const apiUrl = canonicalApiUrl(string(input.apiUrl, 'API URL'))
  const accountId = string(input.accountId, 'Account ID')
  const clientId = string(input.clientId, 'Client ID')
  const identitySecurityVersion = integer(input.identitySecurityVersion, 'Identity security version')
  const minimumIdentitySecurityVersion = integer(
    input.minimumIdentitySecurityVersion,
    'Minimum Identity security version',
  )
  const kdfProfileId = string(input.kdfProfileId, 'KDF profile ID')
  const kdfSalt = string(input.kdfSalt, 'KDF salt')
  const encryptedPrivateKey = string(input.encryptedPrivateKey, 'Encrypted private key')
  const issuedAt = integer(input.issuedAt, 'Issued-at timestamp')
  const expiresAt = integer(input.expiresAt, 'Expiry timestamp')

  if (!UUID.test(accountId)) throw new TypeError('Browser session account ID is invalid')
  if (!CLIENT_ID.test(clientId)) throw new TypeError('Browser session client ID is invalid')
  if (!PROFILE_ID.test(kdfProfileId)) throw new TypeError('Browser session KDF profile ID is invalid')
  if (identitySecurityVersion > 0xffffffff || minimumIdentitySecurityVersion > 0xffffffff) {
    throw new RangeError('Browser session security version is out of range')
  }
  if (minimumIdentitySecurityVersion > identitySecurityVersion) {
    throw new TypeError('Browser session minimum security version is unsupported')
  }
  if (expiresAt <= issuedAt) throw new TypeError('Browser session expiry must follow issue time')

  const salt = fromBase64Url(kdfSalt, 16)
  const wrappedPrivateKey = fromBase64Url(
    encryptedPrivateKey,
    MAX_ENCRYPTED_PRIVATE_KEY_BYTES,
  )
  try {
    if (salt.length !== 16) throw new TypeError('Browser session KDF salt is invalid')
    if (wrappedPrivateKey.length === 0) {
      throw new TypeError('Browser session encrypted private key is empty')
    }
  } finally {
    wipe(salt)
    wipe(wrappedPrivateKey)
  }

  return {
    apiUrl,
    accountId,
    clientId,
    identitySecurityVersion,
    minimumIdentitySecurityVersion,
    kdfProfileId,
    kdfSalt,
    encryptedPrivateKey,
    issuedAt,
    expiresAt,
  }
}

function encodeContext(context: BrowserSessionEnvelopeContext, magic: Uint8Array): Uint8Array {
  const normalized = parseContext(context)
  const writer = new BinaryWriter()
  writer.bytes(magic)
  writer.u16(BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION)
  writer.text(BROWSER_SESSION_ENVELOPE_PURPOSE, 128, 'Browser session purpose')
  writer.text(String(VAULT_XCHACHA20_POLY1305_V1), 128, 'Browser session suite')
  writer.text(normalized.apiUrl, MAX_API_URL_BYTES, 'Browser session API URL')
  writer.text(normalized.accountId, 36, 'Browser session account ID')
  writer.text(normalized.clientId, 128, 'Browser session client ID')
  writer.u32(normalized.identitySecurityVersion)
  writer.u32(normalized.minimumIdentitySecurityVersion)
  writer.text(normalized.kdfProfileId, 128, 'Browser session KDF profile')
  writer.text(normalized.kdfSalt, 24, 'Browser session KDF salt')
  writer.text(
    normalized.encryptedPrivateKey,
    Math.ceil(MAX_ENCRYPTED_PRIVATE_KEY_BYTES * 4 / 3),
    'Browser session encrypted private key',
  )
  writer.u64(normalized.issuedAt)
  writer.u64(normalized.expiresAt)
  return writer.finish()
}

async function deriveSessionKey(masterKey: Uint8Array, context: BrowserSessionEnvelopeContext): Promise<Uint8Array> {
  if (masterKey.length !== KEY_BYTES) throw new RangeError('Browser session master key must be 32 bytes')
  const rootCopy = new Uint8Array(masterKey)
  const saltCopy = new Uint8Array(ABSENT_SALT)
  const encodedContext = encodeContext(context, KDF_MAGIC)
  const infoCopy = new Uint8Array(encodedContext.length)
  infoCopy.set(encodedContext)
  wipe(encodedContext)
  try {
    const key = await crypto.subtle.importKey('raw', rootCopy, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: HKDF_HASH, salt: saltCopy, info: infoCopy },
      key,
      KEY_BYTES * 8,
    )
    return new Uint8Array(bits)
  } finally {
    wipe(rootCopy)
    wipe(saltCopy)
    wipe(infoCopy)
  }
}

export function parseBrowserSessionEnvelope(value: unknown): BrowserSessionEnvelope {
  const input = record(value, 'Browser session envelope')
  exactKeys(input, [
    'protocolVersion',
    'purpose',
    'cryptoSuiteId',
    'context',
    'encodedSuitePayload',
  ], 'Browser session envelope')
  if (input.protocolVersion !== BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION) {
    throw new TypeError('Unsupported browser session protocol')
  }
  if (input.purpose !== BROWSER_SESSION_ENVELOPE_PURPOSE) {
    throw new TypeError('Unsupported browser session purpose')
  }
  if (input.cryptoSuiteId !== VAULT_XCHACHA20_POLY1305_V1) {
    throw new TypeError('Unsupported browser session crypto suite')
  }
  const context = parseContext(input.context)
  const encodedSuitePayload = string(input.encodedSuitePayload, 'Encoded session payload')
  const payload = fromBase64Url(encodedSuitePayload, MAX_SESSION_PLAINTEXT_BYTES + 64)
  try {
    requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1).validateEncodedPayload(payload)
  } finally {
    wipe(payload)
  }
  return {
    protocolVersion: BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION,
    purpose: BROWSER_SESSION_ENVELOPE_PURPOSE,
    cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
    context,
    encodedSuitePayload,
  }
}

export async function sealBrowserSessionEnvelope(
  plaintext: Uint8Array,
  masterKey: Uint8Array,
  context: BrowserSessionEnvelopeContext,
): Promise<BrowserSessionEnvelope> {
  if (plaintext.length === 0 || plaintext.length > MAX_SESSION_PLAINTEXT_BYTES) {
    throw new RangeError('Browser session plaintext has an invalid length')
  }
  const normalized = parseContext(context)
  const aad = encodeContext(normalized, AAD_MAGIC) as CanonicalEnvelopeAad
  let sessionKey: Uint8Array | null = null
  try {
    sessionKey = await deriveSessionKey(masterKey, normalized)
    const payload = await requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1).seal({
      plaintext,
      key: sessionKey,
      aad,
    })
    try {
      return {
        protocolVersion: BROWSER_SESSION_ENVELOPE_PROTOCOL_VERSION,
        purpose: BROWSER_SESSION_ENVELOPE_PURPOSE,
        cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
        context: normalized,
        encodedSuitePayload: toBase64Url(payload),
      }
    } finally {
      wipe(payload)
    }
  } finally {
    wipe(aad)
    if (sessionKey) wipe(sessionKey)
  }
}

export async function openBrowserSessionEnvelope(
  value: unknown,
  masterKey: Uint8Array,
  options: BrowserSessionEnvelopeOpenOptions = {},
): Promise<Uint8Array> {
  const envelope = parseBrowserSessionEnvelope(value)
  const now = (options.now ?? Date.now)()
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError('Browser session clock must return a non-negative safe integer')
  }
  if (now < envelope.context.issuedAt || now >= envelope.context.expiresAt) {
    throw new TypeError('Browser session is outside its validity window')
  }
  const aad = encodeContext(envelope.context, AAD_MAGIC) as CanonicalEnvelopeAad
  const payload = fromBase64Url(
    envelope.encodedSuitePayload,
    MAX_SESSION_PLAINTEXT_BYTES + 64,
  ) as EncodedSuitePayload
  let sessionKey: Uint8Array | null = null
  try {
    sessionKey = await deriveSessionKey(masterKey, envelope.context)
    return await requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1).open({
      payload,
      key: sessionKey,
      aad,
    })
  } finally {
    wipe(aad)
    wipe(payload)
    if (sessionKey) wipe(sessionKey)
  }
}
