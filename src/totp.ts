import { createHMAC, createSHA1, createSHA256, createSHA512 } from 'hash-wasm'
import type { TotpParams } from './payload-types'

/**
 * RFC 6238 TOTP generation and `otpauth://` parsing.
 *
 * TOTP is standard, non-vault crypto (HMAC over a time counter), independent of
 * the zero-knowledge key hierarchy — the secret is stored inside the entry's
 * encrypted blob and only ever decoded client-side. Because it is deterministic
 * and unrelated to the swappable asymmetric scheme, it stays a standalone
 * utility rather than routing through the crypto provider. We use `hash-wasm`
 * for HMAC because it exposes SHA-1 (the TOTP default), which libsodium.js does
 * not, and it is already a dependency.
 *
 * Nothing here is logged or sent to analytics — the secret and the generated
 * code are treated as secret material.
 */

const DEFAULT_ALGORITHM = 'SHA1'
const DEFAULT_DIGITS = 6
const DEFAULT_PERIOD = 30

/** RFC 4648 base32 alphabet (no padding chars in the lookup). */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/**
 * Decode a base32 (RFC 4648) secret to bytes. Case-insensitive; spaces and `=`
 * padding are ignored so grouped/padded secrets pasted from authenticator apps
 * work. Throws on any character outside the alphabet.
 */
export function base32Decode(input: string): Uint8Array {
  const clean = input.replace(/[\s=]/g, '').toUpperCase()
  if (clean.length === 0) throw new Error('Empty base32 secret')

  const bytes: number[] = []
  let bits = 0
  let value = 0
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char)
    if (index === -1) throw new Error(`Invalid base32 character: ${char}`)
    value = (value << 5) | index
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((value >>> bits) & 0xff)
    }
  }
  return new Uint8Array(bytes)
}

function normalizeAlgorithm(raw: string | null): TotpParams['algorithm'] {
  const upper = (raw ?? '').toUpperCase().replace(/[-\s]/g, '')
  if (upper === 'SHA256') return 'SHA256'
  if (upper === 'SHA512') return 'SHA512'
  return DEFAULT_ALGORITHM
}

/**
 * Parse an `otpauth://totp/...` URI into {@link TotpParams}. Returns null for
 * anything that is not a well-formed TOTP URI with a secret — the caller keeps
 * the field in an error state rather than storing a broken seed. `algorithm`,
 * `digits`, and `period` fall back to the RFC defaults (SHA1 / 6 / 30). `issuer`
 * is taken from the query param first, else the `Issuer:Account` label prefix.
 */
export function parseOtpauthUri(uri: string): TotpParams | null {
  let url: URL
  try {
    url = new URL(uri.trim())
  } catch {
    return null
  }
  if (url.protocol !== 'otpauth:') return null
  // The host segment is the OTP type: `otpauth://totp/...`.
  if (url.host.toLowerCase() !== 'totp') return null

  const secretRaw = url.searchParams.get('secret')
  if (!secretRaw) return null
  const secret = secretRaw.replace(/\s/g, '').toUpperCase()
  try {
    base32Decode(secret)
  } catch {
    return null
  }

  const digitsRaw = Number(url.searchParams.get('digits'))
  const periodRaw = Number(url.searchParams.get('period'))
  const digits = Number.isInteger(digitsRaw) && digitsRaw >= 6 && digitsRaw <= 10 ? digitsRaw : DEFAULT_DIGITS
  const period = Number.isInteger(periodRaw) && periodRaw > 0 ? periodRaw : DEFAULT_PERIOD

  // Label is `/Issuer:Account` or `/Account`, URL-encoded.
  const label = decodeURIComponent(url.pathname.replace(/^\//, ''))
  const [labelIssuer, labelAccount] = label.includes(':')
    ? [label.slice(0, label.indexOf(':')).trim(), label.slice(label.indexOf(':') + 1).trim()]
    : [undefined, label.trim()]

  const issuer = url.searchParams.get('issuer')?.trim() || labelIssuer || undefined
  const account = labelAccount || undefined

  return {
    secret,
    algorithm: normalizeAlgorithm(url.searchParams.get('algorithm')),
    digits,
    period,
    issuer,
    account,
  }
}

/**
 * Build a {@link TotpParams} from a bare base32 secret plus optional metadata,
 * applying RFC defaults. Returns null when the secret is not valid base32.
 */
export function totpParamsFromSecret(
  secret: string,
  meta?: { algorithm?: TotpParams['algorithm']; digits?: number; period?: number; issuer?: string; account?: string },
): TotpParams | null {
  const clean = secret.replace(/[\s=]/g, '').toUpperCase()
  try {
    base32Decode(clean)
  } catch {
    return null
  }
  return {
    secret: clean,
    algorithm: meta?.algorithm ?? DEFAULT_ALGORITHM,
    digits: meta?.digits ?? DEFAULT_DIGITS,
    period: meta?.period ?? DEFAULT_PERIOD,
    issuer: meta?.issuer,
    account: meta?.account,
  }
}

function counterToBytes(counter: number): Uint8Array {
  const buffer = new Uint8Array(8)
  // 64-bit big-endian counter. JS bit ops are 32-bit, so fill from the low end
  // dividing by 256 each step — safe for the whole TOTP counter range.
  let value = counter
  for (let i = 7; i >= 0; i--) {
    buffer[i] = value & 0xff
    value = Math.floor(value / 256)
  }
  return buffer
}

function hashFor(algorithm: TotpParams['algorithm']) {
  if (algorithm === 'SHA256') return createSHA256()
  if (algorithm === 'SHA512') return createSHA512()
  return createSHA1()
}

export interface TotpCode {
  /** Current code, zero-padded to `digits`. */
  code: string
  /** Whole seconds until the current window rolls over. */
  expiresIn: number
  /** Window length in seconds (mirrors the params, for the countdown ring). */
  period: number
}

/**
 * Generate the current RFC 6238 code for the given seed. `now` is injectable so
 * tests can pin the clock to the RFC 6238 reference vectors.
 */
export async function generateTotp(
  params: TotpParams,
  now: number = Date.now(),
): Promise<TotpCode> {
  const period = params.period > 0 ? params.period : DEFAULT_PERIOD
  const digits = params.digits >= 6 && params.digits <= 10 ? params.digits : DEFAULT_DIGITS
  const seconds = Math.floor(now / 1000)
  const counter = Math.floor(seconds / period)

  const key = base32Decode(params.secret)
  const hmac = await createHMAC(hashFor(params.algorithm), key)
  hmac.init()
  hmac.update(counterToBytes(counter))
  const digest = hmac.digest('binary')

  // Dynamic truncation (RFC 4226 §5.3).
  const offset = digest[digest.length - 1] & 0x0f
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff)

  const code = (binary % 10 ** digits).toString().padStart(digits, '0')
  const expiresIn = period - (seconds % period)
  return { code, expiresIn, period }
}
