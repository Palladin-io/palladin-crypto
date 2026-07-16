import { describe, expect, it } from 'vitest'
import { base32Decode, generateTotp, parseOtpauthUri, totpParamsFromSecret } from './totp'
import type { TotpParams } from './payload-types'

/** Local base32 encoder — used only to turn the RFC 6238 ASCII seeds into the
 *  base32 secrets our API consumes, so the vectors don't depend on a
 *  hand-copied string. */
function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = 0
  let value = 0
  let output = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += alphabet[(value >>> bits) & 31]
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31]
  return output
}

const ascii = (s: string) => new Uint8Array([...s].map((c) => c.charCodeAt(0)))

// RFC 6238 Appendix B reference seeds.
const SEED_SHA1 = base32Encode(ascii('12345678901234567890'))
const SEED_SHA256 = base32Encode(ascii('12345678901234567890123456789012'))
const SEED_SHA512 = base32Encode(
  ascii('1234567890123456789012345678901234567890123456789012345678901234'),
)

function params(secret: string, algorithm: TotpParams['algorithm']): TotpParams {
  return { secret, algorithm, digits: 8, period: 30 }
}

describe('base32Decode', () => {
  it('decodes a known secret and ignores spaces/padding', () => {
    const decoded = base32Decode('JBSW Y3DP')
    expect(new TextDecoder().decode(decoded)).toBe('Hello')
  })

  it('throws on an invalid character', () => {
    expect(() => base32Decode('0189')).toThrow()
  })
})

describe('generateTotp — RFC 6238 test vectors', () => {
  // [unix seconds, algorithm, seed, expected 8-digit code]
  const vectors: [number, TotpParams['algorithm'], string, string][] = [
    [59, 'SHA1', SEED_SHA1, '94287082'],
    [59, 'SHA256', SEED_SHA256, '46119246'],
    [59, 'SHA512', SEED_SHA512, '90693936'],
    [1111111109, 'SHA1', SEED_SHA1, '07081804'],
    [1111111109, 'SHA256', SEED_SHA256, '68084774'],
    [1111111111, 'SHA256', SEED_SHA256, '67062674'],
    [1234567890, 'SHA1', SEED_SHA1, '89005924'],
    [2000000000, 'SHA512', SEED_SHA512, '38618901'],
    [20000000000, 'SHA1', SEED_SHA1, '65353130'],
  ]

  it.each(vectors)('t=%i %s → %s', async (seconds, algorithm, seed, expected) => {
    const { code } = await generateTotp(params(seed, algorithm), seconds * 1000)
    expect(code).toBe(expected)
  })

  it('reports whole seconds remaining in the window', async () => {
    const { expiresIn, period } = await generateTotp(params(SEED_SHA1, 'SHA1'), 10_000)
    expect(period).toBe(30)
    // 10_000s → 10_000 % 30 = 10 into the window → 20 left.
    expect(expiresIn).toBe(20)
  })

  it('defaults to 6 digits', async () => {
    const { code } = await generateTotp({ secret: SEED_SHA1, algorithm: 'SHA1', digits: 6, period: 30 }, 59_000)
    expect(code).toBe('287082')
  })
})

describe('parseOtpauthUri', () => {
  it('parses a full URI with issuer label and query params', () => {
    const parsed = parseOtpauthUri(
      'otpauth://totp/GitHub:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60',
    )
    expect(parsed).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
      issuer: 'GitHub',
      account: 'alice@example.com',
    })
  })

  it('applies RFC defaults when params are absent', () => {
    const parsed = parseOtpauthUri('otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP')
    expect(parsed).toMatchObject({ algorithm: 'SHA1', digits: 6, period: 30, account: 'alice' })
  })

  it('rejects non-otpauth and secret-less URIs', () => {
    expect(parseOtpauthUri('https://example.com')).toBeNull()
    expect(parseOtpauthUri('otpauth://totp/alice')).toBeNull()
    expect(parseOtpauthUri('otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP')).toBeNull()
    expect(parseOtpauthUri('not a uri')).toBeNull()
  })
})

describe('totpParamsFromSecret', () => {
  it('normalises a spaced/padded base32 secret with defaults', () => {
    expect(totpParamsFromSecret('jbsw y3dp ehpk 3pxp')).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      issuer: undefined,
      account: undefined,
    })
  })

  it('returns null for a non-base32 secret', () => {
    expect(totpParamsFromSecret('!!!not base32!!!')).toBeNull()
  })
})
