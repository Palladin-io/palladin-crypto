import { describe, expect, it } from 'vitest'
import { deriveHkdfSha256, sha256Digest } from './portable-sha256'

const hex = (input: Uint8Array) => Array.from(input, value => value.toString(16).padStart(2, '0')).join('')
describe('portable SHA-256 and HKDF', () => {
  it('matches the SHA-256 abc vector', () => {
    expect(hex(sha256Digest(new TextEncoder().encode('abc')))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  })
  it('matches RFC 5869 test case 1 without mutating caller inputs', () => {
    const input = new Uint8Array(22).fill(0x0b)
    const salt = Uint8Array.from({ length: 13 }, (_, i) => i)
    const info = Uint8Array.from({ length: 10 }, (_, i) => 0xf0 + i)
    expect(hex(deriveHkdfSha256(input, salt, info, 42))).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
    expect(input).toEqual(new Uint8Array(22).fill(0x0b))
    expect(salt).toEqual(Uint8Array.from({ length: 13 }, (_, i) => i))
    expect(info).toEqual(Uint8Array.from({ length: 10 }, (_, i) => 0xf0 + i))
  })
  it('matches WebCrypto across block boundaries and absent salt', async () => {
    for (const length of [0, 1, 63, 64, 65, 1024]) {
      const input = new Uint8Array(length).fill(0x42), salt = new Uint8Array(), info = new Uint8Array([1, 2, 3])
      expect(sha256Digest(input)).toEqual(new Uint8Array(await crypto.subtle.digest('SHA-256', input)))
      const key = await crypto.subtle.importKey('raw', input, 'HKDF', false, ['deriveBits'])
      expect(deriveHkdfSha256(input, salt, info)).toEqual(new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256)))
    }
  })
})
