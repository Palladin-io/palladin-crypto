import { describe, expect, it, vi } from 'vitest'
import { fromBase64, fromBase64Url, toBase64 } from './encoding'

describe('base64 encoding', () => {
  it('round-trips arbitrary bytes', () => {
    const input = new Uint8Array([0, 1, 2, 3, 254, 255, 64, 128])
    const encoded = toBase64(input)
    const decoded = fromBase64(encoded)

    expect(decoded).toEqual(input)
  })

  it('produces the expected base64 string for known input', () => {
    expect(toBase64(new Uint8Array([0, 0, 0]))).toBe('AAAA')
    expect(toBase64(new Uint8Array([72, 105]))).toBe('SGk=')
  })

  it('handles an empty array', () => {
    expect(toBase64(new Uint8Array([]))).toBe('')
    expect(fromBase64('')).toEqual(new Uint8Array([]))
  })

  it('rejects oversized base64url from encoded length before decoding', () => {
    const decode = vi.spyOn(globalThis, 'atob')
    try {
      expect(() => fromBase64Url('A'.repeat(44), 32)).toThrow(/permitted size/)
      expect(decode).not.toHaveBeenCalled()
    } finally {
      decode.mockRestore()
    }
  })
})
