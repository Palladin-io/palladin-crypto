import { describe, expect, it } from 'vitest'
import { ARGON2_PARAMS, deriveKey } from './argon2'
import { decryptWithKey, encryptWithKey } from './sodium'
import { toBase64 } from './encoding'

const salt = (fill: number) => new Uint8Array(16).fill(fill)

describe('deriveKey (Argon2id)', () => {
  it('uses the frozen KDF parameters', () => {
    expect(ARGON2_PARAMS).toEqual({
      memorySize: 19456,
      iterations: 2,
      parallelism: 1,
      hashLength: 32,
    })
  })

  it('is deterministic for the same password + salt', async () => {
    const a = await deriveKey('correct horse battery staple', salt(1))
    const b = await deriveKey('correct horse battery staple', salt(1))
    expect(a).toHaveLength(32)
    expect(toBase64(a)).toBe(toBase64(b))
  })

  it('produces a different key for a different salt', async () => {
    const a = await deriveKey('correct horse battery staple', salt(1))
    const b = await deriveKey('correct horse battery staple', salt(2))
    expect(toBase64(a)).not.toBe(toBase64(b))
  })

  it('derive → wrap → unwrap round-trips a wrapped private key', async () => {
    // Mirrors the unlock chain: MK derived from the password wraps the private
    // key blob; unlock re-derives MK and unwraps it.
    const mk = await deriveKey('master-password', salt(7))
    const privateKey = new Uint8Array(32).fill(0xab)

    const wrapped = await encryptWithKey(privateKey, mk)
    const unwrapped = await decryptWithKey(wrapped, mk)

    expect(unwrapped).toEqual(privateKey)
  })
})
