import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ key: undefined as Uint8Array | undefined,
  digest: new Uint8Array(20), failure: '' }))
vi.mock('hash-wasm', () => ({
  createSHA1: async () => ({}), createSHA256: async () => ({}), createSHA512: async () => ({}),
  createHMAC: async (_hash: unknown, key: Uint8Array) => {
    state.key = key
    if (state.failure === 'create') throw new Error('Synthetic HMAC failure')
    return {
      init() {},
      update() { if (state.failure === 'update') throw new Error('Synthetic HMAC failure') },
      digest() { if (state.failure === 'digest') throw new Error('Synthetic HMAC failure'); return state.digest },
    }
  },
}))

import { generateTotp } from './totp'

describe('TOTP owned-buffer cleanup', () => {
  beforeEach(() => { state.key = undefined; state.failure = ''; state.digest = new Uint8Array(20).fill(10) })
  const params = { secret: 'JBSWY3DP', algorithm: 'SHA1' as const, digits: 6, period: 30 }
  it('clears the decoded seed and returned digest after deriving a code', async () => {
    expect(await generateTotp(params, 59_000)).toMatchObject({ code: expect.stringMatching(/^\d{6}$/) })
    expect(state.key?.length).toBeGreaterThan(0)
    expect(state.key?.every((byte) => byte === 0)).toBe(true)
    expect(state.digest.every((byte) => byte === 0)).toBe(true)
  })
  it.each(['create', 'update', 'digest'])('clears the decoded seed on HMAC %s failure', async (failure) => {
    state.failure = failure
    await expect(generateTotp(params, 59_000)).rejects.toThrow('Synthetic HMAC failure')
    expect(state.key?.length).toBeGreaterThan(0)
    expect(state.key?.every((byte) => byte === 0)).toBe(true)
  })
})
