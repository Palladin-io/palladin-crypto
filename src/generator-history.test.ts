import { describe, expect, it } from 'vitest'
import { openGeneratorHistory, sealGeneratorHistory, GENERATOR_HISTORY_MAX_BYTES } from './generator-history'

const context = { accountId: '00000000-0000-4000-8000-000000000001', apiUrl: 'https://api.example.test' }
const key = new Uint8Array(32).fill(7)
const plaintext = new TextEncoder().encode('synthetic-generator-history')

describe('local generator history', () => {
  it('round-trips with independent session context and fresh nonces', async () => {
    const first = await sealGeneratorHistory(plaintext, key, context)
    const second = await sealGeneratorHistory(plaintext, key, context)
    expect(first).not.toEqual(second)
    expect(await openGeneratorHistory(first, key, context)).toEqual(plaintext)
    expect(key).toEqual(new Uint8Array(32).fill(7))
  })

  it('rejects substitution across accounts, API environments and keys', async () => {
    const envelope = await sealGeneratorHistory(plaintext, key, context)
    await expect(openGeneratorHistory(envelope, key, { ...context, accountId: '00000000-0000-4000-8000-000000000002' })).rejects.toThrow()
    await expect(openGeneratorHistory(envelope, key, { ...context, apiUrl: 'https://other.example.test' })).rejects.toThrow()
    await expect(openGeneratorHistory(envelope, new Uint8Array(32).fill(8), context)).rejects.toThrow()
  })

  it('rejects corrupt, oversized and future envelopes', async () => {
    const envelope = await sealGeneratorHistory(plaintext, key, context)
    const changed = (envelope.ciphertext[0] === 'A' ? 'B' : 'A') + envelope.ciphertext.slice(1)
    await expect(openGeneratorHistory({ ...envelope, ciphertext: changed }, key, context)).rejects.toThrow()
    await expect(openGeneratorHistory({ ...envelope, version: 2 }, key, context)).rejects.toThrow()
    await expect(openGeneratorHistory({ ...envelope, accountId: context.accountId }, key, context)).rejects.toThrow()
    await expect(openGeneratorHistory({ version: 1, ciphertext: 'A'.repeat(3 * 1024 * 1024) }, key, context)).rejects.toThrow()
    await expect(sealGeneratorHistory(new Uint8Array(GENERATOR_HISTORY_MAX_BYTES + 1), key, context)).rejects.toThrow()
  })
})
