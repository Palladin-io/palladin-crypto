import { describe, expect, it } from 'vitest'
import fixtures from './fixtures/shared-unlock-v1/key-context-fixtures.json'
import { toBase64Url } from './encoding'
import { encodeSharedUnlockKeyContext, hashSharedUnlockKeyContext } from './shared-unlock-key-context'

describe('Shared unlock account key context', () => {
  const vector = fixtures.positive[0]
  it('matches the independently generated Node canonical bytes and SHA-256 digest', async () => {
    expect(toBase64Url(encodeSharedUnlockKeyContext(vector.context))).toBe(vector.message)
    expect(await hashSharedUnlockKeyContext(vector.context)).toBe(vector.digest)
  })
  for (const substitution of fixtures.substitutions) {
    it(`binds ${substitution.field} independently of every other field`, async () => {
      const changed = await hashSharedUnlockKeyContext(substitution.context)
      expect(changed).toBe(substitution.digest)
      expect(changed).not.toBe(vector.digest)
    })
  }
  it('snapshots the descriptor before asynchronous hashing', async () => {
    const context = { ...vector.context }
    const pending = hashSharedUnlockKeyContext(context)
    context.memberKeyVersion++
    context.encryptedPrivateKey = ''
    expect(await pending).toBe(vector.digest)
  })
})
