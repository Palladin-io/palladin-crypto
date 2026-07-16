import { describe, expect, it } from 'vitest'
import {
  ENTRY_TYPE_CREDENTIAL,
  ENTRY_TYPE_KEY,
  type EntryPlaintext,
} from './payload-types'
import { decryptEntry, encryptEntry } from './entry-crypto'
import { loadSodium } from './sodium-loader'
import { randomBytes } from './sodium'

describe('entry-crypto', () => {
  it('round-trips a KEY payload through encrypt + decrypt', async () => {
    const vk = await randomBytes(32)
    const plaintext: EntryPlaintext = {
      type: ENTRY_TYPE_KEY,
      value: 'sk_live_super_secret',
      notes: 'Used by the deploy bot',
    }

    const content = await encryptEntry(plaintext, vk)
    const recovered = await decryptEntry(content, vk)

    expect(recovered).toEqual(plaintext)
  })

  it('round-trips a CREDENTIAL payload through encrypt + decrypt', async () => {
    const vk = await randomBytes(32)
    const plaintext: EntryPlaintext = {
      type: ENTRY_TYPE_CREDENTIAL,
      username: 'user@example.com',
      password: 'P@ssw0rd!',
      url: 'https://example.com/login',
    }

    const content = await encryptEntry(plaintext, vk)
    const recovered = await decryptEntry(content, vk)

    expect(recovered).toEqual(plaintext)
  })

  it('produces a fresh nonce per call so the same plaintext never collides', async () => {
    const vk = await randomBytes(32)
    const plaintext: EntryPlaintext = { type: ENTRY_TYPE_KEY, value: 'static' }

    const a = await encryptEntry(plaintext, vk)
    const b = await encryptEntry(plaintext, vk)

    expect(a.nonce).not.toBe(b.nonce)
    expect(a.encryptedBlob).not.toBe(b.encryptedBlob)
  })

  it('throws when decrypted with the wrong vault key', async () => {
    const vk = await randomBytes(32)
    const wrongVk = await randomBytes(32)
    const content = await encryptEntry({ type: ENTRY_TYPE_KEY, value: 'secret' }, vk)

    await expect(decryptEntry(content, wrongVk)).rejects.toThrow()
    // Sanity: calling loadSodium once primes the WASM init for the rejection above.
    await loadSodium()
  })
})
