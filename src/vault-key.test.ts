import { describe, expect, it } from 'vitest'
import { sealVaultKey, unsealVaultKey } from './vault-key'
import { decryptEntry, encryptEntry } from './entry-crypto'
import { generateKeyPair, wipe } from './sodium'
import { ENTRY_TYPE_KEY, type EntryPlaintext } from './payload-types'

describe('vault-key seal → unseal', () => {
  it('seals a fresh VK for a keypair and unseals a usable 32-byte key', async () => {
    const { privateKey } = await generateKeyPair()

    const wrappedVK = await sealVaultKey(privateKey)
    expect(typeof wrappedVK).toBe('string')

    const vk = await unsealVaultKey(wrappedVK, privateKey)
    expect(vk).toHaveLength(32)

    // The unsealed VK is a valid symmetric key: it must round-trip an entry.
    const plaintext: EntryPlaintext = { type: ENTRY_TYPE_KEY, value: 'top-secret' }
    const content = await encryptEntry(plaintext, vk)
    const recovered = await decryptEntry(content, vk)
    expect(recovered).toEqual(plaintext)

    wipe(vk)
  })

  it('fails to unseal with the wrong private key', async () => {
    const owner = await generateKeyPair()
    const attacker = await generateKeyPair()

    const wrappedVK = await sealVaultKey(owner.privateKey)

    await expect(unsealVaultKey(wrappedVK, attacker.privateKey)).rejects.toBeDefined()
  })
})
