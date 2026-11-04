import { describe, expect, it } from 'vitest'
import { unsealVaultKey } from './vault-key'
import { decryptEntry, encryptEntry } from './entry-crypto'
import { toBase64 } from './encoding'
import { getCryptoProvider } from './provider/active-provider'
import { wipe } from './sodium'
import { ENTRY_TYPE_KEY, type EntryPlaintext } from './payload-types'

async function sealedVaultKey() {
  const provider = getCryptoProvider()
  await provider.ready()
  const owner = provider.boxKeypair()
  const vk = provider.randomBytes(32)
  return { owner, vk, wrappedVK: toBase64(provider.boxSeal(vk, owner.publicKey)) }
}

describe('protocol 1 unsealVaultKey', () => {
  it('unseals an existing sealed-box VK into a usable 32-byte key', async () => {
    const { owner, vk: expected, wrappedVK } = await sealedVaultKey()
    const vk = await unsealVaultKey(wrappedVK, owner.privateKey)
    expect(vk).toEqual(expected)

    const plaintext: EntryPlaintext = { type: ENTRY_TYPE_KEY, value: 'top-secret' }
    expect(await decryptEntry(await encryptEntry(plaintext, vk), vk)).toEqual(plaintext)
    wipe(vk); wipe(expected)
  })

  it('fails to unseal with the wrong private key', async () => {
    const { wrappedVK } = await sealedVaultKey()
    const attacker = getCryptoProvider().boxKeypair()
    await expect(unsealVaultKey(wrappedVK, attacker.privateKey)).rejects.toBeDefined()
  })
})
