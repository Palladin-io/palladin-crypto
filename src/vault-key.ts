import { fromBase64, toBase64 } from './encoding'
import { getCryptoProvider } from './provider/active-provider'

/**
 * Generate a fresh 32-byte Vault Key and seal it for the user.
 *
 * The VK is the symmetric key that will encrypt every entry in the new
 * vault. To stay zero-knowledge we never send it to the server in the
 * clear: we derive the user's X25519 public key from their private key
 * (already in memory after unlock) and seal the VK to that pubkey using
 * an anonymous sealed box — only someone holding the matching private
 * key can ever unwrap it. The base64-encoded ciphertext is what the
 * backend stores.
 *
 * The raw VK and the derived public key are wiped from local memory
 * before this function returns; the only surviving artefact is the
 * base64 string that is safe to ship over the wire.
 */
export async function sealVaultKey(privateKey: Uint8Array): Promise<string> {
  const provider = getCryptoProvider()
  await provider.ready()
  const vk = provider.randomBytes(32)
  const publicKey = provider.scalarMultBase(privateKey)
  try {
    const wrappedVK = provider.boxSeal(vk, publicKey)
    return toBase64(wrappedVK)
  } finally {
    provider.wipe(vk)
    provider.wipe(publicKey)
  }
}

/**
 * Unseal a Vault Key the user previously sealed for themselves.
 *
 * `wrappedVK` is the base64 sealed-box stored on `VaultMember` and
 * returned alongside the vault detail. The sealed box is opened with the
 * user's X25519 keypair (we derive the public key from the in-memory
 * private key).
 *
 * Returned VK is a fresh `Uint8Array` that the caller owns; wipe it
 * via `wipe()` once the entry has been decrypted/encrypted so the raw
 * key does not linger in memory between operations.
 */
export async function unsealVaultKey(
  wrappedVK: string,
  privateKey: Uint8Array,
): Promise<Uint8Array> {
  const provider = getCryptoProvider()
  await provider.ready()
  const cipher = fromBase64(wrappedVK)
  const publicKey = provider.scalarMultBase(privateKey)
  try {
    return provider.boxSealOpen(cipher, publicKey, privateKey)
  } finally {
    provider.wipe(publicKey)
  }
}
