import { fromBase64 } from './encoding'
import { getCryptoProvider } from './provider/active-provider'

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
