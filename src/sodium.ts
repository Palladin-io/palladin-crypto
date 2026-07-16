import { getCryptoProvider } from './provider/active-provider'
import type { KeyPair } from './provider/crypto-provider'

export type { KeyPair }

export async function generateKeyPair(): Promise<KeyPair> {
  const provider = getCryptoProvider()
  await provider.ready()
  return provider.boxKeypair()
}

/**
 * Encrypt with XSalsa20-Poly1305 and prepend the nonce so callers only
 * need to store a single byte blob. The companion decrypt routine
 * (used during unlock) is expected to split on the first 24 bytes.
 */
export async function encryptWithKey(
  plaintext: Uint8Array,
  key: Uint8Array,
): Promise<Uint8Array> {
  const provider = getCryptoProvider()
  await provider.ready()
  const nonce = provider.randomBytes(provider.secretboxNonceBytes())
  const cipher = provider.secretboxEasy(plaintext, nonce, key)

  const combined = new Uint8Array(nonce.length + cipher.length)
  combined.set(nonce, 0)
  combined.set(cipher, nonce.length)
  return combined
}

export async function randomBytes(length: number): Promise<Uint8Array> {
  const provider = getCryptoProvider()
  await provider.ready()
  return provider.randomBytes(length)
}

/**
 * Decrypt a blob produced by `encryptWithKey` (nonce prepended).
 * Throws if the MAC check fails — callers should translate into a
 * typed error (e.g. `IncorrectMasterPasswordError`).
 */
export async function decryptWithKey(
  combined: Uint8Array,
  key: Uint8Array,
): Promise<Uint8Array> {
  const provider = getCryptoProvider()
  await provider.ready()
  const nonceLen = provider.secretboxNonceBytes()
  const nonce = combined.slice(0, nonceLen)
  const cipher = combined.slice(nonceLen)
  return provider.secretboxOpenEasy(cipher, nonce, key)
}

/**
 * Overwrite sensitive byte buffers with zeros so key material does not
 * linger in memory after we're done with it. libsodium's `memzero`
 * is resistant to compiler dead-store elimination.
 */
export function wipe(arr: Uint8Array): void {
  getCryptoProvider().wipe(arr)
}
