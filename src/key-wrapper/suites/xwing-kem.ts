import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js'
import { randomBytes, wipe } from '../../sodium'

/** X-Wing per draft-connolly-cfrg-xwing-kem-10 (ML-KEM-768 + X25519, SHA3-256 combiner). */
export const XWING_SEED_BYTES = 32
export const XWING_PUBLIC_KEY_BYTES = 1216
export const XWING_CIPHERTEXT_BYTES = 1120
const XWING_ENCAPSULATION_RANDOMNESS_BYTES = 64
const ZERO_NONCE = new Uint8Array(24)

export async function generateXWingSeed(): Promise<Uint8Array> {
  return randomBytes(XWING_SEED_BYTES)
}

export function xwingPublicKey(seed: Uint8Array): Uint8Array {
  if (seed.length !== XWING_SEED_BYTES) throw new RangeError('Invalid X-Wing seed length')
  return xwing.getPublicKey(seed)
}

export async function xwingEncapsulate(publicKey: Uint8Array): Promise<{ kemCiphertext: Uint8Array, sharedSecret: Uint8Array }> {
  if (publicKey.length !== XWING_PUBLIC_KEY_BYTES) throw new RangeError('Invalid X-Wing public key length')
  const randomness = await randomBytes(XWING_ENCAPSULATION_RANDOMNESS_BYTES)
  try {
    const { cipherText, sharedSecret } = xwing.encapsulate(publicKey, randomness)
    return { kemCiphertext: cipherText, sharedSecret }
  } finally {
    wipe(randomness)
  }
}

// Lengths are checked before the KEM runs so malformed input never reaches
// the decapsulation code path (cf. CVE-2026-28815).
export function xwingDecapsulate(kemCiphertext: Uint8Array, seed: Uint8Array): Uint8Array {
  if (kemCiphertext.length !== XWING_CIPHERTEXT_BYTES || seed.length !== XWING_SEED_BYTES) {
    throw new RangeError('Invalid X-Wing decapsulation input length')
  }
  return xwing.decapsulate(kemCiphertext, seed)
}

// The all-zero nonce is safe only because every key passed here is derived
// from a fresh KEM shared secret and used for exactly one message.
export function sealWithSingleUseKey(key: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, ZERO_NONCE, aad).encrypt(plaintext)
}

export function openWithSingleUseKey(key: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return xchacha20poly1305(key, ZERO_NONCE, aad).decrypt(ciphertext)
}
