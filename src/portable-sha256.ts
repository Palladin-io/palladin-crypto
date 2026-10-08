import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

/** Bundled primitives for explicitly opted-in HTTP clients without SubtleCrypto.
 * Transport consent and authenticated peer selection belong to the caller. */
export function sha256Digest(input: Uint8Array): Uint8Array {
  return sha256(input)
}

export function deriveHkdfSha256(input: Uint8Array, salt: Uint8Array, info: Uint8Array, length = 32): Uint8Array {
  return hkdf(sha256, input, salt, info, length)
}
