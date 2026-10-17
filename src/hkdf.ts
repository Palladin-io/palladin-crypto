import { deriveHkdfSha256 } from './portable-sha256'
import { wipe } from './sodium'
import { encodeCanonicalKdfContext } from './canonical-aad'
import type { KdfContextDescriptor } from './envelope'

const VAULT_SUBKEY_BYTES = 32
const ABSENT_SALT = new Uint8Array(32)

/**
 * Derive a purpose-scoped subkey with HKDF-SHA-256.
 *
 * Salt and info are explicit bytes because their canonical encoding belongs to
 * the cross-client protocol. The temporary secret input copy is wiped in all paths.
 */
export async function deriveVaultSubkey(
  rootKey: Uint8Array,
  context: KdfContextDescriptor,
): Promise<Uint8Array> {
  const ikm = new Uint8Array(rootKey)
  const saltCopy = new Uint8Array(ABSENT_SALT)
  const encodedContext = encodeCanonicalKdfContext(context)
  const infoCopy = new Uint8Array(encodedContext.length)
  infoCopy.set(encodedContext)
  try {
    return deriveHkdfSha256(ikm, saltCopy, infoCopy, VAULT_SUBKEY_BYTES)
  } finally {
    wipe(ikm)
    wipe(saltCopy)
    wipe(infoCopy)
  }
}

