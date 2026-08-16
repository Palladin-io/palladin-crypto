import { wipe } from './sodium'
import { encodeCanonicalKdfContext } from './canonical-aad'
import type { KdfContextDescriptor } from './envelope'

const HKDF_SHA256_HASH = 'SHA-256'
const VAULT_SUBKEY_BYTES = 32
const ABSENT_SALT = new Uint8Array(32)

/**
 * Derive a purpose-scoped subkey with HKDF-SHA-256.
 *
 * Salt and info are explicit bytes because their canonical encoding belongs to
 * the cross-client protocol. Secret input is copied by Web Crypto internally;
 * the temporary local copy is wiped in all paths.
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
    const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: HKDF_SHA256_HASH, salt: saltCopy, info: infoCopy },
      key,
      VAULT_SUBKEY_BYTES * 8,
    )
    return new Uint8Array(bits)
  } finally {
    wipe(ikm)
    wipe(saltCopy)
    wipe(infoCopy)
  }
}

