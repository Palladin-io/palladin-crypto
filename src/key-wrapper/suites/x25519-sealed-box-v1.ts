import { sha256Digest } from '../../portable-sha256'
import { wipe } from '../../sodium'
import { loadSodium } from '../../sodium-loader'
import { concatBytes, encodeU16, encodeUtf8 } from '../../vault-v2-bytes'
import { KeyWrapperError } from '../registry'
import type { KeyWrapperSuiteImplementation } from './suite'

/**
 * palladin-protocol `contracts/key-wrapper/v1/suites/palladin-x25519-sealed-box-v1.json`.
 * Frozen bytes shared with vault-v2, script-execution/v1 and agent-submission/v1.
 */
const FINGERPRINT_MAGIC = encodeUtf8('PLDNV2FP')
const PACKAGE_MAGIC = encodeUtf8('PLDNX2K1')
const KEY_BYTES = 32
const HASH_BYTES = 32
const PLAINTEXT_BYTES = PACKAGE_MAGIC.length + KEY_BYTES + HASH_BYTES

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

/** Legacy fingerprint without the suite id; also used for vault-v2 Ed25519 key kinds. */
export function legacyKeyFingerprint(publicKey: Uint8Array, keyKind: number, protocolVersion: number): Uint8Array {
  if (publicKey.length !== KEY_BYTES) throw new KeyWrapperError('recipient-mismatch')
  return sha256Digest(concatBytes(FINGERPRINT_MAGIC, encodeU16(protocolVersion), encodeU16(keyKind), publicKey))
}

export const x25519SealedBoxV1: KeyWrapperSuiteImplementation = {
  privateKeyBytes: KEY_BYTES,
  packageBytes: PLAINTEXT_BYTES + 48,

  fingerprint: legacyKeyFingerprint,

  async publicKeyFromPrivateKey(privateKey) {
    if (privateKey.length !== KEY_BYTES) throw new RangeError('Invalid private key length')
    return (await loadSodium()).crypto_scalarmult_base(privateKey)
  },

  async seal(wrappedKey, publicKey, contextHash) {
    const sodium = await loadSodium()
    const plaintext = concatBytes(PACKAGE_MAGIC, wrappedKey, contextHash)
    try {
      return sodium.crypto_box_seal(plaintext, publicKey)
    } finally {
      wipe(plaintext)
    }
  },

  async open(sealedPackage, publicKey, privateKey, contextHash) {
    const sodium = await loadSodium()
    let opened: Uint8Array | undefined
    try {
      opened = sodium.crypto_box_seal_open(sealedPackage, publicKey, privateKey)
      if (opened.length !== PLAINTEXT_BYTES
        || !equalBytes(opened.subarray(0, PACKAGE_MAGIC.length), PACKAGE_MAGIC)
        || !equalBytes(opened.subarray(PACKAGE_MAGIC.length + KEY_BYTES), contextHash)) {
        throw new KeyWrapperError('open-failed')
      }
      return opened.slice(PACKAGE_MAGIC.length, PACKAGE_MAGIC.length + KEY_BYTES)
    } catch {
      throw new KeyWrapperError('open-failed')
    } finally {
      if (opened) wipe(opened)
    }
  },
}
