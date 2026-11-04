import { deriveHkdfSha256, sha256Digest } from '../../portable-sha256'
import { wipe } from '../../sodium'
import { concatBytes, encodeU16, encodeUtf8 } from '../../vault-v2-bytes'
import { KeyWrapperError } from '../registry'
import type { KeyWrapperSuiteImplementation } from './suite'
import {
  openWithSingleUseKey,
  sealWithSingleUseKey,
  XWING_CIPHERTEXT_BYTES,
  XWING_PUBLIC_KEY_BYTES,
  XWING_SEED_BYTES,
  xwingDecapsulate,
  xwingEncapsulate,
  xwingPublicKey,
} from './xwing-kem'

/** palladin-protocol `contracts/key-wrapper/v1/suites/palladin-xwing-v1.json`. */
const SUITE_ID = encodeUtf8('palladin-xwing-v1')
const FINGERPRINT_MAGIC = encodeUtf8('PLDNV2FP')
const KEY_INFO_MAGIC = encodeUtf8('PLDNXW1KEY')
const AAD_MAGIC = encodeUtf8('PLDNXW1AAD')
const EMPTY_SALT = new Uint8Array(0)

function aeadKey(sharedSecret: Uint8Array, contextHash: Uint8Array, publicKey: Uint8Array, kemCiphertext: Uint8Array): Uint8Array {
  const info = concatBytes(KEY_INFO_MAGIC, contextHash, sha256Digest(publicKey), sha256Digest(kemCiphertext))
  return deriveHkdfSha256(sharedSecret, EMPTY_SALT, info)
}

export const xwingV1: KeyWrapperSuiteImplementation = {
  privateKeyBytes: XWING_SEED_BYTES,
  packageBytes: XWING_CIPHERTEXT_BYTES + 48,

  fingerprint(publicKey, keyKind, protocolVersion) {
    if (publicKey.length !== XWING_PUBLIC_KEY_BYTES) throw new KeyWrapperError('recipient-mismatch')
    return sha256Digest(concatBytes(
      FINGERPRINT_MAGIC,
      encodeU16(protocolVersion),
      encodeU16(keyKind),
      encodeU16(SUITE_ID.length),
      SUITE_ID,
      publicKey,
    ))
  },

  async publicKeyFromPrivateKey(privateKey) {
    return xwingPublicKey(privateKey)
  },

  async seal(wrappedKey, publicKey, contextHash) {
    const { kemCiphertext, sharedSecret } = await xwingEncapsulate(publicKey)
    const key = aeadKey(sharedSecret, contextHash, publicKey, kemCiphertext)
    try {
      return concatBytes(kemCiphertext, sealWithSingleUseKey(key, concatBytes(AAD_MAGIC, contextHash), wrappedKey))
    } finally {
      wipe(sharedSecret)
      wipe(key)
    }
  },

  async open(sealedPackage, publicKey, privateKey, contextHash) {
    const kemCiphertext = sealedPackage.subarray(0, XWING_CIPHERTEXT_BYTES)
    let sharedSecret: Uint8Array | undefined
    let key: Uint8Array | undefined
    try {
      sharedSecret = xwingDecapsulate(kemCiphertext, privateKey)
      key = aeadKey(sharedSecret, contextHash, publicKey, kemCiphertext)
      return openWithSingleUseKey(key, concatBytes(AAD_MAGIC, contextHash), sealedPackage.subarray(XWING_CIPHERTEXT_BYTES))
    } catch {
      throw new KeyWrapperError('open-failed')
    } finally {
      if (sharedSecret) wipe(sharedSecret)
      if (key) wipe(key)
    }
  },
}
