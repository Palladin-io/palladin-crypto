import { sha256Digest } from './portable-sha256'
import { concatBytes, encodeU16, encodeUtf8 } from './vault-v2-bytes'

/** vault-v2 key kinds of the Ed25519 signing keys (never key-wrapper recipients). */
export const SIGNING_KEY_KIND = {
  agentSigning: 2,
  vaultSigning: 3,
} as const

const FINGERPRINT_MAGIC = encodeUtf8('PLDNV2FP')

/** vault-v2 fingerprint of a raw 32-byte public key; also the frozen sealed-box suite fingerprint. */
export function fingerprint32ByteKey(publicKey: Uint8Array, keyKind: number, protocolVersion = 2): Uint8Array {
  if (publicKey.length !== 32) throw new RangeError('Public key must be 32 bytes')
  return sha256Digest(concatBytes(FINGERPRINT_MAGIC, encodeU16(protocolVersion), encodeU16(keyKind), publicKey))
}
