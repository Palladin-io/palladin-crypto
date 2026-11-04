import { sha256Digest } from '../portable-sha256'
import { concatBytes, decodeUuid, encodeU16, encodeU32, encodeU64, encodeUtf8 } from '../vault-v2-bytes'
import { SCOPE_FIELDS, type KeyWrapperScopeField } from './registry'

const CONTEXT_MAGIC = encodeUtf8('PLDNX2W1')
const CONTEXT_HASH_MAGIC = encodeUtf8('PLDNX2CTX')
const HASH_BYTES = 32

export interface EncodableWrapperContext {
  protocolVersion: number
  wrapperSuiteId: string
  purpose: number
  /** Present identifiers select the scope bitmap; callers validate them against the purpose. */
  scope: Partial<Record<KeyWrapperScopeField, string>>
  resourceRevision: bigint
  wrappedKeyVersion: number
  memberKeyGeneration?: number
  recipientKeyKind: number
  recipientKeyVersion: number
  recipientFingerprint: Uint8Array
  parentDescriptorHash?: Uint8Array
}

function fixed(value: Uint8Array): Uint8Array {
  if (value.length !== HASH_BYTES) throw new RangeError('Wrapper context hash fields must be 32 bytes')
  return value
}

/** `contextEncoding.layout` of key-wrapper v1. */
export function encodeWrapperContext(context: EncodableWrapperContext): Uint8Array {
  if (!/^[\x21-\x7e]{1,64}$/.test(context.wrapperSuiteId)) throw new TypeError('Invalid wrapper suite id')
  const present = SCOPE_FIELDS.filter(([field]) => context.scope[field])
  const suiteId = encodeUtf8(context.wrapperSuiteId)
  return concatBytes(
    CONTEXT_MAGIC,
    encodeU16(context.protocolVersion),
    encodeU16(suiteId.length),
    suiteId,
    encodeU16(context.purpose),
    encodeU16(present.reduce((bitmap, [, bit]) => bitmap | bit, 0)),
    ...present.map(([field]) => decodeUuid(context.scope[field]!.toLowerCase())),
    encodeU64(context.resourceRevision),
    encodeU32(context.wrappedKeyVersion),
    ...(context.memberKeyGeneration === undefined
      ? [Uint8Array.of(0)]
      : [Uint8Array.of(1), encodeU32(context.memberKeyGeneration)]),
    encodeU16(context.recipientKeyKind),
    encodeU32(context.recipientKeyVersion),
    fixed(context.recipientFingerprint),
    ...(context.parentDescriptorHash === undefined
      ? [Uint8Array.of(0)]
      : [Uint8Array.of(1), fixed(context.parentDescriptorHash)]),
  )
}

export function wrapperContextHash(encodedContext: Uint8Array): Uint8Array {
  return sha256Digest(concatBytes(CONTEXT_HASH_MAGIC, encodedContext))
}
