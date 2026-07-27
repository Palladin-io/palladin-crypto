import {
  ENVELOPE_PURPOSE,
  type CanonicalEnvelopeAad,
  type EnvelopeAadExtension,
  type EnvelopeDescriptor,
  type GrantAadExtension,
  type KdfContextDescriptor,
  type MemberSecretAadExtension,
  type ReasonAadExtension,
  type WrappingAadExtension,
} from './envelope'

const ENVELOPE_MAGIC = new TextEncoder().encode('PLDNENV2')
const KDF_MAGIC = new TextEncoder().encode('PLDNKDF2')
const FIELD_SET_MAGIC = new TextEncoder().encode('PLDNV2FS')
export const X25519_WRAPPER_SUITE_ID = 'palladin-x25519-sealed-box-v1'
const ASCII = /^[\x20-\x7e]+$/
const FIELD_ID = /^[A-Za-z0-9._:-]{1,128}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

const SCOPE = {
  organization: 1 << 0,
  vault: 1 << 1,
  entry: 1 << 2,
  grantOrRequest: 1 << 3,
  agent: 1 << 4,
  member: 1 << 5,
} as const

class BinaryWriter {
  private readonly chunks: Uint8Array[] = []
  private length = 0

  bytes(value: Uint8Array): void {
    const copy = new Uint8Array(value)
    this.chunks.push(copy)
    this.length += copy.length
  }

  u8(value: number): void {
    this.integer(value, 1, 'u8')
  }

  u16(value: number): void {
    this.integer(value, 2, 'u16')
  }

  u32(value: number): void {
    this.integer(value, 4, 'u32')
  }

  u64(value: number | bigint): void {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new RangeError('u64 number must be a safe integer')
    const normalized = typeof value === 'bigint' ? value : BigInt(value)
    if (normalized < 0n || normalized > 0xffffffffffffffffn) throw new RangeError('u64 out of range')
    const bytes = new Uint8Array(8)
    new DataView(bytes.buffer).setBigUint64(0, normalized)
    this.bytes(bytes)
  }

  i64(value: number | bigint): void {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new RangeError('i64 number must be a safe integer')
    const normalized = typeof value === 'bigint' ? value : BigInt(value)
    if (normalized < -0x8000000000000000n || normalized > 0x7fffffffffffffffn) {
      throw new RangeError('i64 out of range')
    }
    const bytes = new Uint8Array(8)
    new DataView(bytes.buffer).setBigInt64(0, normalized)
    this.bytes(bytes)
  }

  finish(): Uint8Array {
    const result = new Uint8Array(this.length)
    let offset = 0
    for (const chunk of this.chunks) {
      result.set(chunk, offset)
      offset += chunk.length
    }
    return result
  }

  private integer(value: number, byteLength: 1 | 2 | 4, label: string): void {
    const maximum = 2 ** (byteLength * 8) - 1
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
      throw new RangeError(`${label} out of range`)
    }
    const bytes = new Uint8Array(byteLength)
    const view = new DataView(bytes.buffer)
    if (byteLength === 1) view.setUint8(0, value)
    else if (byteLength === 2) view.setUint16(0, value)
    else view.setUint32(0, value)
    this.bytes(bytes)
  }
}

function uuidBytes(value: string): Uint8Array {
  if (!UUID.test(value)) throw new TypeError('Scope identifier must be an RFC 4122 UUID')
  const compact = value.replaceAll('-', '')
  return Uint8Array.from(compact.match(/../g)!.map((pair) => Number.parseInt(pair, 16)))
}

function exactBytes(value: Uint8Array, length: number, name: string): Uint8Array {
  if (value.length !== length) throw new RangeError(`${name} must be ${length} bytes`)
  return value
}

function writeAscii(writer: BinaryWriter, value: string, name: string): void {
  if (!ASCII.test(value)) throw new TypeError(`${name} must be printable ASCII`)
  const bytes = new TextEncoder().encode(value)
  writer.u16(bytes.length)
  writer.bytes(bytes)
}

function writeBase(writer: BinaryWriter, descriptor: EnvelopeDescriptor): void {
  const suite = String(descriptor.cryptoSuiteId)
  if (!ASCII.test(suite)) throw new TypeError('Crypto suite id must be printable ASCII')
  writer.bytes(ENVELOPE_MAGIC)
  writer.u16(descriptor.protocolVersion)
  writeAscii(writer, suite, 'Crypto suite id')
  writer.u16(descriptor.purpose)

  let bitmap = SCOPE.organization | SCOPE.vault
  if (descriptor.entryId) bitmap |= SCOPE.entry
  if (descriptor.grantOrRequestId) bitmap |= SCOPE.grantOrRequest
  if (descriptor.agentId) bitmap |= SCOPE.agent
  if (descriptor.memberId) bitmap |= SCOPE.member
  writer.u16(bitmap)
  writer.bytes(uuidBytes(descriptor.organizationId))
  writer.bytes(uuidBytes(descriptor.vaultId))
  if (descriptor.entryId) writer.bytes(uuidBytes(descriptor.entryId))
  if (descriptor.grantOrRequestId) writer.bytes(uuidBytes(descriptor.grantOrRequestId))
  if (descriptor.agentId) writer.bytes(uuidBytes(descriptor.agentId))
  if (descriptor.memberId) writer.bytes(uuidBytes(descriptor.memberId))

  writer.u64(descriptor.resourceRevision)
  writer.u32(descriptor.keyVersion)
  writer.u8(descriptor.memberKeyGeneration === undefined ? 0 : 1)
  if (descriptor.memberKeyGeneration !== undefined) writer.u32(descriptor.memberKeyGeneration)
}

function writeScope(
  writer: BinaryWriter,
  scope: Pick<KdfContextDescriptor, 'organizationId' | 'vaultId' | 'entryId' | 'grantOrRequestId' | 'agentId' | 'memberId'>,
): void {
  let bitmap = SCOPE.organization | SCOPE.vault
  if (scope.entryId) bitmap |= SCOPE.entry
  if (scope.grantOrRequestId) bitmap |= SCOPE.grantOrRequest
  if (scope.agentId) bitmap |= SCOPE.agent
  if (scope.memberId) bitmap |= SCOPE.member
  writer.u16(bitmap)
  writer.bytes(uuidBytes(scope.organizationId))
  writer.bytes(uuidBytes(scope.vaultId))
  if (scope.entryId) writer.bytes(uuidBytes(scope.entryId))
  if (scope.grantOrRequestId) writer.bytes(uuidBytes(scope.grantOrRequestId))
  if (scope.agentId) writer.bytes(uuidBytes(scope.agentId))
  if (scope.memberId) writer.bytes(uuidBytes(scope.memberId))
}

function writeExtension(
  writer: BinaryWriter,
  descriptor: EnvelopeDescriptor,
  extension: EnvelopeAadExtension,
): void {
  switch (descriptor.purpose) {
    case ENVELOPE_PURPOSE.memberSecret: {
      const value = extension as MemberSecretAadExtension | undefined
      if (!value || !('operation' in value)) throw new TypeError('MemberSecret operation is required')
      writer.u16(value.operation)
      return
    }
    case ENVELOPE_PURPOSE.vaultDiscoveryKeyByVk:
    case ENVELOPE_PURPOSE.agentMessagePrivateByVk:
    case ENVELOPE_PURPOSE.manifestPrivateByVk:
    case ENVELOPE_PURPOSE.entryDekByVk: {
      const value = extension as WrappingAadExtension | undefined
      if (!value || !('wrappingVkVersion' in value)) throw new TypeError('Wrapping VK version is required')
      writer.u32(value.wrappingVkVersion)
      return
    }
    case ENVELOPE_PURPOSE.reason: {
      const value = extension as ReasonAadExtension | undefined
      if (!value || !('recipientKeyFingerprint' in value)) throw new TypeError('Reason extension is required')
      if (value.wrapperSuiteId !== X25519_WRAPPER_SUITE_ID) throw new TypeError('Unsupported recipient wrapper suite')
      writeAscii(writer, value.wrapperSuiteId, 'Wrapper suite id')
      writer.u32(value.recipientKeyVersion)
      writer.bytes(exactBytes(value.recipientKeyFingerprint, 32, 'Recipient key fingerprint'))
      writer.u16(value.methods)
      return
    }
    case ENVELOPE_PURPOSE.grant: {
      const value = extension as GrantAadExtension | undefined
      if (!value || !('fieldSetCommitment' in value)) throw new TypeError('Grant extension is required')
      writer.u64(value.entryRevision)
      if (value.wrapperSuiteId !== X25519_WRAPPER_SUITE_ID) throw new TypeError('Unsupported recipient wrapper suite')
      writeAscii(writer, value.wrapperSuiteId, 'Wrapper suite id')
      writer.u32(value.recipientKeyVersion)
      writer.bytes(exactBytes(value.recipientKeyFingerprint, 32, 'Recipient key fingerprint'))
      writer.u16(value.methods)
      writer.bytes(exactBytes(value.fieldSetCommitment, 32, 'Field-set commitment'))
      writer.u8(value.expiresAt === undefined ? 0 : 1)
      if (value.expiresAt) {
        writer.i64(value.expiresAt.seconds)
        if (!Number.isSafeInteger(value.expiresAt.nanoseconds) || value.expiresAt.nanoseconds < 0 || value.expiresAt.nanoseconds > 999_999_999) {
          throw new RangeError('Expiry nanoseconds out of range')
        }
        writer.u32(value.expiresAt.nanoseconds)
      }
      writer.u8(value.remainingUses === undefined ? 0 : 1)
      if (value.remainingUses !== undefined) writer.u32(value.remainingUses)
      return
    }
    default:
      if (extension !== undefined) throw new TypeError('This envelope purpose has no AAD extension')
  }
}

/** Encode PLDNENV2 exactly once for every web encryption/decryption path. */
export function encodeCanonicalEnvelopeAad(
  descriptor: EnvelopeDescriptor,
  extension?: EnvelopeAadExtension,
): CanonicalEnvelopeAad {
  const writer = new BinaryWriter()
  writeBase(writer, descriptor)
  writeExtension(writer, descriptor, extension)
  return writer.finish() as CanonicalEnvelopeAad
}

/** Encode the revision-independent PLDNKDF2 HKDF info value. */
export function encodeCanonicalKdfContext(context: KdfContextDescriptor): Uint8Array {
  const writer = new BinaryWriter()
  writer.bytes(KDF_MAGIC)
  writer.u16(context.protocolVersion)
  writeAscii(writer, String(context.cryptoSuiteId), 'Crypto suite id')
  writer.u16(context.purpose)
  writeScope(writer, context)
  writer.u32(context.keyVersion)
  writer.u8(context.memberKeyGeneration === undefined ? 0 : 1)
  if (context.memberKeyGeneration !== undefined) writer.u32(context.memberKeyGeneration)
  return writer.finish()
}

/** SHA-256(PLDNV2FS || count-u32 || repeated(u16-len || ASCII field id)). */
export async function computeFieldSetCommitment(fieldIds: readonly string[]): Promise<Uint8Array> {
  if (fieldIds.length === 0) throw new TypeError('Field ids cannot be empty')
  const encoded = fieldIds.map((fieldId) => {
    if (!FIELD_ID.test(fieldId)) throw new TypeError(`Invalid field id: ${fieldId}`)
    return new TextEncoder().encode(fieldId)
  })
  encoded.sort((left, right) => {
    const limit = Math.min(left.length, right.length)
    for (let i = 0; i < limit; i++) {
      if (left[i] !== right[i]) return left[i] - right[i]
    }
    return left.length - right.length
  })
  for (let i = 1; i < encoded.length; i++) {
    if (encoded[i].length === encoded[i - 1].length && encoded[i].every((byte, j) => byte === encoded[i - 1][j])) {
      throw new TypeError('Field ids must be distinct')
    }
  }

  const writer = new BinaryWriter()
  writer.bytes(FIELD_SET_MAGIC)
  writer.u32(encoded.length)
  for (const fieldId of encoded) {
    writer.u16(fieldId.length)
    writer.bytes(fieldId)
  }
  const input = writer.finish()
  const digestInput = new Uint8Array(input.length)
  digestInput.set(input)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', digestInput.buffer))
}

