import { wipe } from './sodium'
import { loadSodium } from './sodium-loader'
import { fromBase64Url } from './encoding'

export const X25519_SEALED_BOX_V1 = 'palladin-x25519-sealed-box-v1'

export const WRAPPER_PURPOSE = {
  memberVaultKey: 1,
  agentVaultDiscoveryKey: 2,
  reasonDek: 3,
  grantDek: 4,
} as const

export type WrapperPurpose = (typeof WRAPPER_PURPOSE)[keyof typeof WRAPPER_PURPOSE]

export const VAULT_KEY_KIND = {
  agentX25519: 1,
  agentEd25519: 2,
  vaultSigningEd25519: 3,
  vaultMessageX25519: 4,
  memberX25519: 5,
} as const

export type VaultKeyKind = (typeof VAULT_KEY_KIND)[keyof typeof VAULT_KEY_KIND]

export interface X25519WrapperContext {
  protocolVersion: number
  wrapperSuiteId: typeof X25519_SEALED_BOX_V1
  purpose: WrapperPurpose
  organizationId: string
  vaultId: string
  entryId?: string
  grantOrRequestId?: string
  agentId?: string
  memberId?: string
  resourceRevision: number | bigint
  wrappedKeyVersion: number
  memberKeyGeneration?: number
  recipientKeyKind: VaultKeyKind
  recipientKeyVersion: number
  recipientFingerprint: Uint8Array
  parentDescriptorHash?: Uint8Array
}

export interface MemberVaultKeyEnvelopeContract {
  wrappedVaultKey: {
    descriptor: X25519WrapperDescriptorContract
    encodedSealedKeyPackage: string
  }
}

export interface X25519WrapperDescriptorContract {
  protocolVersion: number
  wrapperSuiteId: string
  purpose: WrapperPurpose
  scope: {
    organizationId: string
    vaultId: string
    entryId?: string | null
    grantOrRequestId?: string | null
    agentId?: string | null
    memberId?: string | null
  }
  resourceRevision: string
  wrappedKeyVersion: number
  memberKeyGeneration?: number | null
  recipientKeyKind: VaultKeyKind
  recipientKeyVersion: number
  recipientFingerprint: string
  parentDescriptorHash?: string | null
}

const CONTEXT_MAGIC = new TextEncoder().encode('PLDNX2W1')
const CONTEXT_HASH_MAGIC = new TextEncoder().encode('PLDNX2CTX')
const PACKAGE_MAGIC = new TextEncoder().encode('PLDNX2K1')
const FINGERPRINT_MAGIC = new TextEncoder().encode('PLDNV2FP')
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
const KEY_BYTES = 32
const HASH_BYTES = 32
const SEALED_PACKAGE_BYTES = 120

const SCOPE = {
  organization: 1 << 0,
  vault: 1 << 1,
  entry: 1 << 2,
  grantOrRequest: 1 << 3,
  agent: 1 << 4,
  member: 1 << 5,
} as const

class Writer {
  private readonly chunks: Uint8Array[] = []
  private size = 0
  bytes(value: Uint8Array): void { const copy = new Uint8Array(value); this.chunks.push(copy); this.size += copy.length }
  u8(value: number): void { this.number(value, 1) }
  u16(value: number): void { this.number(value, 2) }
  u32(value: number): void { this.number(value, 4) }
  u64(value: number | bigint): void {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new RangeError('u64 number must be safe')
    const normalized = typeof value === 'bigint' ? value : BigInt(value)
    if (normalized < 0n || normalized > 0xffffffffffffffffn) throw new RangeError('u64 out of range')
    const output = new Uint8Array(8)
    new DataView(output.buffer).setBigUint64(0, normalized)
    this.bytes(output)
  }
  ascii(value: string): void {
    if (!/^[\x20-\x7e]+$/.test(value)) throw new TypeError('Protocol id must be printable ASCII')
    const encoded = new TextEncoder().encode(value)
    this.u16(encoded.length)
    this.bytes(encoded)
  }
  finish(): Uint8Array {
    const output = new Uint8Array(this.size)
    let offset = 0
    for (const chunk of this.chunks) { output.set(chunk, offset); offset += chunk.length }
    return output
  }
  private number(value: number, size: 1 | 2 | 4): void {
    const maximum = 2 ** (size * 8) - 1
    if (!Number.isSafeInteger(value) || value < 0 || value > maximum) throw new RangeError('Integer out of range')
    const output = new Uint8Array(size)
    const view = new DataView(output.buffer)
    if (size === 1) view.setUint8(0, value)
    else if (size === 2) view.setUint16(0, value)
    else view.setUint32(0, value)
    this.bytes(output)
  }
}

function uuidBytes(value: string): Uint8Array {
  if (!UUID.test(value)) throw new TypeError('Scope identifier must be an RFC 4122 UUID')
  return Uint8Array.from(value.replaceAll('-', '').match(/../g)!.map((pair) => Number.parseInt(pair, 16)))
}

function fixed(value: Uint8Array, length: number, name: string): Uint8Array {
  if (value.length !== length) throw new RangeError(`${name} must be ${length} bytes`)
  return value
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

function presentScopeBitmap(context: X25519WrapperContext): number {
  return SCOPE.organization | SCOPE.vault
    | (context.entryId ? SCOPE.entry : 0)
    | (context.grantOrRequestId ? SCOPE.grantOrRequest : 0)
    | (context.agentId ? SCOPE.agent : 0)
    | (context.memberId ? SCOPE.member : 0)
}

function validateContext(context: X25519WrapperContext): void {
  if (context.protocolVersion !== 2) {
    throw new TypeError('Unsupported or downgraded X25519 wrapper protocol')
  }
  const vault = SCOPE.organization | SCOPE.vault
  const parentBound = vault | SCOPE.entry | SCOPE.grantOrRequest | SCOPE.agent
  const expected = context.purpose === WRAPPER_PURPOSE.memberVaultKey
    ? { scope: vault | SCOPE.member, kind: VAULT_KEY_KIND.memberX25519, parent: false }
    : context.purpose === WRAPPER_PURPOSE.agentVaultDiscoveryKey
      ? { scope: vault | SCOPE.agent, kind: VAULT_KEY_KIND.agentX25519, parent: false }
      : context.purpose === WRAPPER_PURPOSE.reasonDek
        ? { scope: parentBound, kind: VAULT_KEY_KIND.vaultMessageX25519, parent: true }
        : context.purpose === WRAPPER_PURPOSE.grantDek
          ? { scope: parentBound, kind: VAULT_KEY_KIND.agentX25519, parent: true }
          : undefined
  if (!expected || presentScopeBitmap(context) !== expected.scope
    || context.recipientKeyKind !== expected.kind
    || (context.parentDescriptorHash !== undefined) !== expected.parent) {
    throw new TypeError('Wrapper context does not match its registered purpose')
  }
  if (context.resourceRevision === 0 || context.resourceRevision === 0n || context.wrappedKeyVersion === 0
    || context.memberKeyGeneration === 0 || context.recipientKeyVersion === 0) {
    throw new RangeError('Wrapper context versions must be positive')
  }
}

export async function computeVaultKeyFingerprint(
  rawPublicKey: Uint8Array,
  keyKind: VaultKeyKind,
  protocolVersion = 2,
): Promise<Uint8Array> {
  fixed(rawPublicKey, KEY_BYTES, 'Public key')
  const writer = new Writer()
  writer.bytes(FINGERPRINT_MAGIC)
  writer.u16(protocolVersion)
  writer.u16(keyKind)
  writer.bytes(rawPublicKey)
  const input = writer.finish()
  const copy = new Uint8Array(input.length)
  copy.set(input)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', copy.buffer))
}

/**
 * Frozen Member-VK rule: both wrapper resource revision and wrapped-key
 * version equal `vkVersion`; the package is scoped to org/vault/member.
 */
export function wrapperContextFromMemberVaultKey(
  contract: MemberVaultKeyEnvelopeContract,
): X25519WrapperContext {
  const descriptor = contract.wrappedVaultKey.descriptor
  if (descriptor.protocolVersion !== 2 || descriptor.wrapperSuiteId !== X25519_SEALED_BOX_V1) {
    throw new TypeError('Unsupported or downgraded X25519 wrapper protocol')
  }
  if (descriptor.purpose !== WRAPPER_PURPOSE.memberVaultKey
    || descriptor.recipientKeyKind !== VAULT_KEY_KIND.memberX25519
    || descriptor.scope.memberId == null
    || descriptor.memberKeyGeneration == null
    || descriptor.resourceRevision !== String(descriptor.wrappedKeyVersion)) {
    throw new TypeError('Invalid Member Vault-key wrapper descriptor')
  }
  return {
    protocolVersion: descriptor.protocolVersion,
    wrapperSuiteId: X25519_SEALED_BOX_V1,
    purpose: WRAPPER_PURPOSE.memberVaultKey,
    organizationId: descriptor.scope.organizationId,
    vaultId: descriptor.scope.vaultId,
    memberId: descriptor.scope.memberId,
    resourceRevision: BigInt(descriptor.resourceRevision),
    wrappedKeyVersion: descriptor.wrappedKeyVersion,
    memberKeyGeneration: descriptor.memberKeyGeneration,
    recipientKeyKind: VAULT_KEY_KIND.memberX25519,
    recipientKeyVersion: descriptor.recipientKeyVersion,
    recipientFingerprint: fromBase64Url(descriptor.recipientFingerprint, HASH_BYTES),
  }
}

export function encodeX25519WrapperContext(context: X25519WrapperContext): Uint8Array {
  if (context.wrapperSuiteId !== X25519_SEALED_BOX_V1) throw new TypeError('Unsupported wrapper suite')
  validateContext(context)

  const writer = new Writer()
  writer.bytes(CONTEXT_MAGIC)
  writer.u16(context.protocolVersion)
  writer.ascii(context.wrapperSuiteId)
  writer.u16(context.purpose)
  let bitmap = SCOPE.organization | SCOPE.vault
  if (context.entryId) bitmap |= SCOPE.entry
  if (context.grantOrRequestId) bitmap |= SCOPE.grantOrRequest
  if (context.agentId) bitmap |= SCOPE.agent
  if (context.memberId) bitmap |= SCOPE.member
  writer.u16(bitmap)
  writer.bytes(uuidBytes(context.organizationId))
  writer.bytes(uuidBytes(context.vaultId))
  if (context.entryId) writer.bytes(uuidBytes(context.entryId))
  if (context.grantOrRequestId) writer.bytes(uuidBytes(context.grantOrRequestId))
  if (context.agentId) writer.bytes(uuidBytes(context.agentId))
  if (context.memberId) writer.bytes(uuidBytes(context.memberId))
  writer.u64(context.resourceRevision)
  writer.u32(context.wrappedKeyVersion)
  writer.u8(context.memberKeyGeneration === undefined ? 0 : 1)
  if (context.memberKeyGeneration !== undefined) writer.u32(context.memberKeyGeneration)
  writer.u16(context.recipientKeyKind)
  writer.u32(context.recipientKeyVersion)
  writer.bytes(fixed(context.recipientFingerprint, HASH_BYTES, 'Recipient fingerprint'))
  writer.u8(context.parentDescriptorHash === undefined ? 0 : 1)
  if (context.parentDescriptorHash) writer.bytes(fixed(context.parentDescriptorHash, HASH_BYTES, 'Parent descriptor hash'))
  return writer.finish()
}

async function computeContextHash(context: X25519WrapperContext): Promise<Uint8Array> {
  const encoded = encodeX25519WrapperContext(context)
  const input = new Uint8Array(CONTEXT_HASH_MAGIC.length + encoded.length)
  input.set(CONTEXT_HASH_MAGIC)
  input.set(encoded, CONTEXT_HASH_MAGIC.length)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', input.buffer))
}

export async function sealKeyToX25519Recipient(
  key: Uint8Array,
  recipientPublicKey: Uint8Array,
  context: X25519WrapperContext,
): Promise<Uint8Array> {
  fixed(key, KEY_BYTES, 'Wrapped key')
  fixed(recipientPublicKey, KEY_BYTES, 'Recipient public key')
  const recipientFingerprint = await computeVaultKeyFingerprint(
    recipientPublicKey,
    context.recipientKeyKind,
    context.protocolVersion,
  )
  if (!equalBytes(recipientFingerprint, context.recipientFingerprint)) {
    throw new Error('Recipient public key fingerprint does not match wrapper context')
  }
  const sodium = await loadSodium()
  const contextHash = await computeContextHash(context)
  const plaintextPackage = new Uint8Array(PACKAGE_MAGIC.length + KEY_BYTES + HASH_BYTES)
  plaintextPackage.set(PACKAGE_MAGIC)
  plaintextPackage.set(key, PACKAGE_MAGIC.length)
  plaintextPackage.set(contextHash, PACKAGE_MAGIC.length + KEY_BYTES)
  try {
    const sealed = sodium.crypto_box_seal(plaintextPackage, recipientPublicKey)
    if (sealed.length !== SEALED_PACKAGE_BYTES) throw new Error('Unexpected sealed package length')
    return sealed
  } finally {
    wipe(plaintextPackage)
    wipe(contextHash)
  }
}

export async function openKeyFromX25519Recipient(
  sealedPackage: Uint8Array,
  recipientPublicKey: Uint8Array,
  recipientPrivateKey: Uint8Array,
  context: X25519WrapperContext,
): Promise<Uint8Array> {
  fixed(sealedPackage, SEALED_PACKAGE_BYTES, 'Sealed package')
  fixed(recipientPublicKey, KEY_BYTES, 'Recipient public key')
  fixed(recipientPrivateKey, KEY_BYTES, 'Recipient private key')
  const recipientFingerprint = await computeVaultKeyFingerprint(
    recipientPublicKey,
    context.recipientKeyKind,
    context.protocolVersion,
  )
  if (!equalBytes(recipientFingerprint, context.recipientFingerprint)) {
    throw new Error('Recipient public key fingerprint does not match wrapper context')
  }
  const sodium = await loadSodium()
  const opened = sodium.crypto_box_seal_open(sealedPackage, recipientPublicKey, recipientPrivateKey)
  try {
    const expectedHash = await computeContextHash(context)
    try {
      const openedMagic = new Uint8Array(opened.slice(0, PACKAGE_MAGIC.length))
      const openedHash = new Uint8Array(opened.slice(PACKAGE_MAGIC.length + KEY_BYTES))
      if (opened.length !== PACKAGE_MAGIC.length + KEY_BYTES + HASH_BYTES
        || !equalBytes(openedMagic, PACKAGE_MAGIC)
        || !equalBytes(openedHash, expectedHash)) {
        throw new Error('X25519 wrapped key context verification failed')
      }
      return opened.slice(PACKAGE_MAGIC.length, PACKAGE_MAGIC.length + KEY_BYTES)
    } finally {
      wipe(expectedHash)
    }
  } finally {
    wipe(opened)
  }
}
