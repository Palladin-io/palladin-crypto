import { wipe } from './sodium'
import { fromBase64Url } from './encoding'
import { encodeWrapperContext, wrapperContextHash } from './key-wrapper/context'
import { equalBytes, legacyKeyFingerprint, x25519SealedBoxV1 } from './key-wrapper/suites/x25519-sealed-box-v1'

export const X25519_SEALED_BOX_V1 = 'palladin-x25519-sealed-box-v1'

export const WRAPPER_PURPOSE = {
  memberVaultKey: 1,
  agentVaultDiscoveryKey: 2,
  reasonDek: 3,
  grantDek: 4,
  scriptExecutionDek: 6,
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

function fixed(value: Uint8Array, length: number, name: string): Uint8Array {
  if (value.length !== length) throw new RangeError(`${name} must be ${length} bytes`)
  return value
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
          : context.purpose === WRAPPER_PURPOSE.scriptExecutionDek
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
  return legacyKeyFingerprint(rawPublicKey, keyKind, protocolVersion)
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
    || descriptor.scope.entryId != null
    || descriptor.scope.grantOrRequestId != null
    || descriptor.scope.agentId != null
    || descriptor.memberKeyGeneration == null
    || descriptor.resourceRevision !== String(descriptor.wrappedKeyVersion)
    || descriptor.parentDescriptorHash != null) {
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
  for (const id of [context.organizationId, context.vaultId, context.entryId, context.grantOrRequestId, context.agentId, context.memberId]) {
    if (id && !UUID.test(id)) throw new TypeError('Scope identifier must be an RFC 4122 UUID')
  }
  if (typeof context.resourceRevision === 'number' && !Number.isSafeInteger(context.resourceRevision)) {
    throw new RangeError('u64 number must be safe')
  }
  return encodeWrapperContext({
    ...context,
    scope: {
      organizationId: context.organizationId,
      vaultId: context.vaultId,
      entryId: context.entryId,
      grantOrRequestId: context.grantOrRequestId,
      agentId: context.agentId,
      memberId: context.memberId,
    },
    resourceRevision: BigInt(context.resourceRevision),
    recipientFingerprint: fixed(context.recipientFingerprint, HASH_BYTES, 'Recipient fingerprint'),
    parentDescriptorHash: context.parentDescriptorHash
      && fixed(context.parentDescriptorHash, HASH_BYTES, 'Parent descriptor hash'),
  })
}

async function assertRecipient(recipientPublicKey: Uint8Array, context: X25519WrapperContext): Promise<void> {
  const fingerprint = await computeVaultKeyFingerprint(recipientPublicKey, context.recipientKeyKind, context.protocolVersion)
  if (!equalBytes(fingerprint, context.recipientFingerprint)) {
    throw new Error('Recipient public key fingerprint does not match wrapper context')
  }
}

/** Frozen vault-v2 / script-execution v1 write path; new contracts use `sealKey`. */
export async function sealKeyToX25519Recipient(
  key: Uint8Array,
  recipientPublicKey: Uint8Array,
  context: X25519WrapperContext,
): Promise<Uint8Array> {
  fixed(key, KEY_BYTES, 'Wrapped key')
  fixed(recipientPublicKey, KEY_BYTES, 'Recipient public key')
  await assertRecipient(recipientPublicKey, context)
  const contextHash = wrapperContextHash(encodeX25519WrapperContext(context))
  try {
    const sealed = await x25519SealedBoxV1.seal(key, recipientPublicKey, contextHash)
    if (sealed.length !== SEALED_PACKAGE_BYTES) throw new Error('Unexpected sealed package length')
    return sealed
  } finally {
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
  await assertRecipient(recipientPublicKey, context)
  const contextHash = wrapperContextHash(encodeX25519WrapperContext(context))
  try {
    return await x25519SealedBoxV1.open(sealedPackage, recipientPublicKey, recipientPrivateKey, contextHash)
  } catch {
    throw new Error('X25519 wrapped key context verification failed')
  } finally {
    wipe(contextHash)
  }
}
