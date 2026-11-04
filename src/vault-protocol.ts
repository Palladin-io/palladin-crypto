import type { MemberVaultMetadataV1 } from './vault-plaintext'
import { parseMemberVaultMetadata } from './vault-plaintext'
import type { VaultEnvelopeContract } from './vault-envelope'
import { assertEnvelopeScope, openVaultEnvelope, sealVaultEnvelope, toEnvelopeDescriptor } from './vault-envelope'
import { deriveVaultSubkey } from './hkdf'
import { ENVELOPE_PURPOSE } from './envelope'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { encodeMemberVaultMetadata } from './vault-plaintext'
import { wipe } from './sodium'
import { openKey, type KeyWrapperDescriptor, type KeyWrapperRecipient } from './key-wrapper/key-wrapper'
import { KEY_WRAPPER_PURPOSE, RECIPIENT_KEY_KIND } from './key-wrapper/registry'

export interface MemberVaultKeyEnvelopeContract {
  wrappedVaultKey: {
    descriptor: KeyWrapperDescriptor
    encodedSealedKeyPackage: string
  }
}

export interface EmptyEnvelopeBindingContract { readonly __empty?: never }

export type MemberVaultMetadataEnvelopeContract = VaultEnvelopeContract<EmptyEnvelopeBindingContract>

export interface EncryptedVaultProjection {
  id: string
  organizationId: string
  metadataRevision: string
  memberKeyGeneration: number
  currentKeyEpoch: {
    vaultKeyVersion: number
  }
  memberVaultMetadata: MemberVaultMetadataEnvelopeContract
  memberVaultKey: MemberVaultKeyEnvelopeContract
}

export async function sealMemberVaultMetadata(
  outer: Pick<EncryptedVaultProjection, 'id' | 'organizationId' | 'memberKeyGeneration'>,
  current: MemberVaultMetadataEnvelopeContract,
  metadata: MemberVaultMetadataV1,
  vaultKey: Uint8Array,
): Promise<MemberVaultMetadataEnvelopeContract> {
  assertEnvelopeScope(current.descriptor, {
    purpose: ENVELOPE_PURPOSE.memberVaultMetadata,
    organizationId: outer.organizationId,
    vaultId: outer.id,
  })
  if (current.descriptor.memberKeyGeneration !== outer.memberKeyGeneration) {
    throw new Error('Vault metadata generation does not match the outer Vault')
  }
  const revision = BigInt(current.descriptor.resourceRevision) + 1n
  const descriptor = {
    protocolVersion: 2,
    cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
    purpose: ENVELOPE_PURPOSE.memberVaultMetadata,
    scope: { organizationId: outer.organizationId, vaultId: outer.id },
    resourceRevision: revision.toString(),
    keyVersion: current.descriptor.keyVersion,
    memberKeyGeneration: outer.memberKeyGeneration,
    binding: {},
  } satisfies MemberVaultMetadataEnvelopeContract['descriptor']
  const key = await deriveVaultSubkey(vaultKey, {
    protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
    purpose: descriptor.purpose, organizationId: outer.organizationId, vaultId: outer.id,
    keyVersion: descriptor.keyVersion, memberKeyGeneration: outer.memberKeyGeneration,
  })
  try {
    const plaintext = encodeMemberVaultMetadata(metadata)
    try { return await sealVaultEnvelope(descriptor, plaintext, key) }
    finally { wipe(plaintext) }
  } finally { wipe(key) }
}

export interface OpenVaultProjectionResult {
  metadata: MemberVaultMetadataV1
  vaultKey: Uint8Array
}

/**
 * Opens the Member Vault key with the member's own key from the authenticated
 * member key directory (`keySuiteId`, `keyKind` = memberEncryption,
 * `keyVersion`, `publicKey`, `privateKey`). Works for every openable suite.
 */
export async function openMemberVaultKey(
  envelope: MemberVaultKeyEnvelopeContract,
  memberKey: KeyWrapperRecipient,
): Promise<Uint8Array> {
  const descriptor = envelope.wrappedVaultKey.descriptor
  // Frozen Member-VK rule: resource revision and wrapped-key version both equal vkVersion.
  if (descriptor.purpose !== KEY_WRAPPER_PURPOSE.memberVaultKey
    || memberKey.keyKind !== RECIPIENT_KEY_KIND.memberEncryption
    || descriptor.resourceRevision !== String(descriptor.wrappedKeyVersion)) {
    throw new Error('Invalid Member Vault-key wrapper descriptor')
  }
  return openKey(descriptor, envelope.wrappedVaultKey.encodedSealedKeyPackage, memberKey)
}

export async function openVaultDerivedEnvelope<TBinding extends { wrappingVaultKeyVersion: number }>(
  envelope: VaultEnvelopeContract<TBinding>,
  vaultKey: Uint8Array,
): Promise<Uint8Array> {
  const descriptor = toEnvelopeDescriptor(envelope.descriptor)
  const key = await deriveVaultSubkey(vaultKey, {
    protocolVersion: descriptor.protocolVersion, cryptoSuiteId: descriptor.cryptoSuiteId,
    purpose: descriptor.purpose, organizationId: descriptor.organizationId, vaultId: descriptor.vaultId,
    keyVersion: descriptor.keyVersion, memberKeyGeneration: descriptor.memberKeyGeneration,
  })
  try {
    return await openVaultEnvelope(envelope, key, {
      wrappingVkVersion: envelope.descriptor.binding.wrappingVaultKeyVersion,
    })
  } finally { wipe(key) }
}

export async function openVaultProjection(
  vault: EncryptedVaultProjection,
  memberKey: KeyWrapperRecipient,
  memberId: string,
): Promise<OpenVaultProjectionResult> {
  const wrapper = vault.memberVaultKey.wrappedVaultKey
  if (wrapper.descriptor.scope.organizationId !== vault.organizationId
    || wrapper.descriptor.scope.vaultId !== vault.id
    || wrapper.descriptor.scope.memberId !== memberId
    || wrapper.descriptor.memberKeyGeneration !== vault.memberKeyGeneration
    || wrapper.descriptor.resourceRevision !== String(vault.currentKeyEpoch.vaultKeyVersion)
    || wrapper.descriptor.wrappedKeyVersion !== vault.currentKeyEpoch.vaultKeyVersion) {
    throw new Error('Member Vault-key envelope does not match the outer Vault')
  }
  assertMetadataMatchesVault(vault)

  const vaultKey = await openMemberVaultKey(vault.memberVaultKey, memberKey)
  try {
    return { metadata: await openMemberVaultMetadata(vault, vaultKey), vaultKey }
  } catch (error) {
    wipe(vaultKey)
    throw error
  }
}

function assertMetadataMatchesVault(vault: EncryptedVaultProjection) {
  const envelope = vault.memberVaultMetadata
  if (envelope.descriptor.keyVersion !== vault.currentKeyEpoch.vaultKeyVersion) {
    throw new Error('Vault metadata key version does not match the outer Vault')
  }
  const descriptor = toEnvelopeDescriptor(envelope.descriptor)
  if (descriptor.resourceRevision.toString() !== vault.metadataRevision) {
    throw new Error('Vault metadata revision does not match the outer Vault')
  }
  assertEnvelopeScope(envelope.descriptor, {
    purpose: ENVELOPE_PURPOSE.memberVaultMetadata,
    organizationId: vault.organizationId,
    vaultId: vault.id,
  })
  if (envelope.descriptor.memberKeyGeneration !== vault.memberKeyGeneration) {
    throw new Error('Vault metadata generation does not match the outer Vault')
  }
  return descriptor
}

/**
 * Opens the Member Vault metadata of `vault` with a Vault key the caller has
 * already opened for this Vault (for example with `openMemberVaultKey`).
 */
export async function openMemberVaultMetadata(
  vault: EncryptedVaultProjection,
  vaultKey: Uint8Array,
): Promise<MemberVaultMetadataV1> {
  const descriptor = assertMetadataMatchesVault(vault)
  const metadataKey = await deriveVaultSubkey(vaultKey, {
    protocolVersion: descriptor.protocolVersion,
    cryptoSuiteId: descriptor.cryptoSuiteId,
    purpose: descriptor.purpose,
    organizationId: descriptor.organizationId,
    vaultId: descriptor.vaultId,
    keyVersion: descriptor.keyVersion,
    memberKeyGeneration: descriptor.memberKeyGeneration,
  })
  try {
    const plaintext = await openVaultEnvelope(vault.memberVaultMetadata, metadataKey)
    try {
      return parseMemberVaultMetadata(plaintext)
    } finally {
      wipe(plaintext)
    }
  } finally {
    wipe(metadataKey)
  }
}
