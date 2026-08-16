import type { MemberVaultMetadataV1 } from './vault-plaintext'
import { parseMemberVaultMetadata } from './vault-plaintext'
import type { VaultEnvelopeContract } from './vault-envelope'
import { assertEnvelopeScope, openVaultEnvelope, sealVaultEnvelope, toEnvelopeDescriptor } from './vault-envelope'
import { deriveVaultSubkey } from './hkdf'
import { ENVELOPE_PURPOSE } from './envelope'
import { fromBase64Url } from './encoding'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { encodeMemberVaultMetadata } from './vault-plaintext'
import { wipe } from './sodium'
import { loadSodium } from './sodium-loader'
import {
  openKeyFromX25519Recipient,
  wrapperContextFromMemberVaultKey,
  type MemberVaultKeyEnvelopeContract,
} from './x25519-wrapper'

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

export async function openMemberVaultKey(
  envelope: MemberVaultKeyEnvelopeContract,
  memberPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  if (memberPrivateKey.length !== 32) throw new Error('Member private key must be 32 bytes')
  const sodium = await loadSodium()
  const publicKey = sodium.crypto_scalarmult_base(memberPrivateKey)
  try {
    return await openKeyFromX25519Recipient(
      fromBase64Url(envelope.wrappedVaultKey.encodedSealedKeyPackage, 120), publicKey, memberPrivateKey,
      wrapperContextFromMemberVaultKey(envelope),
    )
  } finally { wipe(publicKey) }
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
  memberPrivateKey: Uint8Array,
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
  if (vault.memberVaultMetadata.descriptor.keyVersion !== vault.currentKeyEpoch.vaultKeyVersion) {
    throw new Error('Vault metadata key version does not match the outer Vault')
  }
  const metadataDescriptor = toEnvelopeDescriptor(vault.memberVaultMetadata.descriptor)
  if (metadataDescriptor.resourceRevision.toString() !== vault.metadataRevision) {
    throw new Error('Vault metadata revision does not match the outer Vault')
  }

  const sodium = await loadSodium()
  const publicKey = sodium.crypto_scalarmult_base(memberPrivateKey)
  const vaultKey = await openKeyFromX25519Recipient(
    fromBase64Url(wrapper.encodedSealedKeyPackage, 120),
    publicKey,
    memberPrivateKey,
    wrapperContextFromMemberVaultKey(vault.memberVaultKey),
  )
  wipe(publicKey)
  try {
    assertEnvelopeScope(vault.memberVaultMetadata.descriptor, {
      purpose: ENVELOPE_PURPOSE.memberVaultMetadata,
      organizationId: vault.organizationId,
      vaultId: vault.id,
    })
    if (vault.memberVaultMetadata.descriptor.memberKeyGeneration !== vault.memberKeyGeneration) {
      throw new Error('Vault metadata generation does not match the outer Vault')
    }
    const metadataKey = await deriveVaultSubkey(vaultKey, {
      protocolVersion: metadataDescriptor.protocolVersion,
      cryptoSuiteId: metadataDescriptor.cryptoSuiteId,
      purpose: metadataDescriptor.purpose,
      organizationId: metadataDescriptor.organizationId,
      vaultId: metadataDescriptor.vaultId,
      keyVersion: metadataDescriptor.keyVersion,
      memberKeyGeneration: metadataDescriptor.memberKeyGeneration,
    })
    try {
      const plaintext = await openVaultEnvelope(vault.memberVaultMetadata, metadataKey)
      try {
        return { metadata: parseMemberVaultMetadata(plaintext), vaultKey }
      } finally {
        wipe(plaintext)
      }
    } finally {
      wipe(metadataKey)
    }
  } catch (error) {
    wipe(vaultKey)
    throw error
  }
}
