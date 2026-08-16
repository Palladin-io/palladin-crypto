import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { ENVELOPE_PURPOSE } from './envelope'
import { deriveVaultSubkey } from './hkdf'
import { randomBytes, wipe } from './sodium'
import {
  encodeAgentDiscovery, encodeMemberIndex, encodeMemberSecret,
  parseMemberIndex, parseMemberSecret, projectAgentDiscovery, projectMemberIndex,
  type MemberIndexV1, type MemberSecretV1,
} from './vault-plaintext'
import { assertEnvelopeScope, openVaultEnvelope, sealVaultEnvelope, type EnvelopeDescriptorContract, type VaultEnvelopeContract } from './vault-envelope'

export type EmptyBinding = Record<string, never>
export type MemberSecretBinding = { operation: 1 | 2 | 3 | 4 | 5 }
export type VaultKeyBinding = { wrappingVaultKeyVersion: number }

export interface EntryCryptoCoordinates {
  organizationId: string
  vaultId: string
  entryId: string
  revision: string
  entryKeyRevision?: string
  entryKeyVersion?: number
  memberIndexRevision?: string
  agentDiscoveryRevision?: string
  vaultKeyVersion: number
  vdkVersion: number
  memberKeyGeneration: number
}

export interface CanonicalEntryEnvelopes {
  entryKey: VaultEnvelopeContract<VaultKeyBinding>
  memberIndex: VaultEnvelopeContract<EmptyBinding>
  memberSecret: VaultEnvelopeContract<MemberSecretBinding>
  agentDiscovery: VaultEnvelopeContract<EmptyBinding> | null
}

export interface ExpectedEntryEnvelopeCoordinates {
  organizationId: string
  vaultId: string
  entryId: string
  revision: string
}

function assertEntryEnvelope(
  descriptor: EnvelopeDescriptorContract<unknown>,
  expected: ExpectedEntryEnvelopeCoordinates,
  purpose: EnvelopeDescriptorContract<unknown>['purpose'],
): void {
  assertEnvelopeScope(descriptor, {
    organizationId: expected.organizationId,
    vaultId: expected.vaultId,
    entryId: expected.entryId,
    purpose,
  })
  if (purpose !== ENVELOPE_PURPOSE.entryDekByVk && descriptor.resourceRevision !== expected.revision) {
    throw new Error('Envelope descriptor does not match the outer Entry revision')
  }
}

function makeDescriptor<T>(c: EntryCryptoCoordinates, purpose: number, keyVersion: number, binding: T): EnvelopeDescriptorContract<T> {
  return {
    protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
    purpose: purpose as EnvelopeDescriptorContract<T>['purpose'],
    scope: { organizationId: c.organizationId, vaultId: c.vaultId, entryId: c.entryId },
    resourceRevision: c.revision, keyVersion, memberKeyGeneration: c.memberKeyGeneration, binding,
  }
}

async function derived(root: Uint8Array, descriptor: EnvelopeDescriptorContract<unknown>): Promise<Uint8Array> {
  return deriveVaultSubkey(root, {
    protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
    purpose: descriptor.purpose, organizationId: descriptor.scope.organizationId,
    vaultId: descriptor.scope.vaultId, entryId: descriptor.scope.entryId ?? undefined,
    keyVersion: descriptor.keyVersion, memberKeyGeneration: descriptor.memberKeyGeneration ?? undefined,
  })
}

export async function sealCanonicalEntry(
  coordinates: EntryCryptoCoordinates,
  secret: MemberSecretV1,
  vaultKey: Uint8Array,
  vaultDiscoveryKey: Uint8Array,
  operation: 1 | 2 | 3 | 4 | 5,
): Promise<CanonicalEntryEnvelopes> {
  const entryDek = await randomBytes(32)
  let entryWrapKey: Uint8Array | undefined
  let indexKey: Uint8Array | undefined
  let secretKey: Uint8Array | undefined
  let discoveryKey: Uint8Array | undefined
  let secretBytes: Uint8Array | undefined
  let indexBytes: Uint8Array | undefined
  let discoveryBytes: Uint8Array | null | undefined
  try {
    const index = projectMemberIndex(secret)
    const discovery = projectAgentDiscovery(secret)
    const keyCoordinates = { ...coordinates, revision: coordinates.entryKeyRevision ?? coordinates.revision }
    const indexCoordinates = { ...coordinates, revision: coordinates.memberIndexRevision ?? coordinates.revision }
    const discoveryCoordinates = { ...coordinates, revision: coordinates.agentDiscoveryRevision ?? coordinates.revision }
    const entryKeyVersion = coordinates.entryKeyVersion ?? 1
    const keyDescriptor = makeDescriptor(keyCoordinates, ENVELOPE_PURPOSE.entryDekByVk, entryKeyVersion, { wrappingVaultKeyVersion: coordinates.vaultKeyVersion })
    const indexDescriptor = makeDescriptor(indexCoordinates, ENVELOPE_PURPOSE.memberIndex, entryKeyVersion, {})
    const secretDescriptor = makeDescriptor(coordinates, ENVELOPE_PURPOSE.memberSecret, entryKeyVersion, { operation })
    const discoveryDescriptor = makeDescriptor(discoveryCoordinates, ENVELOPE_PURPOSE.agentDiscovery, coordinates.vdkVersion, {})
    entryWrapKey = await derived(vaultKey, keyDescriptor)
    indexKey = await derived(entryDek, indexDescriptor)
    secretKey = await derived(entryDek, secretDescriptor)
    discoveryKey = await derived(vaultDiscoveryKey, discoveryDescriptor)
    secretBytes = encodeMemberSecret(secret)
    indexBytes = encodeMemberIndex(index)
    discoveryBytes = discovery ? encodeAgentDiscovery(discovery) : null
    const [entryKey, memberIndex, memberSecret, agentDiscovery] = await Promise.all([
      sealVaultEnvelope(keyDescriptor, entryDek, entryWrapKey, { wrappingVkVersion: coordinates.vaultKeyVersion }),
      sealVaultEnvelope(indexDescriptor, indexBytes, indexKey),
      sealVaultEnvelope(secretDescriptor, secretBytes, secretKey, { operation }),
      discoveryBytes ? sealVaultEnvelope(discoveryDescriptor, discoveryBytes, discoveryKey) : Promise.resolve(null),
    ])
    return { entryKey, memberIndex, memberSecret, agentDiscovery }
  } finally {
    wipe(entryDek)
    if (entryWrapKey) wipe(entryWrapKey)
    if (indexKey) wipe(indexKey)
    if (secretKey) wipe(secretKey)
    if (discoveryKey) wipe(discoveryKey)
    secretBytes?.fill(0)
    indexBytes?.fill(0)
    discoveryBytes?.fill(0)
  }
}

export async function openMemberIndex(
  entryKey: VaultEnvelopeContract<VaultKeyBinding>,
  envelope: VaultEnvelopeContract<EmptyBinding>,
  vaultKey: Uint8Array,
  expected: ExpectedEntryEnvelopeCoordinates,
): Promise<MemberIndexV1> {
  assertEntryEnvelope(entryKey.descriptor, expected, ENVELOPE_PURPOSE.entryDekByVk)
  assertEntryEnvelope(envelope.descriptor, expected, ENVELOPE_PURPOSE.memberIndex)
  if (entryKey.descriptor.keyVersion !== envelope.descriptor.keyVersion
    || entryKey.descriptor.memberKeyGeneration !== envelope.descriptor.memberKeyGeneration) {
    throw new Error('Entry key and Member Index envelopes do not share the same key coordinates')
  }
  const wrapKey = await derived(vaultKey, entryKey.descriptor)
  try {
    const dek = await openVaultEnvelope(entryKey, wrapKey, {
      wrappingVkVersion: entryKey.descriptor.binding.wrappingVaultKeyVersion,
    })
    try {
      const indexKey = await derived(dek, envelope.descriptor)
      try {
        const bytes = await openVaultEnvelope(envelope, indexKey)
        try { return parseMemberIndex(bytes) } finally { bytes.fill(0) }
      } finally { wipe(indexKey) }
    } finally { wipe(dek) }
  } finally { wipe(wrapKey) }
}

export async function openMemberSecret(
  entryKey: VaultEnvelopeContract<VaultKeyBinding>,
  memberSecret: VaultEnvelopeContract<MemberSecretBinding>,
  vaultKey: Uint8Array,
  expected: ExpectedEntryEnvelopeCoordinates,
): Promise<MemberSecretV1> {
  assertEntryEnvelope(entryKey.descriptor, expected, ENVELOPE_PURPOSE.entryDekByVk)
  assertEntryEnvelope(memberSecret.descriptor, expected, ENVELOPE_PURPOSE.memberSecret)
  if (entryKey.descriptor.keyVersion !== memberSecret.descriptor.keyVersion
    || entryKey.descriptor.memberKeyGeneration !== memberSecret.descriptor.memberKeyGeneration) {
    throw new Error('Entry key and Member Secret envelopes do not share the same key coordinates')
  }
  const wrapKey = await derived(vaultKey, entryKey.descriptor)
  try {
    const dek = await openVaultEnvelope(entryKey, wrapKey, { wrappingVkVersion: entryKey.descriptor.binding.wrappingVaultKeyVersion })
    try {
      const secretKey = await derived(dek, memberSecret.descriptor)
      try {
        const bytes = await openVaultEnvelope(memberSecret, secretKey, { operation: memberSecret.descriptor.binding.operation })
        try { return parseMemberSecret(bytes) } finally { bytes.fill(0) }
      } finally { wipe(secretKey) }
    } finally { wipe(dek) }
  } finally { wipe(wrapKey) }
}
