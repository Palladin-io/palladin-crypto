/**
 * Stable, algorithm-independent coordinates for an encrypted resource.
 *
 * This object is deliberately separate from the suite payload. It is persisted
 * and transported as structural data; the selected suite owns the opaque bytes
 * inside {@link EncodedSuitePayload}. The canonical binary encoder is part of
 * the cross-client wire contract and must be added only once that contract is
 * frozen across backend, web, mobile, and the native runtime.
 */
export interface EnvelopeDescriptor {
  protocolVersion: number
  cryptoSuiteId: CryptoSuiteId
  purpose: EnvelopePurpose
  organizationId: string
  vaultId: string
  entryId?: string
  grantOrRequestId?: string
  agentId?: string
  memberId?: string
  resourceRevision: number | bigint
  keyVersion: number
  memberKeyGeneration?: number
}

export const ENVELOPE_PURPOSE = {
  memberVaultMetadata: 1,
  vaultDiscoveryKeyByVk: 2,
  agentMessagePrivateByVk: 3,
  manifestPrivateByVk: 4,
  memberIndex: 5,
  memberSecret: 6,
  agentDiscovery: 7,
  entryDekByVk: 8,
  reason: 9,
  grant: 10,
} as const

export type EnvelopePurpose =
  (typeof ENVELOPE_PURPOSE)[keyof typeof ENVELOPE_PURPOSE]

/** HKDF coordinates. Resource revision and envelope binding are excluded. */
export type KdfContextDescriptor = Omit<EnvelopeDescriptor, 'resourceRevision'>

export interface MemberSecretAadExtension {
  operation: number
}

export interface WrappingAadExtension {
  wrappingVkVersion: number
}

export interface ReasonAadExtension {
  wrapperSuiteId: string
  recipientKeyVersion: number
  recipientKeyFingerprint: Uint8Array
  methods: number
}

export interface GrantAadExtension {
  entryRevision: number | bigint
  wrapperSuiteId: string
  recipientKeyVersion: number
  recipientKeyFingerprint: Uint8Array
  methods: number
  fieldSetCommitment: Uint8Array
  expiresAt?: { seconds: number | bigint; nanoseconds: number }
  remainingUses?: number
}

export type EnvelopeAadExtension =
  | MemberSecretAadExtension
  | WrappingAadExtension
  | ReasonAadExtension
  | GrantAadExtension
  | undefined

/** A registry-owned identifier. Never accept it as an algorithm name. */
export type CryptoSuiteId = string & { readonly __cryptoSuiteId: unique symbol }

/**
 * Canonical descriptor bytes authenticated by AEAD. Callers cannot construct
 * this brand with a type assertion outside the crypto layer; the future shared
 * encoder will be the only public producer.
 */
export type CanonicalEnvelopeAad = Uint8Array & {
  readonly __canonicalEnvelopeAad: unique symbol
}

/** Opaque, bounded bytes whose internal layout belongs to one crypto suite. */
export type EncodedSuitePayload = Uint8Array & {
  readonly __encodedSuitePayload: unique symbol
}

