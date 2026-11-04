/**
 * Build-time copy of palladin-protocol `contracts/key-wrapper/v1/registry.json`.
 * There is no runtime registration or negotiation: a suite is usable only when
 * it is listed here and implemented in `./suites`.
 */

export const KEY_WRAPPER_PROTOCOL_VERSION = 2

export const KEY_WRAPPER_SUITE = {
  active: 'palladin-xwing-v1',
  legacy: 'palladin-x25519-sealed-box-v1',
} as const

export type KeyWrapperSuiteId = (typeof KEY_WRAPPER_SUITE)[keyof typeof KEY_WRAPPER_SUITE]

export type KeyWrapperSuiteStatus = 'active' | 'read-only' | 'retired'

const ALL_PURPOSES = [1, 2, 3, 4, 5, 6, 7, 8, 9] as const

export const KEY_WRAPPER_SUITES: Readonly<Record<KeyWrapperSuiteId, {
  readonly status: KeyWrapperSuiteStatus
  readonly purposes: readonly number[]
}>> = Object.freeze({
  'palladin-xwing-v1': { status: 'active', purposes: ALL_PURPOSES },
  'palladin-x25519-sealed-box-v1': { status: 'read-only', purposes: ALL_PURPOSES },
})

export const SUITE_LIFECYCLE: Readonly<Record<KeyWrapperSuiteStatus, { readonly seal: boolean, readonly open: boolean }>> = Object.freeze({
  active: { seal: true, open: true },
  'read-only': { seal: false, open: true },
  retired: { seal: false, open: false },
})

export const SCOPE_BIT = {
  organization: 1,
  vault: 2,
  entry: 4,
  grantOrRequest: 8,
  agent: 16,
  member: 32,
} as const

/** Scope identifiers in their encoded order. */
export const SCOPE_FIELDS = [
  ['organizationId', SCOPE_BIT.organization],
  ['vaultId', SCOPE_BIT.vault],
  ['entryId', SCOPE_BIT.entry],
  ['grantOrRequestId', SCOPE_BIT.grantOrRequest],
  ['agentId', SCOPE_BIT.agent],
  ['memberId', SCOPE_BIT.member],
] as const

export type KeyWrapperScopeField = (typeof SCOPE_FIELDS)[number][0]

export const RECIPIENT_KEY_KIND = {
  agentEncryption: 1,
  vaultAgentMessage: 4,
  memberEncryption: 5,
  organizationApproverMessage: 6,
} as const

export type RecipientKeyKind = (typeof RECIPIENT_KEY_KIND)[keyof typeof RECIPIENT_KEY_KIND]

export const KEY_WRAPPER_PURPOSE = {
  memberVaultKey: 1,
  agentVaultDiscoveryKey: 2,
  reasonDek: 3,
  grantDek: 4,
  agentVaultKey: 5,
  scriptExecutionDek: 6,
  submissionDek: 7,
  approverMessagePrivateKey: 8,
  approverSigningPrivateKey: 9,
} as const

export type KeyWrapperPurpose = (typeof KEY_WRAPPER_PURPOSE)[keyof typeof KEY_WRAPPER_PURPOSE]

type Presence = 'required' | 'optional' | 'forbidden'

export interface PurposeRule {
  readonly scopeBitmap: number
  readonly recipientKeyKinds: readonly RecipientKeyKind[]
  readonly memberKeyGeneration: Presence
  readonly parentDescriptorHash: Exclude<Presence, 'optional'>
}

const { agentEncryption, vaultAgentMessage, memberEncryption, organizationApproverMessage } = RECIPIENT_KEY_KIND

export const PURPOSE_RULES: Readonly<Record<KeyWrapperPurpose, PurposeRule>> = Object.freeze({
  1: { scopeBitmap: 35, recipientKeyKinds: [memberEncryption], memberKeyGeneration: 'required', parentDescriptorHash: 'forbidden' },
  2: { scopeBitmap: 19, recipientKeyKinds: [agentEncryption], memberKeyGeneration: 'optional', parentDescriptorHash: 'forbidden' },
  3: { scopeBitmap: 31, recipientKeyKinds: [vaultAgentMessage], memberKeyGeneration: 'optional', parentDescriptorHash: 'required' },
  4: { scopeBitmap: 31, recipientKeyKinds: [agentEncryption], memberKeyGeneration: 'optional', parentDescriptorHash: 'required' },
  5: { scopeBitmap: 27, recipientKeyKinds: [agentEncryption], memberKeyGeneration: 'forbidden', parentDescriptorHash: 'forbidden' },
  6: { scopeBitmap: 31, recipientKeyKinds: [agentEncryption], memberKeyGeneration: 'forbidden', parentDescriptorHash: 'required' },
  7: { scopeBitmap: 25, recipientKeyKinds: [agentEncryption, organizationApproverMessage], memberKeyGeneration: 'forbidden', parentDescriptorHash: 'required' },
  8: { scopeBitmap: 33, recipientKeyKinds: [memberEncryption], memberKeyGeneration: 'forbidden', parentDescriptorHash: 'forbidden' },
  9: { scopeBitmap: 33, recipientKeyKinds: [memberEncryption], memberKeyGeneration: 'forbidden', parentDescriptorHash: 'forbidden' },
})

export const KEY_WRAPPER_ERROR_CODES = [
  'unsupported-suite',
  'suite-not-allowed-for-purpose',
  'suite-not-writable',
  'unsupported-purpose',
  'malformed-descriptor',
  'malformed-package',
  'recipient-mismatch',
  'open-failed',
  // recipient-key-publication.json: the recipient's published key suite is not active.
  'key-migration-pending',
] as const

export type KeyWrapperErrorCode = (typeof KEY_WRAPPER_ERROR_CODES)[number]

/** Carries only a registry error code; never key material or descriptor values. */
export class KeyWrapperError extends Error {
  readonly code: KeyWrapperErrorCode

  constructor(code: KeyWrapperErrorCode) {
    super(code)
    this.name = 'KeyWrapperError'
    this.code = code
  }
}
