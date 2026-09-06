import { computeFieldSetCommitment, encodeDeliveryBoundGrantAad } from './canonical-aad'
import { requireCryptoSuite, VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { ENVELOPE_PURPOSE } from './envelope'
import { fromBase64, toBase64Url } from './encoding'
import { randomBytes, wipe } from './sodium'
import { deriveVaultSubkey } from './hkdf'
import { listCanonicalGrantableFieldIds, projectCanonicalGrantPayload } from './canonical-grant-payload'
import {
  encodeGrantPayload,
  type MemberSecretV1,
} from './current-vault-plaintext'
import { toEnvelopeDescriptor, type EnvelopeDescriptorContract } from './vault-envelope'
import { computeVaultKeyFingerprint, sealKeyToX25519Recipient, VAULT_KEY_KIND, WRAPPER_PURPOSE, X25519_SEALED_BOX_V1 } from './x25519-wrapper'

export const GRANT_DELIVERY_POLICY = { standard: 0, execOnly: 1, injectOnly: 2 } as const
export type GrantDeliveryPolicy = (typeof GRANT_DELIVERY_POLICY)[keyof typeof GRANT_DELIVERY_POLICY]
export const GRANT_DELIVERY_POLICY_NAME = {
  standard: 'standard',
  execOnly: 'execOnly',
  injectOnly: 'injectOnly',
} as const
export type GrantDeliveryPolicyName =
  (typeof GRANT_DELIVERY_POLICY_NAME)[keyof typeof GRANT_DELIVERY_POLICY_NAME]

export interface BuildGrantEnvelopeInput {
  organizationId: string; vaultId: string; entryId: string; grantId: string; agentId: string
  entryRevision: string; memberKeyGeneration: number; agentPublicKey: string; recipientKeyVersion: number
  grantEnvelopeRevision: string; grantKeyVersion: number; approvedFieldIds: string[]
  approvedMethods: number; deliveryPolicy?: 0 | 1 | 2
  expiresAt?: string; remainingUses?: number; secret: MemberSecretV1
}

export interface GrantableField {
  id: string
  label: string
  access: 'onGrantValue' | 'onGrantDerived' | 'onGrantRuntime'
}

export function listGrantableFields(secret: MemberSecretV1): GrantableField[] {
  const labels = new Map(secret.content.customFields.map((field) => [field.id, field.label]))
  const registered = new Set(listCanonicalGrantableFieldIds(secret))
  return Object.entries(secret.agentFieldAccess)
    .filter((entry): entry is [string, GrantableField['access']] =>
      registered.has(entry[0])
      && (entry[1] === 'onGrantValue' || entry[1] === 'onGrantDerived' || entry[1] === 'onGrantRuntime'))
    .map(([id, access]) => ({ id, access, label: labels.get(id) ?? id }))
    .sort((left, right) => left.label.localeCompare(right.label))
}

function instant(value?: string): { seconds: bigint; nanoseconds: number } | undefined {
  if (!value) return undefined
  const millis = Date.parse(value)
  if (!Number.isFinite(millis)) throw new TypeError('Invalid grant expiry')
  const match = /(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})$/.exec(value)
  if (!match) throw new TypeError('Invalid grant expiry')
  return { seconds: BigInt(Math.floor(millis / 1000)), nanoseconds: Number((match[1] ?? '').padEnd(9, '0')) }
}

export async function buildCanonicalGrantEnvelope(input: BuildGrantEnvelopeInput) {
  if (!Number.isInteger(input.approvedMethods) || input.approvedMethods < 1 || input.approvedMethods > 7) {
    throw new RangeError('Grant methods must use the registered Get/Exec/Inject mask')
  }
  if (BigInt(input.grantEnvelopeRevision) < 1n || input.grantKeyVersion < 1) {
    throw new RangeError('Grant envelope revisions must be positive')
  }
  const approvedPolicyFieldIds = [...new Set(input.approvedFieldIds)].sort()
  if (approvedPolicyFieldIds.length === 0) throw new Error('Grant payload requires at least one approved field')
  const approvedMethods = input.approvedMethods
  for (const id of approvedPolicyFieldIds) {
    const access = input.secret.agentFieldAccess[id]
    if (access !== 'onGrantValue' && access !== 'onGrantDerived' && access !== 'onGrantRuntime') {
      throw new Error(`Field ${id} is not grantable by its agent-access policy`)
    }
  }
  const payload = await projectCanonicalGrantPayload(input.secret, approvedPolicyFieldIds)
  const fieldIds = payload.fields.map(({ id }) => id)
  const publicKey = fromBase64(input.agentPublicKey)
  const fingerprint = await computeVaultKeyFingerprint(publicKey, VAULT_KEY_KIND.agentX25519)
  const commitment = await computeFieldSetCommitment(fieldIds)
  const expiresAt = instant(input.expiresAt)
  const deliveryPolicy = input.deliveryPolicy ?? GRANT_DELIVERY_POLICY.standard
  const binding = {
    entryRevision: input.entryRevision, wrapperSuiteId: X25519_SEALED_BOX_V1,
    recipientKeyVersion: input.recipientKeyVersion, recipientKeyFingerprint: toBase64Url(fingerprint),
    approvedMethods, deliveryPolicy, fieldSetCommitment: toBase64Url(commitment),
    expiresAt: input.expiresAt ?? null, remainingUses: input.remainingUses ?? null,
  }
  const descriptor: EnvelopeDescriptorContract<typeof binding> = {
    protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1, purpose: ENVELOPE_PURPOSE.grant,
    scope: { organizationId: input.organizationId, vaultId: input.vaultId, entryId: input.entryId, grantOrRequestId: input.grantId, agentId: input.agentId },
    resourceRevision: input.grantEnvelopeRevision, keyVersion: input.grantKeyVersion,
    memberKeyGeneration: input.memberKeyGeneration, binding,
  }
  const extension = {
    entryRevision: BigInt(input.entryRevision), wrapperSuiteId: X25519_SEALED_BOX_V1,
    recipientKeyVersion: input.recipientKeyVersion, recipientKeyFingerprint: fingerprint,
    methods: approvedMethods, deliveryPolicy, fieldSetCommitment: commitment, expiresAt,
    remainingUses: input.remainingUses,
  }
  const dek = await randomBytes(32)
  const plaintext = encodeGrantPayload(payload)
  let payloadKey: Uint8Array | undefined
  try {
    const { resourceRevision, ...kdfContext } = toEnvelopeDescriptor(descriptor)
    void resourceRevision
    payloadKey = await deriveVaultSubkey(dek, kdfContext)
    const descriptorBytes = encodeDeliveryBoundGrantAad(toEnvelopeDescriptor(descriptor), extension)
    const encrypted = await requireCryptoSuite(descriptor.cryptoSuiteId).seal({ plaintext, key: payloadKey, aad: descriptorBytes })
    const envelope = { descriptor, encodedSuitePayload: toBase64Url(encrypted) }
    const descriptorCopy = new Uint8Array(descriptorBytes)
    const parentHash = new Uint8Array(await crypto.subtle.digest('SHA-256', descriptorCopy.buffer))
    try {
      const wrapperContext = {
        protocolVersion: 2, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: WRAPPER_PURPOSE.grantDek,
        organizationId: input.organizationId, vaultId: input.vaultId, entryId: input.entryId,
        grantOrRequestId: input.grantId, agentId: input.agentId,
        resourceRevision: BigInt(input.grantEnvelopeRevision),
        wrappedKeyVersion: input.grantKeyVersion, memberKeyGeneration: input.memberKeyGeneration,
        recipientKeyKind: VAULT_KEY_KIND.agentX25519, recipientKeyVersion: input.recipientKeyVersion,
        recipientFingerprint: fingerprint, parentDescriptorHash: parentHash,
      } as const
      const sealed = await sealKeyToX25519Recipient(dek, publicKey, wrapperContext)
      return {
        ...envelope,
        wrappedGrantDek: { descriptor: {
          protocolVersion: 2, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: WRAPPER_PURPOSE.grantDek,
          scope: descriptor.scope, resourceRevision: input.grantEnvelopeRevision,
          wrappedKeyVersion: input.grantKeyVersion,
          memberKeyGeneration: input.memberKeyGeneration, recipientKeyKind: VAULT_KEY_KIND.agentX25519,
          recipientKeyVersion: input.recipientKeyVersion, recipientFingerprint: toBase64Url(fingerprint),
          parentDescriptorHash: toBase64Url(parentHash),
        }, encodedSealedKeyPackage: toBase64Url(sealed) }, fieldIds,
      }
    } finally { wipe(parentHash); wipe(descriptorCopy) }
  } finally {
    if (payloadKey) wipe(payloadKey)
    wipe(dek); plaintext.fill(0); wipe(publicKey); wipe(fingerprint); wipe(commitment)
  }
}
