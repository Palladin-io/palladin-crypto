import { encodeCanonicalEnvelopeAad } from './canonical-aad'
import {
  MAX_ENCODED_SUITE_PAYLOAD_BYTES,
  requireCryptoSuite,
  VAULT_XCHACHA20_POLY1305_V1,
} from './crypto-suite'
import { fromBase64Url, toBase64Url } from './encoding'
import type {
  CryptoSuiteId,
  EncodedSuitePayload,
  EnvelopeAadExtension,
  EnvelopeDescriptor,
  EnvelopePurpose,
} from './envelope'

export interface EnvelopeScopeContract {
  organizationId: string
  vaultId: string
  entryId?: string | null
  grantOrRequestId?: string | null
  agentId?: string | null
  memberId?: string | null
}

export interface EnvelopeDescriptorContract<TBinding> {
  protocolVersion: number
  cryptoSuiteId: string
  purpose: EnvelopePurpose
  scope: EnvelopeScopeContract
  /** UInt64 is a decimal string on the JSON contract. */
  resourceRevision: string
  keyVersion: number
  memberKeyGeneration?: number | null
  binding: TBinding
}

export interface VaultEnvelopeContract<TBinding> {
  descriptor: EnvelopeDescriptorContract<TBinding>
  encodedSuitePayload: string
}

export interface ExpectedEnvelopeScope {
  organizationId: string
  vaultId: string
  entryId?: string
  grantOrRequestId?: string
  agentId?: string
  memberId?: string
  purpose: EnvelopePurpose
}

function parseRevision(value: string): bigint {
  if (!/^[1-9][0-9]*$/.test(value)) throw new TypeError('Resource revision must be a positive canonical decimal')
  const revision = BigInt(value)
  if (revision > 0xffffffffffffffffn) throw new RangeError('Resource revision exceeds UInt64')
  return revision
}

export function toEnvelopeDescriptor(
  contract: EnvelopeDescriptorContract<unknown>,
): EnvelopeDescriptor {
  if (contract.protocolVersion !== 2 || contract.cryptoSuiteId !== VAULT_XCHACHA20_POLY1305_V1) {
    throw new Error('Unsupported or downgraded Vault envelope protocol')
  }
  return {
    protocolVersion: contract.protocolVersion,
    cryptoSuiteId: contract.cryptoSuiteId as CryptoSuiteId,
    purpose: contract.purpose,
    organizationId: contract.scope.organizationId,
    vaultId: contract.scope.vaultId,
    entryId: contract.scope.entryId ?? undefined,
    grantOrRequestId: contract.scope.grantOrRequestId ?? undefined,
    agentId: contract.scope.agentId ?? undefined,
    memberId: contract.scope.memberId ?? undefined,
    resourceRevision: parseRevision(contract.resourceRevision),
    keyVersion: contract.keyVersion,
    memberKeyGeneration: contract.memberKeyGeneration ?? undefined,
  }
}

export function assertEnvelopeScope(
  descriptor: EnvelopeDescriptorContract<unknown>,
  expected: ExpectedEnvelopeScope,
): void {
  const scope = descriptor.scope
  if (descriptor.purpose !== expected.purpose
    || scope.organizationId !== expected.organizationId
    || scope.vaultId !== expected.vaultId
    || (scope.entryId ?? undefined) !== expected.entryId
    || (scope.grantOrRequestId ?? undefined) !== expected.grantOrRequestId
    || (scope.agentId ?? undefined) !== expected.agentId
    || (scope.memberId ?? undefined) !== expected.memberId) {
    throw new Error('Envelope descriptor does not match the outer resource scope')
  }
}

export async function openVaultEnvelope<TBinding>(
  envelope: VaultEnvelopeContract<TBinding>,
  key: Uint8Array,
  extension?: EnvelopeAadExtension,
): Promise<Uint8Array> {
  const descriptor = toEnvelopeDescriptor(envelope.descriptor)
  const aad = encodeCanonicalEnvelopeAad(descriptor, extension)
  const payload = fromBase64Url(
    envelope.encodedSuitePayload,
    MAX_ENCODED_SUITE_PAYLOAD_BYTES,
  ) as EncodedSuitePayload
  return requireCryptoSuite(envelope.descriptor.cryptoSuiteId).open({ payload, key, aad })
}

export async function sealVaultEnvelope<TBinding>(
  descriptor: EnvelopeDescriptorContract<TBinding>,
  plaintext: Uint8Array,
  key: Uint8Array,
  extension?: EnvelopeAadExtension,
): Promise<VaultEnvelopeContract<TBinding>> {
  const model = toEnvelopeDescriptor(descriptor)
  const aad = encodeCanonicalEnvelopeAad(model, extension)
  const payload = await requireCryptoSuite(descriptor.cryptoSuiteId).seal({ plaintext, key, aad })
  return { descriptor, encodedSuitePayload: toBase64Url(payload) }
}

