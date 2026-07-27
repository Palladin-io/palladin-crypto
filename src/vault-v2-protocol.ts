import { concatBytes, decodeBase64Url, decodeUuid, encodeU16, encodeU32, encodeU64, encodeUtf8 } from './vault-v2-bytes'

export const VAULT_PROTOCOL_VERSION = 2 as const
export const VAULT_ALGORITHM_SUITE = 1 as const

export type VaultAadProfile =
  | 'member-vault-metadata'
  | 'member-index'
  | 'member-secret'
  | 'agent-discovery'
  | 'entry-key-wrapper'
  | 'vault-private-key'
  | 'vault-discovery-key'
  | 'encrypted-reason'
  | 'grant-payload'

export interface VaultEnvelopeHeader {
  protocolVersion: number
  algorithmSuite: number
  resourceKind: number
  projectionKind: number
  resourceRevision: string
  keyVersion: number
  memberKeyGeneration: number
  nonce: string
}

export type VaultAadContext = Record<string, unknown> & { header: VaultEnvelopeHeader }

type ValueType = 'u16' | 'u32' | 'u64' | 'uuid' | 'bytes' | 'instant'
interface Binding { tag: number; type: ValueType; source: string; constant?: number; optional?: boolean }

const common: Binding[] = [
  { tag: 1, type: 'u16', source: 'header.protocolVersion' },
  { tag: 2, type: 'u16', source: 'header.algorithmSuite' },
  { tag: 4, type: 'uuid', source: 'organizationId' },
  { tag: 5, type: 'uuid', source: 'vaultId' },
]

const profiles: Record<VaultAadProfile, Binding[]> = {
  'member-vault-metadata': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 1 }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 1 }, { tag: 8, type: 'u64', source: 'metadataRevision' }, { tag: 9, type: 'u32', source: 'header.keyVersion' }, { tag: 10, type: 'u32', source: 'header.memberKeyGeneration' }],
  'member-index': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 2 }, { tag: 6, type: 'uuid', source: 'entryId' }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 2 }, { tag: 8, type: 'u64', source: 'memberIndexRevision' }, { tag: 9, type: 'u32', source: 'header.keyVersion' }, { tag: 10, type: 'u32', source: 'header.memberKeyGeneration' }],
  'member-secret': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 2 }, { tag: 6, type: 'uuid', source: 'entryId' }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 3 }, { tag: 8, type: 'u64', source: 'revision' }, { tag: 9, type: 'u32', source: 'header.keyVersion' }, { tag: 10, type: 'u32', source: 'header.memberKeyGeneration' }, { tag: 20, type: 'u16', source: 'operation' }],
  'agent-discovery': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 2 }, { tag: 6, type: 'uuid', source: 'entryId' }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 4 }, { tag: 8, type: 'u64', source: 'agentDiscoveryRevision' }, { tag: 9, type: 'u32', source: 'vdkVersion' }, { tag: 10, type: 'u32', source: 'header.memberKeyGeneration' }],
  'entry-key-wrapper': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 2 }, { tag: 6, type: 'uuid', source: 'entryId' }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 8 }, { tag: 8, type: 'u64', source: 'wrapperRevision' }, { tag: 9, type: 'u32', source: 'keyVersion' }, { tag: 10, type: 'u32', source: 'memberKeyGeneration' }, { tag: 21, type: 'u32', source: 'wrappingKeyVersion' }],
  'vault-private-key': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 1 }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 7 }, { tag: 8, type: 'u64', source: 'privateKeyRevision' }, { tag: 9, type: 'u32', source: 'privateKeyVersion' }, { tag: 10, type: 'u32', source: 'memberKeyGeneration' }, { tag: 21, type: 'u32', source: 'wrappingKeyVersion' }, { tag: 22, type: 'u16', source: 'privateKeyKind' }],
  'vault-discovery-key': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 1 }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 12 }, { tag: 8, type: 'u64', source: 'discoveryKeyRevision' }, { tag: 9, type: 'u32', source: 'vdkVersion' }, { tag: 10, type: 'u32', source: 'memberKeyGeneration' }, { tag: 21, type: 'u32', source: 'wrappingKeyVersion' }],
  'encrypted-reason': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 3 }, { tag: 6, type: 'uuid', source: 'entryId' }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 5 }, { tag: 8, type: 'u64', source: 'requestRevision' }, { tag: 9, type: 'u32', source: 'reasonKeyVersion' }, { tag: 10, type: 'u32', source: 'header.memberKeyGeneration' }, { tag: 12, type: 'uuid', source: 'grantRequestId' }, { tag: 13, type: 'uuid', source: 'agentId' }, { tag: 14, type: 'u16', source: 'requestedMethods' }, { tag: 17, type: 'u32', source: 'agentMessageKeyVersion' }, { tag: 18, type: 'bytes', source: 'recipientAgentMessageKeyFingerprint' }],
  'grant-payload': [...common, { tag: 3, type: 'u16', source: 'header.resourceKind', constant: 4 }, { tag: 6, type: 'uuid', source: 'entryId' }, { tag: 7, type: 'u16', source: 'header.projectionKind', constant: 6 }, { tag: 8, type: 'u64', source: 'grantEnvelopeRevision' }, { tag: 9, type: 'u32', source: 'grantKeyVersion' }, { tag: 10, type: 'u32', source: 'header.memberKeyGeneration' }, { tag: 11, type: 'uuid', source: 'grantId' }, { tag: 13, type: 'uuid', source: 'agentId' }, { tag: 14, type: 'u16', source: 'approvedMethods' }, { tag: 15, type: 'instant', source: 'expiresAt', optional: true }, { tag: 16, type: 'u32', source: 'useLimit', optional: true }, { tag: 17, type: 'u32', source: 'recipientAgentKeyVersion' }, { tag: 18, type: 'bytes', source: 'recipientAgentKeyFingerprint' }, { tag: 19, type: 'u64', source: 'entryRevision' }],
}

function read(context: VaultAadContext, source: string): unknown {
  if (!source.startsWith('header.')) return context[source]
  return context.header[source.slice('header.'.length) as keyof VaultEnvelopeHeader]
}

function encode(type: ValueType, value: unknown): Uint8Array {
  if (type === 'u16') return encodeU16(value as number)
  if (type === 'u32') return encodeU32(value as number)
  if (type === 'u64') return encodeU64(value as string)
  if (type === 'uuid') return decodeUuid(value as string)
  if (type === 'bytes') {
    const bytes = decodeBase64Url(value as string)
    if (bytes.length > 64) throw new Error('AAD bytes exceed 64-byte limit')
    return bytes
  }
  const bytes = encodeUtf8(value as string)
  if (bytes.length > 27) throw new Error('AAD instant exceeds 27-byte limit')
  return bytes
}

export function encodeVaultAad(profile: VaultAadProfile, context: VaultAadContext): Uint8Array {
  const header = context.header
  if (header.protocolVersion !== VAULT_PROTOCOL_VERSION) throw new Error('unsupported Vault protocol version')
  if (header.algorithmSuite !== VAULT_ALGORITHM_SUITE) throw new Error('unsupported Vault algorithm suite')
  const bindings = profiles[profile]
  const fields = bindings.map((binding) => {
    const value = read(context, binding.source)
    if (value === undefined || value === null) {
      if (binding.optional) return null
      throw new Error(`${profile} missing ${binding.source}`)
    }
    if (binding.constant !== undefined && value !== binding.constant) throw new Error(`${profile} header/profile mismatch`)
    const bytes = encode(binding.type, value)
    const typeCode = { u16: 1, u32: 2, u64: 3, uuid: 4, bytes: 5, instant: 6 }[binding.type]
    return concatBytes(Uint8Array.of(binding.tag, typeCode), encodeU16(bytes.length), bytes)
  }).filter((field): field is Uint8Array => field !== null).sort((left, right) => left[0] - right[0])
  return concatBytes(encodeUtf8('PLDNV2AD'), Uint8Array.of(1, fields.length), encodeU16(0), ...fields)
}

export function assertEnvelopeBindings(profile: VaultAadProfile, context: VaultAadContext): void {
  encodeVaultAad(profile, context)
  const { header } = context
  const revisionSource: Partial<Record<VaultAadProfile, string>> = {
    'member-vault-metadata': 'metadataRevision', 'member-index': 'memberIndexRevision', 'member-secret': 'revision', 'agent-discovery': 'agentDiscoveryRevision', 'entry-key-wrapper': 'wrapperRevision', 'vault-private-key': 'privateKeyRevision', 'vault-discovery-key': 'discoveryKeyRevision', 'encrypted-reason': 'requestRevision', 'grant-payload': 'grantEnvelopeRevision',
  }
  if (context[revisionSource[profile]!] !== header.resourceRevision) throw new Error('resource revision/header mismatch')
  const keySource: Partial<Record<VaultAadProfile, string>> = { 'agent-discovery': 'vdkVersion', 'entry-key-wrapper': 'keyVersion', 'vault-private-key': 'privateKeyVersion', 'vault-discovery-key': 'vdkVersion', 'encrypted-reason': 'reasonKeyVersion', 'grant-payload': 'grantKeyVersion' }
  const key = keySource[profile]
  if (key && context[key] !== header.keyVersion) throw new Error('key version/header mismatch')
  if (profile === 'entry-key-wrapper' || profile === 'vault-private-key' || profile === 'vault-discovery-key') {
    if (context.memberKeyGeneration !== header.memberKeyGeneration) throw new Error('member generation/header mismatch')
  }
}

export function assertMinimumGeneration(actual: number, minimum: number): void {
  if (!Number.isInteger(actual) || !Number.isInteger(minimum) || actual < minimum) throw new Error('stale key generation')
}

