import { z } from 'zod'

export const AGENT_FIELD_ACCESS = [
  'never',
  'discovery',
  'onGrantValue',
  'onGrantDerived',
  'onGrantRuntime',
] as const
export type AgentFieldAccess = (typeof AGENT_FIELD_ACCESS)[number]
export type VaultEntryTypeName = 'key' | 'credential' | 'script' | 'creditCard'

const normalizedString = z.string().refine((value) => value === value.normalize('NFC'), 'String must be NFC')
const nullableString = normalizedString.nullable()
const color = z.string().regex(/^#[0-9A-F]{6}$/).nullable()
const glyphIcon = z.object({ kind: z.literal('glyph'), value: normalizedString.min(1).max(64) }).strict()
const assetIcon = z.object({ kind: z.literal('encryptedAsset'), assetId: z.string().uuid() }).strict()
const icon = z.union([glyphIcon, assetIcon]).nullable()

const jsonValue: z.ZodType<unknown> = z.lazy(() => z.union([
  z.string(), z.number().safe(), z.boolean(), z.null(), z.array(jsonValue), z.record(z.string(), jsonValue),
]))

const totpValue = z.object({
  secret: z.string().regex(/^[A-Z2-7]+$/),
  algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
  digits: z.union([z.literal(6), z.literal(8)]),
  period: z.number().int().min(15).max(120),
  issuer: nullableString,
  account: nullableString,
}).strict()

const customField = z.object({
  id: z.string().regex(/^custom:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i),
  label: normalizedString.min(1).max(128),
  type: normalizedString.min(1).max(64),
  value: jsonValue,
}).strict()

const keyContent = z.object({
  value: normalizedString,
  notes: nullableString,
  customFields: z.array(customField),
}).strict()
const credentialContent = z.object({
  username: normalizedString,
  password: normalizedString,
  url: nullableString,
  urlDomain: nullableString,
  totp: totpValue.nullable(),
  notes: nullableString,
  customFields: z.array(customField),
}).strict()
const scriptRef = z.object({
  env: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
  vaultId: z.string().uuid(),
  entryId: z.string().uuid(),
  fieldId: normalizedString.regex(/^(?:memberLabel|agentLabel|description|icon|color|entryType|key\.value|credential\.(?:username|password|url|urlDomain|totp)|creditCard\.(?:cardholderName|cardNumber|expiryMonth|expiryYear|billingAddress)|notes|script\.(?:source|interpreter|refs)|custom:[0-9a-f-]{36})$/),
}).strict()
const scriptContent = z.object({
  source: normalizedString,
  interpreter: z.enum(['bash', 'sh', 'node', 'python']),
  refs: z.array(scriptRef),
  notes: nullableString,
  customFields: z.array(customField),
}).strict()
const creditCardContent = z.object({
  cardholderName: normalizedString.min(1).max(256),
  cardNumber: z.string().regex(/^\d{12,19}$/),
  expiryMonth: z.string().regex(/^(0[1-9]|1[0-2])$/),
  expiryYear: z.string().regex(/^\d{4}$/),
  billingAddress: normalizedString.nullable(),
  notes: nullableString,
  customFields: z.array(customField),
}).strict()

const policy = z.record(z.string(), z.enum(AGENT_FIELD_ACCESS))
const secretCommon = {
  schema: z.literal('palladin.member-secret.v1'),
  memberLabel: normalizedString.min(1).max(256),
  agentLabel: nullableString,
  discoverable: z.boolean(),
  description: nullableString,
  icon,
  color,
  agentFieldAccess: policy,
}

const memberSecretSchema = z.discriminatedUnion('entryType', [
  z.object({ ...secretCommon, entryType: z.literal('key'), content: keyContent }).strict(),
  z.object({ ...secretCommon, entryType: z.literal('credential'), content: credentialContent }).strict(),
  z.object({ ...secretCommon, entryType: z.literal('script'), content: scriptContent }).strict(),
  z.object({ ...secretCommon, entryType: z.literal('creditCard'), content: creditCardContent }).strict(),
])

const memberVaultMetadataSchema = z.object({
  schema: z.literal('palladin.member-vault-metadata.v1'),
  name: normalizedString.min(1).max(256),
  description: nullableString,
  icon,
  color,
  grantMode: z.enum(['full', 'granular']),
}).strict()

const customIndexItem = z.object({
  id: z.string().regex(/^custom:[0-9a-f-]{36}$/),
  label: normalizedString,
  value: normalizedString,
}).strict()
const memberIndexSchema = z.object({
  schema: z.literal('palladin.member-index.v1'),
  entryType: z.enum(['key', 'credential', 'script', 'creditCard']),
  memberLabel: normalizedString,
  description: nullableString,
  icon,
  color,
  username: nullableString,
  urlDomain: nullableString,
  customIndex: z.array(customIndexItem).max(20),
}).strict()

const projectedField = z.object({ id: normalizedString, value: jsonValue }).strict()
const agentDiscoverySchema = z.object({
  schema: z.literal('palladin.agent-discovery.v1'),
  entryType: z.enum(['key', 'credential', 'script', 'creditCard']),
  agentLabel: normalizedString.min(1),
  capabilities: z.array(z.enum(['get', 'exec', 'inject'])),
  fields: z.array(projectedField),
}).strict()
const grantField = z.object({
  id: normalizedString,
  kind: z.enum(['text', 'multiline', 'concealed', 'url', 'totp', 'script', 'interpreter', 'refs']),
  mode: z.enum(['value', 'derived', 'runtime']),
  value: jsonValue,
}).strict()
const grantPayloadSchema = z.object({
  schema: z.literal('palladin.grant-payload.v1'),
  entryType: z.enum(['key', 'credential', 'script', 'creditCard']),
  fields: z.array(grantField),
}).strict()

export type MemberVaultMetadataV1 = z.infer<typeof memberVaultMetadataSchema>
export type MemberSecretV1 = z.infer<typeof memberSecretSchema>
export type MemberIndexV1 = z.infer<typeof memberIndexSchema>
export type AgentDiscoveryV1 = z.infer<typeof agentDiscoverySchema>
export type GrantPayloadV1 = z.infer<typeof grantPayloadSchema>

const BUILTIN_FIELDS: Record<VaultEntryTypeName, readonly string[]> = {
  key: ['memberLabel', 'agentLabel', 'description', 'icon', 'color', 'entryType', 'key.value', 'notes'],
  credential: ['memberLabel', 'agentLabel', 'description', 'icon', 'color', 'entryType', 'credential.username', 'credential.password', 'credential.url', 'credential.urlDomain', 'credential.totp', 'notes'],
  script: ['memberLabel', 'agentLabel', 'description', 'icon', 'color', 'entryType', 'script.source', 'script.interpreter', 'script.refs', 'notes'],
  creditCard: ['memberLabel', 'agentLabel', 'description', 'icon', 'color', 'entryType', 'creditCard.cardholderName', 'creditCard.cardNumber', 'creditCard.expiryMonth', 'creditCard.expiryYear', 'creditCard.billingAddress', 'notes'],
}

const ALLOWED_ACCESS: Record<string, readonly AgentFieldAccess[]> = {
  memberLabel: ['never'], icon: ['never'], color: ['never'],
  agentLabel: ['never', 'discovery'], entryType: ['never', 'discovery'],
  description: ['never', 'discovery'],
  'key.value': ['never', 'onGrantValue'], notes: ['never', 'onGrantValue', 'onGrantRuntime'],
  'credential.username': ['never', 'discovery', 'onGrantValue'],
  'credential.password': ['never', 'onGrantValue'],
  'credential.url': ['never', 'onGrantValue'],
  'credential.urlDomain': ['never', 'discovery', 'onGrantValue'],
  'credential.totp': ['never', 'onGrantDerived'],
  'script.source': ['never', 'onGrantRuntime'],
  'script.interpreter': ['never', 'discovery', 'onGrantRuntime'],
  'script.refs': ['never', 'onGrantRuntime'],
  'creditCard.cardholderName': ['never', 'onGrantRuntime'],
  'creditCard.cardNumber': ['never', 'onGrantRuntime'],
  'creditCard.expiryMonth': ['never', 'onGrantRuntime'],
  'creditCard.expiryYear': ['never', 'onGrantRuntime'],
  'creditCard.billingAddress': ['never', 'onGrantRuntime'],
}

function assertPolicy(secret: MemberSecretV1): void {
  const customFields = secret.content.customFields
  const expected = [...BUILTIN_FIELDS[secret.entryType], ...customFields.map((field) => field.id)].sort()
  const actual = Object.keys(secret.agentFieldAccess).sort()
  if (expected.length !== actual.length || expected.some((field, index) => field !== actual[index])) {
    throw new Error('AgentFieldAccess keys do not exactly match the Entry schema')
  }
  if (!secret.discoverable && (secret.agentLabel !== null
    || secret.agentFieldAccess.agentLabel !== 'never'
    || secret.agentFieldAccess.entryType !== 'never')) {
    throw new Error('A non-discoverable Entry cannot expose an Agent label or type')
  }
  if (secret.discoverable && (!secret.agentLabel
    || secret.agentFieldAccess.agentLabel !== 'discovery'
    || secret.agentFieldAccess.entryType !== 'discovery')) {
    throw new Error('A discoverable Entry requires a Discovery label and type')
  }
  for (const [field, access] of Object.entries(secret.agentFieldAccess)) {
    const custom = field.startsWith('custom:')
      ? customFields.find((candidate) => candidate.id === field)
      : undefined
    const allowed = custom
      ? custom.type === 'totp'
        ? ['never', 'onGrantDerived']
        : custom.type === 'text' || custom.type === 'multiline' || custom.type === 'concealed'
          ? secret.entryType === 'script' || secret.entryType === 'creditCard'
            ? ['never', 'onGrantRuntime']
            : ['never', 'discovery', 'onGrantValue']
          : ['never']
      : ALLOWED_ACCESS[field]
    if (!allowed?.includes(access)) throw new Error(`Unsafe AgentFieldAccess for ${field}`)
  }
}

function rejectDuplicateKeys(json: string): void {
  let index = 0
  const whitespace = () => { while (/\s/.test(json[index] ?? '')) index++ }
  const string = (): string => {
    const start = index++
    while (index < json.length) {
      if (json[index] === '\\') index += 2
      else if (json[index++] === '"') return JSON.parse(json.slice(start, index)) as string
    }
    throw new SyntaxError('Unterminated JSON string')
  }
  const value = (): void => {
    whitespace()
    if (json[index] === '{') {
      index++; whitespace(); const keys = new Set<string>()
      if (json[index] === '}') { index++; return }
      while (true) {
        whitespace(); if (json[index] !== '"') throw new SyntaxError('Object key expected')
        const key = string(); if (keys.has(key)) throw new SyntaxError(`Duplicate JSON property: ${key}`); keys.add(key)
        whitespace(); if (json[index++] !== ':') throw new SyntaxError('Colon expected'); value(); whitespace()
        if (json[index] === '}') { index++; return }
        if (json[index++] !== ',') throw new SyntaxError('Comma expected')
      }
    }
    if (json[index] === '[') {
      index++; whitespace(); if (json[index] === ']') { index++; return }
      while (true) { value(); whitespace(); if (json[index] === ']') { index++; return }; if (json[index++] !== ',') throw new SyntaxError('Comma expected') }
    }
    if (json[index] === '"') { string(); return }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(json.slice(index))
    if (!match) throw new SyntaxError('Invalid JSON value')
    index += match[0].length
  }
  value(); whitespace(); if (index !== json.length) throw new SyntaxError('Trailing JSON data')
}

function parse<T>(bytes: Uint8Array, schema: z.ZodType<T>): T {
  const json = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  rejectDuplicateKeys(json)
  return schema.parse(JSON.parse(json))
}

function canonical(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('Canonical Vault JSON permits bounded integers only')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`
  }
  throw new TypeError('Unsupported canonical JSON value')
}

function encodeCanonicalVaultJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(canonical(value))
}

export const encodeMemberVaultMetadata = (value: MemberVaultMetadataV1): Uint8Array => encodeCanonicalVaultJson(memberVaultMetadataSchema.parse(value))
export const encodeMemberIndex = (value: MemberIndexV1): Uint8Array => encodeCanonicalVaultJson(memberIndexSchema.parse(value))
export function encodeMemberSecret(value: MemberSecretV1): Uint8Array { const parsed = memberSecretSchema.parse(value); assertPolicy(parsed); return encodeCanonicalVaultJson(parsed) }
export const encodeAgentDiscovery = (value: AgentDiscoveryV1): Uint8Array => encodeCanonicalVaultJson(agentDiscoverySchema.parse(value))
export const encodeGrantPayload = (value: GrantPayloadV1): Uint8Array => encodeCanonicalVaultJson(grantPayloadSchema.parse(value))

export const parseMemberVaultMetadata = (bytes: Uint8Array): MemberVaultMetadataV1 => parse(bytes, memberVaultMetadataSchema)
export const parseMemberIndex = (bytes: Uint8Array): MemberIndexV1 => parse(bytes, memberIndexSchema)
export function parseMemberSecret(bytes: Uint8Array): MemberSecretV1 { const value = parse(bytes, memberSecretSchema); assertPolicy(value); return value }
export const parseAgentDiscovery = (bytes: Uint8Array): AgentDiscoveryV1 => parse(bytes, agentDiscoverySchema)
export const parseGrantPayload = (bytes: Uint8Array): GrantPayloadV1 => parse(bytes, grantPayloadSchema)

function fieldValue(secret: MemberSecretV1, id: string): unknown {
  if (id === 'memberLabel') return secret.memberLabel
  if (id === 'agentLabel') return secret.agentLabel
  if (id === 'description') return secret.description
  if (id === 'icon') return secret.icon
  if (id === 'color') return secret.color
  if (id === 'entryType') return secret.entryType
  if (id === 'notes') return secret.content.notes
  if (id.startsWith('custom:')) return secret.content.customFields.find((field) => field.id === id)?.value
  if (secret.entryType === 'key' && id === 'key.value') return secret.content.value
  if (secret.entryType === 'credential') {
    const map = { 'credential.username': secret.content.username, 'credential.password': secret.content.password, 'credential.url': secret.content.url, 'credential.urlDomain': secret.content.urlDomain, 'credential.totp': secret.content.totp }
    return map[id as keyof typeof map]
  }
  if (secret.entryType === 'script') {
    const map = { 'script.source': secret.content.source, 'script.interpreter': secret.content.interpreter, 'script.refs': secret.content.refs }
    return map[id as keyof typeof map]
  }
  if (secret.entryType === 'creditCard') {
    const map = {
      'creditCard.cardholderName': secret.content.cardholderName,
      'creditCard.cardNumber': secret.content.cardNumber,
      'creditCard.expiryMonth': secret.content.expiryMonth,
      'creditCard.expiryYear': secret.content.expiryYear,
      'creditCard.billingAddress': secret.content.billingAddress,
    }
    return map[id as keyof typeof map]
  }
  return undefined
}

export function projectMemberIndex(secret: MemberSecretV1): MemberIndexV1 {
  assertPolicy(secret)
  const customIndex = secret.content.customFields
    .filter((field) => (field.type === 'text' || field.type === 'multiline') && typeof field.value === 'string')
    .map((field) => ({ id: field.id, label: field.label, value: field.value as string }))
  if (customIndex.length > 20) throw new Error('MemberIndex custom field limit exceeded')
  return memberIndexSchema.parse({
    schema: 'palladin.member-index.v1', entryType: secret.entryType,
    memberLabel: secret.memberLabel, description: secret.description, icon: secret.icon, color: secret.color,
    username: secret.entryType === 'credential' ? secret.content.username : null,
    urlDomain: secret.entryType === 'credential' ? secret.content.urlDomain : null,
    customIndex,
  })
}

export function projectAgentDiscovery(secret: MemberSecretV1): AgentDiscoveryV1 | null {
  assertPolicy(secret)
  if (!secret.discoverable) return null
  const fields = Object.entries(secret.agentFieldAccess)
    .filter(([id, access]) => access === 'discovery' && id !== 'agentLabel' && id !== 'entryType')
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([id]) => ({ id, value: fieldValue(secret, id) }))
  return agentDiscoverySchema.parse({
    schema: 'palladin.agent-discovery.v1', entryType: secret.entryType, agentLabel: secret.agentLabel,
    capabilities: secret.entryType === 'script'
      ? ['exec']
      : secret.entryType === 'creditCard'
        ? ['inject']
        : ['get', 'exec'],
    fields,
  })
}

export function projectGrantPayload(secret: MemberSecretV1, fieldIds: readonly string[]): GrantPayloadV1 {
  assertPolicy(secret)
  const sorted = [...fieldIds].sort()
  if (new Set(sorted).size !== sorted.length) throw new Error('Grant field IDs must be distinct')
  const fields = sorted.map((id) => {
    const access = secret.agentFieldAccess[id]
    const mode = access === 'onGrantValue' ? 'value' : access === 'onGrantDerived' ? 'derived' : access === 'onGrantRuntime' ? 'runtime' : undefined
    const value = fieldValue(secret, id)
    if (!mode || value === undefined) throw new Error(`Field ${id} is not grantable`)
    const custom = id.startsWith('custom:') ? secret.content.customFields.find((field) => field.id === id) : undefined
    const kind = custom
      ? custom.type
      : id === 'key.value' || id === 'credential.password' || id === 'creditCard.cardNumber'
        ? 'concealed'
        : id === 'credential.url'
          ? 'url'
          : id === 'credential.totp'
            ? 'totp'
            : id === 'notes'
              ? 'multiline'
              : id === 'script.source'
                ? 'script'
                : id === 'script.interpreter'
                  ? 'interpreter'
                  : id === 'script.refs'
                    ? 'refs'
                    : 'text'
    if (!['text', 'multiline', 'concealed', 'url', 'totp', 'script', 'interpreter', 'refs'].includes(kind)) {
      throw new Error(`Unknown field kind for ${id}`)
    }
    return { id, kind: kind as GrantPayloadV1['fields'][number]['kind'], mode, value }
  })
  return grantPayloadSchema.parse({ schema: 'palladin.grant-payload.v1', entryType: secret.entryType, fields })
}

export function listGrantableFieldIds(secret: MemberSecretV1): string[] {
  assertPolicy(secret)
  return Object.entries(secret.agentFieldAccess)
    .filter(([, access]) => access === 'onGrantValue' || access === 'onGrantDerived' || access === 'onGrantRuntime')
    .map(([id]) => id)
    .sort()
}

export function memberIndexSearchValues(index: MemberIndexV1): string[] {
  return [index.memberLabel, index.description, index.username, index.urlDomain,
    ...index.customIndex.flatMap((field) => [field.label, field.value])]
    .filter((value): value is string => Boolean(value))
}

export function presentationIconReference(icon: MemberIndexV1['icon'] | MemberVaultMetadataV1['icon']): string | undefined {
  return icon?.kind === 'glyph' ? icon.value
    : icon?.kind === 'encryptedAsset' ? `asset:${icon.assetId}` : undefined
}
