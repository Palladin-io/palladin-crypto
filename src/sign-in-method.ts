import { z } from 'zod'

/**
 * Federated sign-in method stored as one custom field of a Credential
 * MemberSecret. The member value may name the provider account; the Agent
 * Discovery projection never does — it exposes only the provider and an
 * optional reference to the provider Credential an Agent may request a grant for.
 */
export const SIGN_IN_FIELD_TYPE = 'palladin.signin.v1'
export const SIGN_IN_DISCOVERY_FIELD_ID = 'signIn'
export const SIGN_IN_PROVIDERS = ['google', 'apple', 'microsoft', 'github', 'facebook'] as const

const uuid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
const account = z.string().min(1).max(256)
  .refine((value) => value === value.normalize('NFC').trim(), 'Account must be NFC and trimmed')

export const signInMethodValueSchema = z.object({
  provider: z.enum(SIGN_IN_PROVIDERS),
  account: account.nullable(),
  entry: z.object({ vaultId: uuid, entryId: uuid }).strict().nullable(),
}).strict()

export type SignInMethodValue = z.infer<typeof signInMethodValueSchema>

export interface SignInDiscoveryValue {
  schema: typeof SIGN_IN_FIELD_TYPE
  provider: SignInMethodValue['provider']
  entry: { vaultId: string; entryId: string } | null
}

interface CustomFieldLike { id: string; type: string; value: unknown }

/** Discovery may be enabled only on a Credential and only for a well-formed value. */
export function signInAllowedAccess(entryType: string, field: CustomFieldLike): readonly string[] {
  return entryType === 'credential' && signInMethodValueSchema.safeParse(field.value).success
    ? ['never', 'discovery'] : ['never']
}

/**
 * The single discoverable sign-in method of a Credential, or null when none is
 * discoverable or more than one is (ambiguous methods are never exposed).
 */
export function projectSignInDiscovery(
  entryType: string,
  customFields: readonly CustomFieldLike[],
  access: Readonly<Record<string, string>>,
): { id: string; value: SignInDiscoveryValue } | null {
  if (entryType !== 'credential' || customFields.some(field => field.type === SIGN_IN_FIELD_TYPE_V2)) return null
  const discoverable = customFields.filter((field) => field.type === SIGN_IN_FIELD_TYPE && access[field.id] === 'discovery')
  if (discoverable.length !== 1) return null
  const parsed = signInMethodValueSchema.safeParse(discoverable[0]!.value)
  if (!parsed.success) return null
  return { id: SIGN_IN_DISCOVERY_FIELD_ID,
    value: { schema: SIGN_IN_FIELD_TYPE, provider: parsed.data.provider, entry: parsed.data.entry } }
}

/** Canonical (sorted-key) JSON string carried in the string-valued Discovery field. */
export function canonicalSignInDiscovery(value: SignInDiscoveryValue): string {
  const entry = value.entry === null ? null : { entryId: value.entry.entryId, vaultId: value.entry.vaultId }
  return JSON.stringify({ entry, provider: value.provider, schema: value.schema })
}

export const SIGN_IN_FIELD_TYPE_V2 = 'palladin.signin.v2'
export const SIGN_IN_METHODS_DISCOVERY_FIELD_ID = 'signInMethods'

export const signInMethodIdSchema = z.string().regex(/^custom:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/)
export const signInMethodsDiscoverySchema = z.object({
  schema: z.literal(SIGN_IN_FIELD_TYPE_V2),
  methods: z.array(z.object({
    id: signInMethodIdSchema,
    provider: z.enum(SIGN_IN_PROVIDERS),
    entry: z.object({ vaultId: uuid, entryId: uuid }).strict().nullable(),
  }).strict()).min(1).refine(methods => methods.every((method, index) => index === 0 || methods[index - 1]!.id < method.id),
    'Method IDs must be unique and sorted'),
}).strict()
export type SignInMethodsDiscoveryValue = z.infer<typeof signInMethodsDiscoverySchema>

export function signInV2AllowedAccess(entryType: string, field: CustomFieldLike): readonly string[] {
  return field.type === SIGN_IN_FIELD_TYPE_V2 && signInMethodIdSchema.safeParse(field.id).success
    ? signInAllowedAccess(entryType, field) : ['never']
}

/** Presence of v2 selects the collection contract, even when that method is hidden. */
export function projectSignInMethodsDiscovery(
  entryType: string,
  customFields: readonly CustomFieldLike[],
  access: Readonly<Record<string, string>>,
): { id: typeof SIGN_IN_METHODS_DISCOVERY_FIELD_ID; value: SignInMethodsDiscoveryValue } | null {
  if (entryType !== 'credential' || !customFields.some(field => field.type === SIGN_IN_FIELD_TYPE_V2)) return null
  const methods: SignInMethodsDiscoveryValue['methods'] = []
  for (const field of customFields) {
    if ((field.type !== SIGN_IN_FIELD_TYPE && field.type !== SIGN_IN_FIELD_TYPE_V2) || access[field.id] !== 'discovery') continue
    const parsed = signInMethodValueSchema.safeParse(field.value)
    if (!parsed.success || !signInMethodIdSchema.safeParse(field.id).success) return null
    methods.push({ id: field.id, provider: parsed.data.provider, entry: parsed.data.entry })
  }
  methods.sort((left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0)
  const value = signInMethodsDiscoverySchema.safeParse({ schema: SIGN_IN_FIELD_TYPE_V2, methods })
  return value.success ? { id: SIGN_IN_METHODS_DISCOVERY_FIELD_ID, value: value.data } : null
}

export function canonicalSignInMethodsDiscovery(value: SignInMethodsDiscoveryValue): string {
  const parsed = signInMethodsDiscoverySchema.parse(value)
  return JSON.stringify({ methods: parsed.methods.map(method => ({
    entry: method.entry === null ? null : { entryId: method.entry.entryId, vaultId: method.entry.vaultId },
    id: method.id, provider: method.provider,
  })), schema: parsed.schema })
}

/** Select a wire contract without emitting a competing legacy singleton. */
export function projectSignInDiscoveryField(
  entryType: string,
  customFields: readonly CustomFieldLike[],
  access: Readonly<Record<string, string>>,
): { id: string; value: string } | null {
  if (customFields.some(field => field.type === SIGN_IN_FIELD_TYPE_V2)) {
    const collection = projectSignInMethodsDiscovery(entryType, customFields, access)
    return collection && { id: collection.id, value: canonicalSignInMethodsDiscovery(collection.value) }
  }
  const singleton = projectSignInDiscovery(entryType, customFields, access)
  return singleton && { id: singleton.id, value: canonicalSignInDiscovery(singleton.value) }
}
