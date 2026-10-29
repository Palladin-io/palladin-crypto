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
  if (entryType !== 'credential') return null
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
