/**
 * Crypto payload types — the shapes that get encrypted/decrypted by this
 * package. They mirror the vault feature's wire contract; the web panel keeps
 * its own richer domain types (icons, colours, list metadata, ...) and stays
 * structurally compatible with these.
 *
 * Entry types match the backend `EntryType` enum, serialised as integers:
 * KEY (0) = a single secret value; CREDENTIAL (1) = username + password (+ url);
 * SCRIPT (2) = an agent-run script with declared vault-data refs.
 */

export const ENTRY_TYPE_KEY = 0 as const
export const ENTRY_TYPE_CREDENTIAL = 1 as const
export const ENTRY_TYPE_SCRIPT = 2 as const
export type EntryType =
  | typeof ENTRY_TYPE_KEY
  | typeof ENTRY_TYPE_CREDENTIAL
  | typeof ENTRY_TYPE_SCRIPT

/**
 * Encrypted-blob schema version. Absence means v1 (well-known fields only, no
 * `fields[]`). v2 is additive — well-known fields stay top-level and custom
 * `fields[]` sit alongside them.
 */
export const BLOB_VERSION_V2 = 2 as const

/** Custom-field kinds a client renders. Unknown values are tolerated on read. */
export type CustomFieldType = 'text' | 'multiline' | 'concealed' | 'totp'

/**
 * Parsed TOTP seed. Stored as the `value` of a `totp` custom field (never the
 * raw `otpauth://` URI). Lives inside the encrypted blob — the backend never
 * sees it.
 */
export interface TotpParams {
  /** Base32 (RFC 4648) shared secret, no spaces/padding. */
  secret: string
  algorithm: 'SHA1' | 'SHA256' | 'SHA512'
  digits: number
  period: number
  issuer?: string
  account?: string
}

/**
 * A user-defined field carried in the encrypted blob's `fields[]` (v2). For
 * `totp` fields `value` is a {@link TotpParams} object; otherwise a string.
 */
export interface CustomField {
  id: string
  label: string
  type: string
  value: string | TotpParams
  agentVisible?: boolean
}

/** Interpreters an agent may run a SCRIPT entry under (validated, never arbitrary). */
export const SCRIPT_INTERPRETERS = ['bash', 'sh', 'node', 'python'] as const
export type ScriptInterpreter = (typeof SCRIPT_INTERPRETERS)[number]

/** An explicit `ENV_NAME -> (entry, field)` mapping declared on a SCRIPT entry. */
export interface ScriptRef {
  env: string
  vaultId?: string
  entryId: string
  field: string
}

/**
 * Encrypted entry content stored as JSONB on the backend. The plaintext type
 * lives on the outer entry `type` field — clients use it to choose the right
 * schema when decrypting.
 */
export interface EntryContent {
  encryptedBlob: string
  nonce: string
}

/** Fields shared by every v2 plaintext. Absent `v` means a v1 blob. */
export interface EntryPlaintextV2Common {
  v?: typeof BLOB_VERSION_V2
  fields?: CustomField[]
}

/**
 * Plaintext payload that gets encrypted into `EntryContent.encryptedBlob`.
 * Discriminated union on `type`.
 */
export type EntryPlaintext =
  | (EntryPlaintextV2Common & { type: typeof ENTRY_TYPE_KEY; value: string; notes?: string })
  | (EntryPlaintextV2Common & {
      type: typeof ENTRY_TYPE_CREDENTIAL
      username: string
      password: string
      url?: string
      notes?: string
      totp?: string
    })
  | (EntryPlaintextV2Common & {
      type: typeof ENTRY_TYPE_SCRIPT
      script: string
      interpreter: ScriptInterpreter
      notes?: string
      refs?: ScriptRef[]
    })
