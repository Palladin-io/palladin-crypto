import { z } from 'zod'
import { fromBase64, toBase64 } from './encoding'
import { loadSodium } from './sodium-loader'
import { wipe } from './sodium'
import { concatBytes, decodeUuid, encodeU32, encodeU64 } from './vault-v2-bytes'

const MAXIMUM_CIPHERTEXT_BYTES = 262_144
const KEY_BYTES = 32
const NONCE_BYTES = 24
const TAG_BYTES = 16
const DOMAIN = new TextEncoder().encode('PLDN-ENTRY-SHARE-v1')

const fieldSchema = z.strictObject({
  id: z.string().min(1).max(160),
  label: z.string().max(256),
  type: z.enum(['text', 'multiline', 'concealed', 'totp']),
  value: z.string().max(MAXIMUM_CIPHERTEXT_BYTES),
})

const nativeFieldTypes: Readonly<Record<string, z.infer<typeof fieldSchema>['type']>> = {
  'credential.username': 'text', 'credential.password': 'concealed', 'credential.url': 'text',
  'credential.totp': 'totp', 'key.value': 'concealed', 'key.url': 'text',
  'script.source': 'multiline', 'script.interpreter': 'text',
  'creditCard.cardholderName': 'text', 'creditCard.cardNumber': 'concealed',
  'creditCard.cvv': 'concealed',
  'creditCard.expiryMonth': 'text', 'creditCard.expiryYear': 'text',
  'creditCard.billingAddress': 'multiline', notes: 'multiline', description: 'multiline',
}

const snapshotSchema = z.strictObject({
  schema: z.literal('palladin.entry-share.v1'),
  title: z.string().min(1).max(512),
  entryType: z.enum(['key', 'credential', 'script', 'creditCard']),
  fields: z.array(fieldSchema).min(1).max(256),
}).refine((value) => new Set(value.fields.map((field) => field.id)).size === value.fields.length)
  .refine((value) => value.fields.every((field) => field.id.startsWith('custom:') && field.id.length > 7
    || Object.hasOwn(nativeFieldTypes, field.id) && nativeFieldTypes[field.id] === field.type
      && (field.id === 'notes' || field.id === 'description' || field.id.startsWith(`${value.entryType}.`))))

export type EntryShareField = z.infer<typeof fieldSchema>
export type EntryShareSnapshot = z.infer<typeof snapshotSchema>

export interface EntryShareScope {
  shareId: string
  organizationId: string
  vaultId: string
  entryId: string
  sourceRevision: string
  expiresAt: string
}

export interface EntryShareCiphertext {
  nonce: string
  ciphertext: string
}

export interface PreparedEntryShare extends EntryShareCiphertext {
  key: Uint8Array
  accessToken: Uint8Array
}

function invalidSnapshot(): Error {
  return new Error('Invalid Entry sharing snapshot')
}

export function parseEntryShareSnapshot(value: unknown): EntryShareSnapshot {
  const parsed = snapshotSchema.safeParse(value)
  // Zod diagnostics must not escape this boundary: they may contain secret input.
  if (!parsed.success) throw invalidSnapshot()
  return parsed.data
}

function snapshotBytes(snapshot: EntryShareSnapshot): Uint8Array {
  const encoded = new TextEncoder().encode(JSON.stringify(parseEntryShareSnapshot(snapshot)))
  try { return Uint8Array.from(encoded) }
  finally { wipe(encoded) }
}

function encodeExpiry(value: string): Uint8Array {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(value)
  if (!match) throw invalidSnapshot()
  const milliseconds = Date.parse(`${match[1]}Z`)
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0
    || new Date(milliseconds).toISOString() !== `${match[1]}.000Z`) throw invalidSnapshot()
  return concatBytes(encodeU64(BigInt(milliseconds / 1000)),
    encodeU32(Number((match[2] ?? '').padEnd(9, '0'))))
}

export function entryShareAad(scope: EntryShareScope): Uint8Array {
  return concatBytes(DOMAIN, decodeUuid(scope.shareId), decodeUuid(scope.organizationId),
    decodeUuid(scope.vaultId), decodeUuid(scope.entryId), encodeU64(scope.sourceRevision),
    encodeExpiry(scope.expiresAt))
}

export async function prepareEntryShare(
  scope: EntryShareScope,
  snapshot: EntryShareSnapshot,
): Promise<PreparedEntryShare> {
  const s = await loadSodium()
  const aad = entryShareAad(scope)
  const plaintext = snapshotBytes(snapshot)
  let key: Uint8Array | undefined
  let accessToken: Uint8Array | undefined
  try {
    if (plaintext.byteLength + TAG_BYTES > MAXIMUM_CIPHERTEXT_BYTES) throw invalidSnapshot()
    key = s.randombytes_buf(KEY_BYTES)
    accessToken = s.randombytes_buf(KEY_BYTES)
    const nonce = s.randombytes_buf(NONCE_BYTES)
    const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key)
    return { nonce: toBase64(nonce), ciphertext: toBase64(ciphertext), key, accessToken }
  } catch {
    if (key) wipe(key)
    if (accessToken) wipe(accessToken)
    throw invalidSnapshot()
  } finally {
    wipe(plaintext)
  }
}

function decodeCiphertext(value: string, maximumBytes: number): Uint8Array {
  if (value.length > Math.ceil(maximumBytes / 3) * 4) throw invalidSnapshot()
  const bytes = fromBase64(value)
  if (bytes.length > maximumBytes || toBase64(bytes) !== value) throw invalidSnapshot()
  return bytes
}

export async function openEntryShare(
  packet: EntryShareCiphertext,
  authority: EntryShareScope,
  requestedShareId: string,
  key: Uint8Array,
): Promise<EntryShareSnapshot> {
  let plaintext: Uint8Array | undefined
  try {
    if (authority.shareId !== requestedShareId || key.byteLength !== KEY_BYTES) throw invalidSnapshot()
    const aad = entryShareAad(authority)
    const nonce = decodeCiphertext(packet.nonce, NONCE_BYTES)
    const ciphertext = decodeCiphertext(packet.ciphertext, MAXIMUM_CIPHERTEXT_BYTES)
    if (nonce.length !== NONCE_BYTES || ciphertext.length < TAG_BYTES) throw invalidSnapshot()
    const s = await loadSodium()
    plaintext = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, aad, nonce, key)
    return parseEntryShareSnapshot(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)))
  } catch {
    throw invalidSnapshot()
  } finally {
    if (plaintext) wipe(plaintext)
  }
}
