import { fromBase64Url, toBase64Url } from '../encoding'
import { getCryptoProvider } from '../provider/active-provider'
import { encodeWrapperContext, wrapperContextHash, type EncodableWrapperContext } from './context'
import {
  KEY_WRAPPER_PROTOCOL_VERSION,
  KEY_WRAPPER_SUITE,
  KEY_WRAPPER_SUITES,
  KeyWrapperError,
  PURPOSE_RULES,
  SCOPE_FIELDS,
  SUITE_LIFECYCLE,
  type KeyWrapperPurpose,
  type KeyWrapperScopeField,
  type KeyWrapperSuiteId,
  type PurposeRule,
} from './registry'
import type { KeyWrapperSuiteImplementation } from './suites/suite'
import { equalBytes, x25519SealedBoxV1 } from './suites/x25519-sealed-box-v1'
import { xwingV1 } from './suites/xwing-v1'

const IMPLEMENTATIONS: Readonly<Record<KeyWrapperSuiteId, KeyWrapperSuiteImplementation>> = Object.freeze({
  'palladin-xwing-v1': xwingV1,
  'palladin-x25519-sealed-box-v1': x25519SealedBoxV1,
})

/** Wire descriptor of a sealed key package (`descriptor` in key-wrapper v1). */
export interface KeyWrapperDescriptor {
  protocolVersion: number
  wrapperSuiteId: string
  purpose: number
  scope: Partial<Record<KeyWrapperScopeField, string | null>>
  /** Positive u64 as canonical decimal text. */
  resourceRevision: string
  wrappedKeyVersion: number
  memberKeyGeneration?: number | null
  recipientKeyKind: number
  recipientKeyVersion: number
  /** Canonical unpadded base64url of the 32-byte suite fingerprint. */
  recipientFingerprint: string
  parentDescriptorHash?: string | null
}

/**
 * Recipient key as registered in its authenticated key directory. `suiteId`
 * must come from that directory entry, never from the envelope being opened.
 */
export interface KeyWrapperRecipient {
  suiteId: string
  keyKind: number
  keyVersion: number
  publicKey: Uint8Array
  /** Required only to open. */
  privateKey?: Uint8Array
}

export interface RecipientKeyPair {
  suiteId: KeyWrapperSuiteId
  publicKey: Uint8Array
  /** 32-byte seed. Keep in memory only and `wipe` after use. */
  privateKey: Uint8Array
}

const DESCRIPTOR_FIELDS = new Set([
  'protocolVersion', 'wrapperSuiteId', 'purpose', 'scope', 'resourceRevision', 'wrappedKeyVersion',
  'memberKeyGeneration', 'recipientKeyKind', 'recipientKeyVersion', 'recipientFingerprint', 'parentDescriptorHash',
])
const SCOPE_FIELD_NAMES = new Set<string>(SCOPE_FIELDS.map(([field]) => field))
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const U64_MAX = 0xffffffffffffffffn

const fail = (code: ConstructorParameters<typeof KeyWrapperError>[0]): never => {
  throw new KeyWrapperError(code)
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

const positiveU32 = (value: unknown): value is number =>
  typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 0xffffffff

function suiteImplementation(suiteId: string): KeyWrapperSuiteImplementation | undefined {
  return Object.hasOwn(IMPLEMENTATIONS, suiteId) ? IMPLEMENTATIONS[suiteId as KeyWrapperSuiteId] : undefined
}

function resolveSuite(descriptor: KeyWrapperDescriptor, operation: 'seal' | 'open') {
  if (!isObject(descriptor)) fail('malformed-descriptor')
  const suiteId = descriptor.wrapperSuiteId
  const implementation = typeof suiteId === 'string' ? suiteImplementation(suiteId) : undefined
  if (!implementation) return fail('unsupported-suite')
  const suite = KEY_WRAPPER_SUITES[suiteId as KeyWrapperSuiteId]
  const lifecycle = SUITE_LIFECYCLE[suite.status]
  if (!lifecycle.open) fail('unsupported-suite')
  if (!lifecycle[operation]) fail('suite-not-writable')
  const purpose = descriptor.purpose
  if (typeof purpose !== 'number' || !Object.hasOwn(PURPOSE_RULES, purpose)) fail('unsupported-purpose')
  if (!suite.purposes.includes(purpose)) fail('suite-not-allowed-for-purpose')
  return { implementation, rule: PURPOSE_RULES[purpose as KeyWrapperPurpose] }
}

function decodeHash(value: unknown): Uint8Array {
  if (typeof value !== 'string') return fail('malformed-descriptor')
  try {
    const bytes = fromBase64Url(value, 32)
    if (bytes.length === 32) return bytes
  } catch { /* mapped below */ }
  return fail('malformed-descriptor')
}

function validateDescriptor(descriptor: KeyWrapperDescriptor, rule: PurposeRule): EncodableWrapperContext {
  for (const field of Object.keys(descriptor)) if (!DESCRIPTOR_FIELDS.has(field)) fail('malformed-descriptor')
  if (descriptor.protocolVersion !== KEY_WRAPPER_PROTOCOL_VERSION) fail('malformed-descriptor')

  const scope = descriptor.scope
  if (!isObject(scope)) return fail('malformed-descriptor')
  for (const field of Object.keys(scope)) if (!SCOPE_FIELD_NAMES.has(field)) fail('malformed-descriptor')
  const scopeIds: EncodableWrapperContext['scope'] = {}
  for (const [field, bit] of SCOPE_FIELDS) {
    const value = scope[field]
    const required = (rule.scopeBitmap & bit) !== 0
    if (required !== (value != null)) fail('malformed-descriptor')
    if (!required) continue
    if (typeof value !== 'string' || !UUID.test(value)) fail('malformed-descriptor')
    scopeIds[field] = value as string
  }

  const revision = descriptor.resourceRevision
  if (typeof revision !== 'string' || !/^[1-9][0-9]{0,19}$/.test(revision) || BigInt(revision) > U64_MAX) {
    fail('malformed-descriptor')
  }
  if (!positiveU32(descriptor.wrappedKeyVersion) || !positiveU32(descriptor.recipientKeyVersion)) fail('malformed-descriptor')

  const generation = descriptor.memberKeyGeneration
  const hasGeneration = generation != null
  if ((rule.memberKeyGeneration === 'required' && !hasGeneration)
    || (rule.memberKeyGeneration === 'forbidden' && hasGeneration)
    || (hasGeneration && !positiveU32(generation))) fail('malformed-descriptor')

  const hasParent = descriptor.parentDescriptorHash != null
  if ((rule.parentDescriptorHash === 'required') !== hasParent) fail('malformed-descriptor')
  if (!(rule.recipientKeyKinds as readonly number[]).includes(descriptor.recipientKeyKind)) fail('malformed-descriptor')

  return {
    protocolVersion: descriptor.protocolVersion,
    wrapperSuiteId: descriptor.wrapperSuiteId,
    purpose: descriptor.purpose,
    scope: scopeIds,
    resourceRevision: BigInt(revision),
    wrappedKeyVersion: descriptor.wrappedKeyVersion,
    memberKeyGeneration: hasGeneration ? generation : undefined,
    recipientKeyKind: descriptor.recipientKeyKind,
    recipientKeyVersion: descriptor.recipientKeyVersion,
    recipientFingerprint: decodeHash(descriptor.recipientFingerprint),
    parentDescriptorHash: hasParent ? decodeHash(descriptor.parentDescriptorHash) : undefined,
  }
}

function bindRecipient(
  context: EncodableWrapperContext,
  implementation: KeyWrapperSuiteImplementation,
  recipient: KeyWrapperRecipient,
): void {
  if (!isObject(recipient)
    || recipient.suiteId !== context.wrapperSuiteId
    || recipient.keyKind !== context.recipientKeyKind
    || recipient.keyVersion !== context.recipientKeyVersion
    || !(recipient.publicKey instanceof Uint8Array)) fail('recipient-mismatch')
  const fingerprint = implementation.fingerprint(recipient.publicKey, recipient.keyKind, context.protocolVersion)
  if (!equalBytes(fingerprint, context.recipientFingerprint)) fail('recipient-mismatch')
}

function prepare(descriptor: KeyWrapperDescriptor, recipient: KeyWrapperRecipient, operation: 'seal' | 'open') {
  const { implementation, rule } = resolveSuite(descriptor, operation)
  const context = validateDescriptor(descriptor, rule)
  bindRecipient(context, implementation, recipient)
  return { implementation, contextHash: wrapperContextHash(encodeWrapperContext(context)) }
}

/**
 * Seals a 32-byte key for one recipient and returns the canonical base64url
 * package. Only an `active` suite may seal. `descriptor` and `recipient` must
 * be built from authenticated state (key directory, Vault, Member, Agent).
 */
export async function sealKey(
  descriptor: KeyWrapperDescriptor,
  wrappedKey: Uint8Array,
  recipient: KeyWrapperRecipient,
): Promise<string> {
  const { implementation, contextHash } = prepare(descriptor, recipient, 'seal')
  if (!(wrappedKey instanceof Uint8Array) || wrappedKey.length !== 32) fail('malformed-descriptor')
  await getCryptoProvider().ready()
  return toBase64Url(await implementation.seal(wrappedKey, recipient.publicKey, contextHash))
}

/**
 * Opens a package and returns the 32-byte wrapped key (caller wipes it).
 * `descriptor` is the expected descriptor built independently of the package;
 * `recipient.suiteId` is the suite registered in the authenticated key directory.
 */
export async function openKey(
  descriptor: KeyWrapperDescriptor,
  encodedSealedKeyPackage: string,
  recipient: KeyWrapperRecipient,
): Promise<Uint8Array> {
  const { implementation, contextHash } = prepare(descriptor, recipient, 'open')
  let sealedPackage: Uint8Array | undefined
  try {
    if (typeof encodedSealedKeyPackage === 'string') {
      sealedPackage = fromBase64Url(encodedSealedKeyPackage, implementation.packageBytes)
    }
  } catch { /* mapped below */ }
  if (!sealedPackage || sealedPackage.length !== implementation.packageBytes) return fail('malformed-package')
  const privateKey = recipient.privateKey
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== implementation.privateKeyBytes) {
    return fail('recipient-mismatch')
  }
  await getCryptoProvider().ready()
  return implementation.open(sealedPackage, recipient.publicKey, privateKey, contextHash)
}

/** Canonical encoded context (`PLDNX2W1…`) of a descriptor that is valid to open. */
export function encodeKeyWrapperContext(descriptor: KeyWrapperDescriptor): Uint8Array {
  const { rule } = resolveSuite(descriptor, 'open')
  return encodeWrapperContext(validateDescriptor(descriptor, rule))
}

/** Suite-specific 32-byte recipient fingerprint for `descriptor.recipientFingerprint`. */
export function computeRecipientFingerprint(
  suiteId: string,
  keyKind: number,
  publicKey: Uint8Array,
): Uint8Array {
  const implementation = suiteImplementation(suiteId)
  if (!implementation) return fail('unsupported-suite')
  return implementation.fingerprint(publicKey, keyKind, KEY_WRAPPER_PROTOCOL_VERSION)
}

/** Fresh recipient key pair for the active suite; the private key is a CSPRNG seed. */
export async function generateRecipientKeyPair(): Promise<RecipientKeyPair> {
  const provider = getCryptoProvider()
  await provider.ready()
  const suiteId = KEY_WRAPPER_SUITE.active
  const privateKey = provider.randomBytes(IMPLEMENTATIONS[suiteId].privateKeyBytes)
  return { suiteId, privateKey, publicKey: await IMPLEMENTATIONS[suiteId].publicKeyFromPrivateKey(privateKey) }
}

/** Recomputes the public key of a stored private key so callers can compare it with the key directory. */
export async function deriveRecipientPublicKey(suiteId: string, privateKey: Uint8Array): Promise<Uint8Array> {
  const implementation = suiteImplementation(suiteId)
  if (!implementation || !SUITE_LIFECYCLE[KEY_WRAPPER_SUITES[suiteId as KeyWrapperSuiteId].status].open) {
    return fail('unsupported-suite')
  }
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== implementation.privateKeyBytes) fail('recipient-mismatch')
  await getCryptoProvider().ready()
  return implementation.publicKeyFromPrivateKey(privateKey)
}
