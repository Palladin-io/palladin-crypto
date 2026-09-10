import { loadSodium } from './sodium-loader'
import { fromBase64Url, toBase64Url } from './encoding'

export const SHARED_UNLOCK_PROTOCOL = 'palladin.shared-unlock.v1' as const
export const SHARED_UNLOCK_SUITE = 'X25519-HKDF-SHA256-XCHACHA20POLY1305' as const
export type SharedUnlockDirection = 'web-to-extension' | 'extension-to-web'

/** Expected values come from Identity, the browser route and local lifecycle state,
 * never from the envelope being opened. No durable key material belongs here. */
export interface SharedUnlockContext {
  protocol: typeof SHARED_UNLOCK_PROTOCOL
  direction: SharedUnlockDirection
  operationId: string
  accountId: string
  organizationId: string
  apiOrigin: string
  webOrigin: string
  extensionId: string
  documentBinding: string
  webGeneration: string
  extensionGeneration: string
  linkId: string
  linkEpoch: number
  preferenceRevision: number
  authorizationVersion: number
  keyContextDigest: string
  issuedAtMs: number
  expiresAtMs: number
  unlockedAtMs: number
  idleDeadlineMs: number
  absoluteDeadlineMs: number
  offlineDeadlineMs: number
}
export interface SharedUnlockEnvelope {
  protocol: typeof SHARED_UNLOCK_PROTOCOL
  suite: typeof SHARED_UNLOCK_SUITE
  context: SharedUnlockContext
  sourcePublicKey: string
  recipientPublicKey: string
  nonce: string
  ciphertext: string
}

const fields = [
  'protocol', 'direction', 'operationId', 'accountId', 'organizationId',
  'apiOrigin', 'webOrigin', 'extensionId', 'documentBinding',
  'webGeneration', 'extensionGeneration', 'linkId', 'linkEpoch',
  'preferenceRevision', 'authorizationVersion', 'keyContextDigest',
  'issuedAtMs', 'expiresAtMs', 'unlockedAtMs', 'idleDeadlineMs',
  'absoluteDeadlineMs', 'offlineDeadlineMs',
] as const
const envelopeFields = ['protocol', 'suite', 'context', 'sourcePublicKey', 'recipientPublicKey', 'nonce', 'ciphertext']
const encoder = new TextEncoder()
function invalid(): never { throw new Error('Shared unlock operation rejected') }
function exact(value: unknown, keys: readonly string[]): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid()
  const own = Object.keys(value)
  if (own.length !== keys.length || own.some(key => !keys.includes(key))) invalid()
}
function bytes(value: unknown, length: number): Uint8Array {
  if (typeof value !== 'string') invalid()
  try {
    const decoded = fromBase64Url(value, length)
    if (decoded.length !== length) invalid()
    return decoded
  } catch { return invalid() }
}
function context(value: unknown): SharedUnlockContext {
  exact(value, fields)
  if (value.protocol !== SHARED_UNLOCK_PROTOCOL ||
      !['web-to-extension', 'extension-to-web'].includes(value.direction as string)) invalid()
  for (const name of ['operationId', 'accountId', 'organizationId', 'linkId']) {
    if (typeof value[name] !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value[name] as string)) invalid()
  }
  for (const name of ['apiOrigin', 'webOrigin']) {
    if (typeof value[name] !== 'string' || (value[name] as string).length > 256) invalid()
    let url: URL
    try { url = new URL(value[name] as string) } catch { return invalid() }
    if (url.origin !== value[name] || (url.protocol !== 'https:' &&
        !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)))) invalid()
  }
  for (const name of ['extensionId', 'documentBinding']) {
    if (typeof value[name] !== 'string' || !/^[\x21-\x7e]{1,256}$/.test(value[name] as string)) invalid()
  }
  for (const name of ['webGeneration', 'extensionGeneration', 'keyContextDigest']) bytes(value[name], 32)
  for (const name of ['linkEpoch', 'preferenceRevision', 'authorizationVersion', 'issuedAtMs',
    'expiresAtMs', 'unlockedAtMs', 'idleDeadlineMs', 'absoluteDeadlineMs', 'offlineDeadlineMs']) {
    if (!Number.isSafeInteger(value[name]) || (value[name] as number) <= 0) invalid()
  }
  const c = value as unknown as SharedUnlockContext
  if (c.expiresAtMs <= c.issuedAtMs || c.expiresAtMs - c.issuedAtMs > 30_000 ||
    c.unlockedAtMs > c.issuedAtMs || c.expiresAtMs > Math.min(c.idleDeadlineMs, c.absoluteDeadlineMs, c.offlineDeadlineMs)) invalid()
  return Object.freeze({ ...c })
}
function encode(values: readonly (string | number)[]): Uint8Array {
  const parts = values.map(value => encoder.encode(String(value)))
  const output = new Uint8Array(parts.reduce((n, part) => n + part.length + 4, 0))
  const view = new DataView(output.buffer)
  let offset = 0
  for (const part of parts) {
    view.setUint32(offset, part.length, false)
    output.set(part, offset + 4)
    offset += 4 + part.length
  }
  return output
}
export function encodeSharedUnlockTranscript(expected: SharedUnlockContext, sourcePublicKey: string, recipientPublicKey: string): Uint8Array {
  const c = context(expected)
  bytes(sourcePublicKey, 32)
  bytes(recipientPublicKey, 32)
  return encode([SHARED_UNLOCK_PROTOCOL, SHARED_UNLOCK_SUITE, ...fields.map(field => c[field]), sourcePublicKey, recipientPublicKey])
}
/** Hash the independently authorized complete MK transcript for the Identity proof. */
export async function hashSharedUnlockTranscript(expected: SharedUnlockContext, sourcePublicKey: string, recipientPublicKey: string): Promise<string> {
  const transcript = new Uint8Array(encodeSharedUnlockTranscript(expected, sourcePublicKey, recipientPublicKey))
  return toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', transcript)))
}

async function derive(shared: Uint8Array<ArrayBuffer>, transcript: Uint8Array<ArrayBuffer>, direction: SharedUnlockDirection): Promise<Uint8Array> {
  try {
    const salt = await crypto.subtle.digest('SHA-256', transcript)
    const key = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits'])
    return new Uint8Array(await crypto.subtle.deriveBits({
      name: 'HKDF', hash: 'SHA-256', salt,
      info: encoder.encode(`${SHARED_UNLOCK_PROTOCOL}/mk/${direction}`),
    }, key, 256))
  } finally { shared.fill(0) }
}

export interface SharedUnlockParticipant {
  readonly publicKey: string
  seal(masterKey: Uint8Array, verifiedRecipientPublicKey: string): Promise<SharedUnlockEnvelope>
  open(envelope: unknown, verifiedSourcePublicKey: string): Promise<Uint8Array>
  dispose(): void
}

/** A single operation's ephemeral participant. Browser adapters authenticate the peer
 * public key over their verified channel. assertCurrent MUST synchronously reject
 * changed account/environment/document/generation, lock/logout/off/revoke or stale
 * Identity authorization. It is called before and after asynchronous derivation.
 * The caller must recheck current authority after awaiting open, immediately before
 * installing the MK, and wipe the returned buffer when installation is cancelled.
 * This primitive neither authenticates a browser nor issues an Identity session. */
export interface SharedUnlockOffer {
  readonly publicKey: string
  bind(expected: SharedUnlockContext): SharedUnlockParticipant
  dispose(): void
}

/** Generate the public DH offer before Identity authorizes the transcript. Binding
 * then consumes that offer exactly once. An unbound offer contains no authority;
 * adapters dispose it on peer loss/cancellation and must never persist it. */
export async function createSharedUnlockOffer(options: {
  role: 'source' | 'recipient'
  assertCurrent: (expected: Readonly<SharedUnlockContext>) => void
  now?: () => number
}): Promise<SharedUnlockOffer> {
  const { role, assertCurrent } = options
  if (!['source', 'recipient'].includes(role) || typeof assertCurrent !== 'function') invalid()
  const now = options.now ?? Date.now
  const sodium = await loadSodium()
  const createdAt = now()
  if (!Number.isSafeInteger(createdAt) || createdAt <= 0) invalid()
  const pair = sodium.crypto_kx_keypair()
  const publicKey = toBase64Url(pair.publicKey)
  let bound = false
  let disposed = false
  function dispose() { disposed = true; sodium.memzero(pair.privateKey) }
  return {
    publicKey, dispose,
    bind(expectedInput) {
      let expected: SharedUnlockContext
      try {
        if (bound || disposed) invalid()
        bound = true
        expected = context(expectedInput)
      } catch { dispose(); return invalid() }
      let used = false
      function check() {
        const time = now()
        if (disposed || time < createdAt || time - createdAt >= 30_000 || !Number.isSafeInteger(time) || time < expected.issuedAtMs || time >= expected.expiresAtMs) invalid()
        assertCurrent(expected)
      }
      function take(required: typeof role) {
        if (used || role !== required) invalid()
        used = true
        check()
      }
      async function exchange(peer: string, source: string, recipient: string) {
        const transcript = encodeSharedUnlockTranscript(expected, source, recipient)
        const shared = sodium.crypto_scalarmult(pair.privateKey, bytes(peer, 32))
        try { return { transcript, key: await derive(new Uint8Array(shared), new Uint8Array(transcript), expected.direction) } }
        finally { sodium.memzero(shared) }
      }
      try { check() } catch { dispose(); return invalid() }
      return {
        publicKey,
        dispose,
        async seal(masterKey, peer) {
          // Copy before any await so caller mutation cannot change the encrypted MK.
          let plain: Uint8Array | undefined
          let key: Uint8Array | undefined
          try {
            take('source')
            if (!(masterKey instanceof Uint8Array) || masterKey.length !== 32) invalid()
            plain = new Uint8Array(masterKey)
            const derived = await exchange(peer, publicKey, peer)
            key = derived.key
            check()
            const nonce = sodium.randombytes_buf(24)
            const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, derived.transcript, null, nonce, key)
            return { protocol: SHARED_UNLOCK_PROTOCOL, suite: SHARED_UNLOCK_SUITE,
              context: { ...expected }, sourcePublicKey: publicKey, recipientPublicKey: peer,
              nonce: toBase64Url(nonce), ciphertext: toBase64Url(ciphertext) }
          } catch { return invalid() }
          finally { if (plain) sodium.memzero(plain); if (key) sodium.memzero(key); dispose() }
        },
        async open(envelope, peer) {
          let key: Uint8Array | undefined
          let plain: Uint8Array | undefined
          try {
            take('recipient')
            exact(envelope, envelopeFields)
            if (envelope.protocol !== SHARED_UNLOCK_PROTOCOL || envelope.suite !== SHARED_UNLOCK_SUITE ||
                envelope.sourcePublicKey !== peer || envelope.recipientPublicKey !== publicKey) invalid()
            const received = context(envelope.context)
            if (fields.some(field => received[field] !== expected[field])) invalid()
            // Decode/copy attacker-controlled inputs before awaiting derivation.
            const nonce = bytes(envelope.nonce, 24)
            const ciphertext = bytes(envelope.ciphertext, 48)
            const derived = await exchange(peer, peer, publicKey)
            key = derived.key
            check()
            plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ciphertext, derived.transcript, nonce, key)
            if (plain.length !== 32) invalid()
            check()
            const result = plain
            plain = undefined
            return result
          } catch { return invalid() }
          finally { if (plain) sodium.memzero(plain); if (key) sodium.memzero(key); dispose() }
        },
      }
    },
  }
}
