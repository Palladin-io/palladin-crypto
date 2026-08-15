import { fromBase64Url, toBase64Url } from './encoding'
import { loadSodium } from './sodium-loader'

export const INJECT_PROVIDER_PROTOCOL = 'palladin.inject-provider.v1' as const

const SESSION_TRANSCRIPT_PREFIX = `${INJECT_PROVIDER_PROTOCOL}\0extension-session-v1\0`
const SESSION_ID_PREFIX = `${INJECT_PROVIDER_PROTOCOL}\0extension-session-id-v1\0`
const SESSION_KEYS_INFO = `${INJECT_PROVIDER_PROTOCOL}\0extension-session-keys-v1\0`
const SECURE_FRAME_PREFIX = `${INJECT_PROVIDER_PROTOCOL}\0extension-secure-frame-v1\0`
const EXTENSION_ORIGIN = /^(?:chrome|moz|safari-web)-extension:\/\/[A-Za-z0-9._-]+$/
const MAX_PLAINTEXT_BYTES = 768 * 1024
const MAX_SEQUENCE = 0xffff_ffff_ffff_ffffn
const textEncoder = new TextEncoder()

export interface InjectSessionOpen {
  readonly protocol: typeof INJECT_PROVIDER_PROTOCOL
  readonly type: 'session.open'
  readonly extensionNonce: string
  readonly extensionEphemeralPublicKey: string
}

export interface InjectSessionReady {
  readonly protocol: typeof INJECT_PROVIDER_PROTOCOL
  readonly type: 'session.ready'
  readonly extensionNonce: string
  readonly hostNonce: string
  readonly hostEphemeralPublicKey: string
  readonly hostSigningPublicKey: string
  readonly signature: string
  readonly sessionId: string
}

export interface InjectSecureFrame {
  readonly protocol: typeof INJECT_PROVIDER_PROTOCOL
  readonly type: 'secure'
  readonly sessionId: string
  readonly sequence: string
  readonly ciphertext: string
}

export interface InjectSecureChannel {
  seal(plaintext: Uint8Array): Promise<InjectSecureFrame>
  open(frame: InjectSecureFrame): Promise<Uint8Array>
  dispose(): void
}

export interface InjectClientSession {
  readonly openFrame: InjectSessionOpen
  acceptReady(frame: InjectSessionReady): Promise<InjectSecureChannel>
  dispose(): void
}

export interface CreateInjectClientSessionOptions {
  readonly protocol: typeof INJECT_PROVIDER_PROTOCOL
  readonly extensionOrigin: string
  /** Canonical unpadded base64url Ed25519 public key accepted during pairing. */
  readonly pinnedHostSigningPublicKey: string
}

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}

function u32be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new TypeError('Transcript component is too large')
  }
  const output = new Uint8Array(4)
  new DataView(output.buffer).setUint32(0, value, false)
  return output
}

function u64be(value: bigint): Uint8Array {
  if (value < 0n || value > MAX_SEQUENCE) throw new TypeError('Sequence is outside uint64')
  const output = new Uint8Array(8)
  new DataView(output.buffer).setBigUint64(0, value, false)
  return output
}

function lengthPrefixed(value: Uint8Array): Uint8Array {
  return concat(u32be(value.length), value)
}

function transcript(
  extensionOrigin: string,
  extensionNonce: Uint8Array,
  extensionPublicKey: Uint8Array,
  hostNonce: Uint8Array,
  hostPublicKey: Uint8Array,
  hostSigningPublicKey: Uint8Array,
): Uint8Array {
  return concat(
    textEncoder.encode(SESSION_TRANSCRIPT_PREFIX),
    lengthPrefixed(textEncoder.encode(extensionOrigin)),
    lengthPrefixed(extensionNonce),
    lengthPrefixed(extensionPublicKey),
    lengthPrefixed(hostNonce),
    lengthPrefixed(hostPublicKey),
    lengthPrefixed(hostSigningPublicKey),
  )
}

function exactObject(value: unknown, keys: readonly string[], label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`)
  }
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} contains an unexpected field`)
  }
}

function canonicalBytes(value: unknown, length: number, label: string): Uint8Array {
  if (typeof value !== 'string') throw new TypeError(`${label} must be canonical base64url`)
  const decoded = fromBase64Url(value)
  if (decoded.length !== length) throw new TypeError(`${label} has the wrong length`)
  return decoded
}

function canonicalVariableBytes(value: unknown, label: string): Uint8Array {
  if (typeof value !== 'string') throw new TypeError(`${label} must be canonical base64url`)
  return fromBase64Url(value)
}

function canonicalSequence(value: unknown): bigint {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError('Secure-frame sequence is not canonical')
  }
  const parsed = BigInt(value)
  if (parsed > MAX_SEQUENCE) throw new TypeError('Secure-frame sequence is outside uint64')
  return parsed
}

async function hkdfSha256(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array): Promise<Uint8Array> {
  const ikmCopy = new Uint8Array(ikm.length)
  const saltCopy = new Uint8Array(salt.length)
  const infoCopy = new Uint8Array(info.length)
  ikmCopy.set(ikm)
  saltCopy.set(salt)
  infoCopy.set(info)
  try {
    const key = await crypto.subtle.importKey('raw', ikmCopy.buffer, 'HKDF', false, ['deriveBits'])
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: saltCopy.buffer, info: infoCopy.buffer },
      key,
      112 * 8,
    )
    return new Uint8Array(bits)
  } finally {
    ikmCopy.fill(0)
    saltCopy.fill(0)
    infoCopy.fill(0)
  }
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(value.length)
  copy.set(value)
  try {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', copy.buffer))
  } finally {
    copy.fill(0)
  }
}

function frameNonce(base: Uint8Array, sequence: bigint): Uint8Array {
  const output = new Uint8Array(base)
  const encoded = u64be(sequence)
  for (let index = 0; index < encoded.length; index++) {
    output[output.length - encoded.length + index] ^= encoded[index]
  }
  return output
}

function frameAad(sessionId: string, direction: 'host-to-extension' | 'extension-to-host', sequence: bigint): Uint8Array {
  return concat(
    textEncoder.encode(SECURE_FRAME_PREFIX),
    textEncoder.encode(sessionId),
    new Uint8Array([0]),
    textEncoder.encode(direction),
    new Uint8Array([0]),
    u64be(sequence),
  )
}

class SecureChannel implements InjectSecureChannel {
  private outboundSequence = 0n
  private inboundSequence = 0n
  private disposed = false

  constructor(
    private readonly sessionId: string,
    private readonly outboundKey: Uint8Array,
    private readonly inboundKey: Uint8Array,
    private readonly outboundNonceBase: Uint8Array,
    private readonly inboundNonceBase: Uint8Array,
  ) {}

  async seal(plaintext: Uint8Array): Promise<InjectSecureFrame> {
    this.assertActive()
    if (!(plaintext instanceof Uint8Array) || plaintext.length > MAX_PLAINTEXT_BYTES) {
      throw new TypeError('Secure-frame plaintext exceeds the permitted size')
    }
    const sodium = await loadSodium()
    const sequence = this.outboundSequence
    const nonce = frameNonce(this.outboundNonceBase, sequence)
    const aad = frameAad(this.sessionId, 'extension-to-host', sequence)
    try {
      const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        aad,
        null,
        nonce,
        this.outboundKey,
      )
      this.outboundSequence += 1n
      return {
        protocol: INJECT_PROVIDER_PROTOCOL,
        type: 'secure',
        sessionId: this.sessionId,
        sequence: sequence.toString(10),
        ciphertext: toBase64Url(ciphertext),
      }
    } finally {
      sodium.memzero(nonce)
      sodium.memzero(aad)
    }
  }

  async open(frame: InjectSecureFrame): Promise<Uint8Array> {
    this.assertActive()
    exactObject(frame, ['protocol', 'type', 'sessionId', 'sequence', 'ciphertext'], 'Secure frame')
    if (frame.protocol !== INJECT_PROVIDER_PROTOCOL || frame.type !== 'secure') {
      throw new TypeError('Unexpected secure-frame protocol or type')
    }
    if (frame.sessionId !== this.sessionId) throw new Error('Secure frame belongs to another session')
    const sequence = canonicalSequence(frame.sequence)
    if (sequence !== this.inboundSequence) throw new Error('Secure frame is replayed or out of order')
    const ciphertext = canonicalVariableBytes(frame.ciphertext, 'Secure-frame ciphertext')
    if (ciphertext.length < 16 || ciphertext.length > MAX_PLAINTEXT_BYTES + 16) {
      throw new TypeError('Secure-frame ciphertext has an invalid size')
    }
    const sodium = await loadSodium()
    const nonce = frameNonce(this.inboundNonceBase, sequence)
    const aad = frameAad(this.sessionId, 'host-to-extension', sequence)
    try {
      const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        aad,
        nonce,
        this.inboundKey,
      )
      this.inboundSequence += 1n
      return plaintext
    } finally {
      sodium.memzero(ciphertext)
      sodium.memzero(nonce)
      sodium.memzero(aad)
    }
  }

  dispose(): void {
    if (this.disposed) return
    this.disposed = true
    this.outboundKey.fill(0)
    this.inboundKey.fill(0)
    this.outboundNonceBase.fill(0)
    this.inboundNonceBase.fill(0)
  }

  private assertActive(): void {
    if (this.disposed) throw new Error('Inject secure channel is disposed')
    if (this.outboundSequence > MAX_SEQUENCE || this.inboundSequence > MAX_SEQUENCE) {
      this.dispose()
      throw new Error('Inject secure-channel sequence exhausted')
    }
  }
}

/** Fingerprint displayed during explicit host pairing; never a secret. */
export async function injectHostKeyFingerprint(hostSigningPublicKey: string): Promise<string> {
  const publicKey = canonicalBytes(hostSigningPublicKey, 32, 'Host signing public key')
  const sodium = await loadSodium()
  try {
    return toBase64Url(await sha256(publicKey))
  } finally {
    sodium.memzero(publicKey)
  }
}

/**
 * Creates the browser side of the authenticated native-host session.
 * The returned object owns ephemeral secret material until acceptReady or dispose.
 */
export async function createInjectClientSession(
  options: CreateInjectClientSessionOptions,
): Promise<InjectClientSession> {
  exactObject(options, ['protocol', 'extensionOrigin', 'pinnedHostSigningPublicKey'], 'Inject client options')
  if (options.protocol !== INJECT_PROVIDER_PROTOCOL) throw new TypeError('Unsupported inject-provider protocol')
  if (!EXTENSION_ORIGIN.test(options.extensionOrigin)) throw new TypeError('Invalid browser extension origin')
  const pinnedHostKey = canonicalBytes(options.pinnedHostSigningPublicKey, 32, 'Pinned host signing public key')
  const sodium = await loadSodium()
  const extensionPrivateKey = sodium.randombytes_buf(32)
  const extensionPublicKey = sodium.crypto_scalarmult_base(extensionPrivateKey)
  const extensionNonce = sodium.randombytes_buf(32)
  const openFrame: InjectSessionOpen = {
    protocol: INJECT_PROVIDER_PROTOCOL,
    type: 'session.open',
    extensionNonce: toBase64Url(extensionNonce),
    extensionEphemeralPublicKey: toBase64Url(extensionPublicKey),
  }
  let disposed = false

  const dispose = (): void => {
    if (disposed) return
    disposed = true
    sodium.memzero(extensionPrivateKey)
    sodium.memzero(extensionPublicKey)
    sodium.memzero(extensionNonce)
    sodium.memzero(pinnedHostKey)
  }

  return {
    openFrame,
    async acceptReady(frame: InjectSessionReady): Promise<InjectSecureChannel> {
      if (disposed) throw new Error('Inject client session is disposed')
      try {
        exactObject(frame, [
          'protocol', 'type', 'extensionNonce', 'hostNonce', 'hostEphemeralPublicKey',
          'hostSigningPublicKey', 'signature', 'sessionId',
        ], 'Session-ready frame')
        if (frame.protocol !== INJECT_PROVIDER_PROTOCOL || frame.type !== 'session.ready') {
          throw new TypeError('Unexpected session-ready protocol or type')
        }
        const echoedExtensionNonce = canonicalBytes(frame.extensionNonce, 32, 'Extension nonce')
        const hostNonce = canonicalBytes(frame.hostNonce, 32, 'Host nonce')
        const hostPublicKey = canonicalBytes(frame.hostEphemeralPublicKey, 32, 'Host ephemeral public key')
        const hostSigningPublicKey = canonicalBytes(frame.hostSigningPublicKey, 32, 'Host signing public key')
        const signature = canonicalBytes(frame.signature, 64, 'Host signature')
        try {
          if (!sodium.memcmp(echoedExtensionNonce, extensionNonce)) {
            throw new Error('Session-ready frame does not echo the extension nonce')
          }
          if (!sodium.memcmp(hostSigningPublicKey, pinnedHostKey)) {
            throw new Error('Native host identity does not match the paired key')
          }
          const signedTranscript = transcript(
            options.extensionOrigin,
            extensionNonce,
            extensionPublicKey,
            hostNonce,
            hostPublicKey,
            hostSigningPublicKey,
          )
          try {
            if (!sodium.crypto_sign_verify_detached(signature, signedTranscript, hostSigningPublicKey)) {
              throw new Error('Native host handshake signature is invalid')
            }
            const sessionIdBytes = await sha256(concat(
              textEncoder.encode(SESSION_ID_PREFIX),
              signedTranscript,
              signature,
            ))
            const expectedSessionId = toBase64Url(sessionIdBytes)
            sodium.memzero(sessionIdBytes)
            if (frame.sessionId !== expectedSessionId) throw new Error('Native host session ID is invalid')

            const shared = sodium.crypto_scalarmult(extensionPrivateKey, hostPublicKey)
            if (shared.every((byte) => byte === 0)) {
              sodium.memzero(shared)
              throw new Error('Native host produced an invalid shared key')
            }
            const salt = await sha256(signedTranscript)
            const info = textEncoder.encode(SESSION_KEYS_INFO)
            try {
              const material = await hkdfSha256(shared, salt, info)
              try {
                const channel = new SecureChannel(
                  expectedSessionId,
                  material.slice(32, 64),
                  material.slice(0, 32),
                  material.slice(88, 112),
                  material.slice(64, 88),
                )
                dispose()
                return channel
              } finally {
                sodium.memzero(material)
              }
            } finally {
              sodium.memzero(shared)
              sodium.memzero(salt)
              sodium.memzero(info)
            }
          } finally {
            sodium.memzero(signedTranscript)
          }
        } finally {
          sodium.memzero(echoedExtensionNonce)
          sodium.memzero(hostNonce)
          sodium.memzero(hostPublicKey)
          sodium.memzero(hostSigningPublicKey)
          sodium.memzero(signature)
        }
      } catch (error) {
        dispose()
        throw error
      }
    },
    dispose,
  }
}
