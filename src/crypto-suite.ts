import type {
  CanonicalEnvelopeAad,
  CryptoSuiteId,
  EncodedSuitePayload,
} from './envelope'
import { wipe } from './sodium'
import { loadSodium } from './sodium-loader'

export const VAULT_XCHACHA20_POLY1305_V1 =
  'palladin-vault-xchacha-v1' as CryptoSuiteId

const XCHACHA_KEY_BYTES = 32
const XCHACHA_NONCE_BYTES = 24
const XCHACHA_TAG_BYTES = 16
export const MAX_ENCODED_SUITE_PAYLOAD_BYTES = 1024 * 1024

export interface SealSuitePayloadParams {
  plaintext: Uint8Array
  key: Uint8Array
  aad: CanonicalEnvelopeAad
}

export interface OpenSuitePayloadParams {
  payload: EncodedSuitePayload
  key: Uint8Array
  aad: CanonicalEnvelopeAad
}

/** Client-side suite: owns its payload layout and authenticated encryption. */
export interface ClientEnvelopeSuite {
  readonly id: CryptoSuiteId
  seal(params: SealSuitePayloadParams): Promise<EncodedSuitePayload>
  open(params: OpenSuitePayloadParams): Promise<Uint8Array>
  validateEncodedPayload(payload: Uint8Array): EncodedSuitePayload
}

function assertKeyLength(key: Uint8Array): void {
  if (key.length !== XCHACHA_KEY_BYTES) {
    throw new RangeError(`XChaCha20-Poly1305 key must be ${XCHACHA_KEY_BYTES} bytes`)
  }
}

function validateXChaChaPayload(payload: Uint8Array): EncodedSuitePayload {
  const minimum = XCHACHA_NONCE_BYTES + XCHACHA_TAG_BYTES
  if (payload.length < minimum || payload.length > MAX_ENCODED_SUITE_PAYLOAD_BYTES) {
    throw new RangeError(`Encoded suite payload must be between ${minimum} and ${MAX_ENCODED_SUITE_PAYLOAD_BYTES} bytes`)
  }
  return new Uint8Array(payload) as EncodedSuitePayload
}

const xChaCha20Poly1305V1: ClientEnvelopeSuite = {
  id: VAULT_XCHACHA20_POLY1305_V1,
  validateEncodedPayload: validateXChaChaPayload,
  async seal({ plaintext, key, aad }) {
    assertKeyLength(key)
    const sodium = await loadSodium()
    const nonce = sodium.randombytes_buf(XCHACHA_NONCE_BYTES)
    const plaintextCopy = new Uint8Array(plaintext.length)
    plaintextCopy.set(plaintext)
    const keyCopy = new Uint8Array(key.length)
    keyCopy.set(key)
    const aadCopy = new Uint8Array(aad.length)
    aadCopy.set(aad)
    try {
      const ciphertextAndTag = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintextCopy,
        aadCopy,
        null,
        nonce,
        keyCopy,
      )
      const encoded = new Uint8Array(nonce.length + ciphertextAndTag.length)
      encoded.set(nonce)
      encoded.set(ciphertextAndTag, nonce.length)
      return validateXChaChaPayload(encoded)
    } finally {
      wipe(nonce)
      wipe(plaintextCopy)
      wipe(keyCopy)
    }
  },
  async open({ payload, key, aad }) {
    assertKeyLength(key)
    const encoded = validateXChaChaPayload(payload)
    const sodium = await loadSodium()
    const nonce = encoded.slice(0, XCHACHA_NONCE_BYTES)
    const ciphertextAndTag = encoded.slice(XCHACHA_NONCE_BYTES)
    const keyCopy = new Uint8Array(key.length)
    keyCopy.set(key)
    const aadCopy = new Uint8Array(aad.length)
    aadCopy.set(aad)
    try {
      return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertextAndTag,
        aadCopy,
        nonce,
        keyCopy,
      )
    } finally {
      wipe(nonce)
      wipe(ciphertextAndTag)
      wipe(encoded)
      wipe(keyCopy)
    }
  },
}

const SUITES: ReadonlyMap<CryptoSuiteId, ClientEnvelopeSuite> = new Map([
  [xChaCha20Poly1305V1.id, xChaCha20Poly1305V1],
])

/** Resolve only compiled-in suites. Unknown or downgraded identifiers fail closed. */
export function requireCryptoSuite(id: string): ClientEnvelopeSuite {
  const suite = SUITES.get(id as CryptoSuiteId)
  if (!suite) throw new Error(`Unsupported crypto suite: ${id}`)
  return suite
}
