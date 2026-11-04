import { fromBase64Url, toBase64Url } from './encoding'
import { ACCOUNT_SECRET_BYTES, encodeCrockfordBits } from './identity-account-secret'
import {
  generateXWingSeed,
  openWithSingleUseKey,
  sealWithSingleUseKey,
  XWING_CIPHERTEXT_BYTES,
  XWING_PUBLIC_KEY_BYTES,
  XWING_SEED_BYTES,
  xwingDecapsulate,
  xwingEncapsulate,
  xwingPublicKey,
} from './key-wrapper/suites/xwing-kem'
import { equalBytes } from './key-wrapper/suites/x25519-sealed-box-v1'
import { deriveHkdfSha256, sha256Digest } from './portable-sha256'
import { getCryptoProvider } from './provider/active-provider'
import { wipe } from './sodium'
import { concatBytes, decodeUuid, encodeU16, encodeUtf8 } from './vault-v2-bytes'

/** Device pairing protocol 2 of palladin-protocol `identity-kdf/v3` (Secret Key transfer). */
export const DEVICE_PAIRING_PROTOCOL_VERSION = 2

export type PairingErrorCode =
  | 'malformed-qr'
  | 'malformed-envelope'
  | 'sas-not-confirmed'
  | 'recipient-key-digest-mismatch'
  | 'aead-failure'

/** Carries only a contract error code; never key material. */
export class PairingError extends Error {
  readonly code: PairingErrorCode

  constructor(code: PairingErrorCode) {
    super(code)
    this.name = 'PairingError'
    this.code = code
  }
}

export interface PairingKeyPair {
  publicKey: Uint8Array
  /** 32-byte seed. Memory only; `wipe` when the transfer ends. */
  privateKey: Uint8Array
}

export type PairingQr =
  | { flow: 'recipient-shows-qr', transferId: string, recipientPublicKeyDigest: string }
  | { flow: 'sender-shows-qr', transferId: string, challenge: string }

/**
 * Session values both devices agree on. `transferId` and `challenge` are the
 * canonical base64url values of the session; `recipientPublicKey` is the key
 * the backend relays for that session.
 */
export interface PairingSession {
  accountId: string
  transferId: string
  challenge: string
  recipientPublicKey: Uint8Array
}

export interface PairingEnvelope {
  kemCiphertext: string
  ciphertext: string
}

const VERSION = encodeU16(DEVICE_PAIRING_PROTOCOL_VERSION)
const OFFER_MAGIC = encodeUtf8('PLDNID3DO')
const TRANSCRIPT_MAGIC = encodeUtf8('PLDNID3DT')
const AAD_MAGIC = encodeUtf8('PLDNID3DA')
const KEK_INFO = encodeUtf8('palladin:identity:v3:device-pairing-account-secret')
const QR_PREFIX = { 'recipient-shows-qr': 'palladin-pair:v2:r:', 'sender-shows-qr': 'palladin-pair:v2:s:' } as const
const TRANSFER_ID_BYTES = 16
const CHALLENGE_BYTES = 32
const DIGEST_BYTES = 32
const CIPHERTEXT_BYTES = ACCOUNT_SECRET_BYTES + 16

function exact(value: unknown, length: number, code: PairingErrorCode): Uint8Array {
  try {
    if (typeof value === 'string') {
      const bytes = fromBase64Url(value, length)
      if (bytes.length === length) return bytes
    }
  } catch { /* mapped below */ }
  throw new PairingError(code)
}

function sessionBytes(session: PairingSession) {
  if (!(session.recipientPublicKey instanceof Uint8Array) || session.recipientPublicKey.length !== XWING_PUBLIC_KEY_BYTES) {
    throw new PairingError('recipient-key-digest-mismatch')
  }
  return {
    accountId: decodeUuid(session.accountId),
    transferId: exact(session.transferId, TRANSFER_ID_BYTES, 'malformed-envelope'),
    challenge: exact(session.challenge, CHALLENGE_BYTES, 'malformed-envelope'),
    recipientDigest: sha256Digest(session.recipientPublicKey),
  }
}

function transcriptHash(session: PairingSession, kemCiphertext: Uint8Array): Uint8Array {
  const { accountId, transferId, challenge, recipientDigest } = sessionBytes(session)
  return sha256Digest(concatBytes(
    TRANSCRIPT_MAGIC, VERSION, accountId, transferId, challenge, recipientDigest, sha256Digest(kemCiphertext),
  ))
}

/** Fresh X-Wing key pair for the new device; never persisted. */
export async function generatePairingKeyPair(): Promise<PairingKeyPair> {
  await getCryptoProvider().ready()
  const privateKey = await generateXWingSeed()
  return { privateKey, publicKey: xwingPublicKey(privateKey) }
}

export function encodePairingQr(qr: PairingQr): string {
  const value = qr.flow === 'recipient-shows-qr' ? qr.recipientPublicKeyDigest : qr.challenge
  exact(qr.transferId, TRANSFER_ID_BYTES, 'malformed-qr')
  exact(value, qr.flow === 'recipient-shows-qr' ? DIGEST_BYTES : CHALLENGE_BYTES, 'malformed-qr')
  return `${QR_PREFIX[qr.flow]}${qr.transferId}.${value}`
}

export function parsePairingQr(payload: string): PairingQr {
  if (typeof payload !== 'string' || payload.length > 128) throw new PairingError('malformed-qr')
  for (const flow of ['recipient-shows-qr', 'sender-shows-qr'] as const) {
    if (!payload.startsWith(QR_PREFIX[flow])) continue
    const parts = payload.slice(QR_PREFIX[flow].length).split('.')
    if (parts.length !== 2) break
    const [transferId, value] = parts
    exact(transferId, TRANSFER_ID_BYTES, 'malformed-qr')
    exact(value, flow === 'sender-shows-qr' ? CHALLENGE_BYTES : DIGEST_BYTES, 'malformed-qr')
    return flow === 'sender-shows-qr'
      ? { flow, transferId, challenge: value }
      : { flow, transferId, recipientPublicKeyDigest: value }
  }
  throw new PairingError('malformed-qr')
}

/** Canonical base64url SHA-256 of a recipient public key, as carried in the recipient QR. */
export function pairingRecipientKeyDigest(recipientPublicKey: Uint8Array): string {
  if (recipientPublicKey.length !== XWING_PUBLIC_KEY_BYTES) throw new PairingError('recipient-key-digest-mismatch')
  return toBase64Url(sha256Digest(recipientPublicKey))
}

export function encodePairingOffer(session: PairingSession): Uint8Array {
  const { accountId, transferId, challenge, recipientDigest } = sessionBytes(session)
  return concatBytes(OFFER_MAGIC, VERSION, accountId, transferId, challenge, recipientDigest)
}

/** Short authentication string both devices display, e.g. `942en-qbszg`. */
export function computePairingSas(session: PairingSession): string {
  const symbols = encodeCrockfordBits(sha256Digest(encodePairingOffer(session)), 50).toLowerCase()
  return `${symbols.slice(0, 5)}-${symbols.slice(5)}`
}

export type SealPairingInput = PairingSession & {
  /** The user confirmed that both devices show the same SAS. */
  sasConfirmed: true
} & (
  /** The digest scanned from the recipient's QR must match the key the backend relays. */
  | { flow: 'recipient-shows-qr', scannedRecipientPublicKeyDigest: string }
  | { flow: 'sender-shows-qr' }
)

/** Sender side: seals the Account Secret to the recipient after SAS confirmation. */
export async function sealAccountSecretForPairing(
  input: SealPairingInput,
  accountSecret: Uint8Array,
): Promise<PairingEnvelope> {
  if (input.sasConfirmed !== true) throw new PairingError('sas-not-confirmed')
  if (input.flow === 'recipient-shows-qr') {
    const scanned = exact(input.scannedRecipientPublicKeyDigest, DIGEST_BYTES, 'recipient-key-digest-mismatch')
    if (!equalBytes(scanned, sha256Digest(input.recipientPublicKey))) throw new PairingError('recipient-key-digest-mismatch')
  } else if (input.flow !== 'sender-shows-qr') {
    throw new PairingError('malformed-qr')
  }
  if (accountSecret.length !== ACCOUNT_SECRET_BYTES) throw new TypeError('Invalid Account Secret length')
  sessionBytes(input)
  await getCryptoProvider().ready()
  const { kemCiphertext, sharedSecret } = await xwingEncapsulate(input.recipientPublicKey)
  const transcript = transcriptHash(input, kemCiphertext)
  const kek = deriveHkdfSha256(sharedSecret, transcript, KEK_INFO)
  try {
    return {
      kemCiphertext: toBase64Url(kemCiphertext),
      ciphertext: toBase64Url(sealWithSingleUseKey(kek, concatBytes(AAD_MAGIC, transcript), accountSecret)),
    }
  } finally {
    wipe(sharedSecret)
    wipe(kek)
  }
}

/**
 * Recipient side: opens the envelope with the in-memory pairing key. The
 * session values must be the ones this device created or scanned, not values
 * echoed by the claim response.
 */
export async function openPairingEnvelope(
  session: Omit<PairingSession, 'recipientPublicKey'>,
  keyPair: PairingKeyPair,
  envelope: PairingEnvelope,
): Promise<Uint8Array> {
  if (keyPair.privateKey.length !== XWING_SEED_BYTES) throw new PairingError('aead-failure')
  const kemCiphertext = exact(envelope?.kemCiphertext, XWING_CIPHERTEXT_BYTES, 'malformed-envelope')
  const ciphertext = exact(envelope?.ciphertext, CIPHERTEXT_BYTES, 'malformed-envelope')
  await getCryptoProvider().ready()
  const recipientPublicKey = xwingPublicKey(keyPair.privateKey)
  const transcript = transcriptHash({ ...session, recipientPublicKey }, kemCiphertext)
  let sharedSecret: Uint8Array | undefined
  let kek: Uint8Array | undefined
  try {
    sharedSecret = xwingDecapsulate(kemCiphertext, keyPair.privateKey)
    kek = deriveHkdfSha256(sharedSecret, transcript, KEK_INFO)
    return openWithSingleUseKey(kek, concatBytes(AAD_MAGIC, transcript), ciphertext)
  } catch {
    throw new PairingError('aead-failure')
  } finally {
    if (sharedSecret) wipe(sharedSecret)
    if (kek) wipe(kek)
  }
}
