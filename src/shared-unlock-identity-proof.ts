import { loadSodium } from './sodium-loader'
import { fromBase64Url, toBase64Url } from './encoding'

export const SHARED_UNLOCK_IDENTITY_PROOF_PROTOCOL = 'palladin.shared-unlock.identity-proof.v1' as const
export type SharedUnlockProofPurpose = 'consume' | 'commit'
export interface SharedUnlockIdentityProofContext {
  operationId: string
  challenge: string
  transcriptHash: string
  issuedAtMs: number
  expiresAtMs: number
}
const fields = ['operationId', 'challenge', 'transcriptHash', 'issuedAtMs', 'expiresAtMs'] as const
function reject(): never { throw new Error('Shared unlock Identity proof rejected') }
function binary(value: unknown): string {
  if (typeof value !== 'string') reject()
  try { if (fromBase64Url(value, 32).length !== 32) reject() } catch { reject() }
  return value
}
function snapshot(value: SharedUnlockIdentityProofContext): Readonly<SharedUnlockIdentityProofContext> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.keys(value).length !== fields.length || Object.keys(value).some(key => !fields.includes(key as typeof fields[number])) ||
    typeof value.operationId !== 'string' || !/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(value.operationId) ||
    value.operationId === '00000000-0000-0000-0000-000000000000' ||
    !Number.isSafeInteger(value.issuedAtMs) || !Number.isSafeInteger(value.expiresAtMs) ||
    value.issuedAtMs <= 0 || value.expiresAtMs <= value.issuedAtMs || value.expiresAtMs - value.issuedAtMs > 30_000) reject()
  binary(value.challenge)
  binary(value.transcriptHash)
  return Object.freeze({ ...value })
}
export function encodeSharedUnlockIdentityProof(
  expected: SharedUnlockIdentityProofContext,
  recipientProofPublicKey: string,
  purpose: SharedUnlockProofPurpose,
): Uint8Array {
  const c = snapshot(expected)
  binary(recipientProofPublicKey)
  if (purpose !== 'consume' && purpose !== 'commit') reject()
  const encoder = new TextEncoder()
  const parts = [SHARED_UNLOCK_IDENTITY_PROOF_PROTOCOL, purpose, c.operationId,
    c.challenge, c.transcriptHash, recipientProofPublicKey, c.issuedAtMs, c.expiresAtMs]
    .map(value => encoder.encode(String(value)))
  const output = new Uint8Array(parts.reduce((n, part) => n + part.length + 4, 0))
  const view = new DataView(output.buffer)
  let offset = 0
  for (const part of parts) {
    view.setUint32(offset, part.length, false)
    output.set(part, offset + 4)
    offset += part.length + 4
  }
  return output
}
export interface SharedUnlockIdentityProofSigner {
  readonly publicKey: string
  sign(expected: SharedUnlockIdentityProofContext, purpose: SharedUnlockProofPurpose): string
  dispose(): void
}

/** Generate before authorizing a handoff and bind publicKey through the verified
 * browser route. Sign consume, then commit, at most once each for one operation.
 * assertCurrent must use independent Identity/browser/lifecycle authority; this
 * helper cannot prove a browser identity or replace server-side single consume.
 * The private signing key remains RAM-only and is wiped on commit or any error. */
export async function createSharedUnlockIdentityProofSigner(options: {
  assertCurrent: (expected: Readonly<SharedUnlockIdentityProofContext>) => void
  now?: () => number
}): Promise<SharedUnlockIdentityProofSigner> {
  const { assertCurrent } = options
  if (typeof assertCurrent !== 'function') reject()
  const now = options.now ?? Date.now
  const sodium = await loadSodium()
  const pair = sodium.crypto_sign_keypair()
  const publicKey = toBase64Url(pair.publicKey)
  let stage: 'initial' | 'consumed' | 'disposed' = 'initial'
  let bound: Readonly<SharedUnlockIdentityProofContext> | undefined
  function dispose() { stage = 'disposed'; sodium.memzero(pair.privateKey) }
  return {
    publicKey, dispose,
    sign(expected, purpose) {
      try {
        if (stage === 'disposed' || (stage === 'initial' ? purpose !== 'consume' : purpose !== 'commit')) reject()
        const current = snapshot(expected)
        if (bound && fields.some(field => bound![field] !== current[field])) reject()
        const time = now()
        if (!Number.isSafeInteger(time) || time < current.issuedAtMs || time >= current.expiresAtMs) reject()
        assertCurrent(current)
        // No asynchronous boundary between the authority check and signing.
        // Reentrant disposal by an adapter callback still cancels the operation.
        if ((stage as string) === 'disposed') reject()
        const signature = sodium.crypto_sign_detached(encodeSharedUnlockIdentityProof(current, publicKey, purpose), pair.privateKey)
        bound = current
        stage = 'consumed'
        if (purpose === 'commit') dispose()
        return toBase64Url(signature)
      } catch { dispose(); return reject() }
    },
  }
}
