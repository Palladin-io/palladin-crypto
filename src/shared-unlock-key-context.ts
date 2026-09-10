import { toBase64Url } from './encoding'

export const SHARED_UNLOCK_KEY_CONTEXT_PROTOCOL = 'palladin.shared-unlock.key-context.v1' as const

/** Current account material returned directly by Identity. This descriptor is
 * never accepted from an encrypted envelope or from a peer as its own authority. */
export interface SharedUnlockKeyContext {
  accountId: string
  securityVersion: number
  minimumSecurityVersion: number
  kdfProfileId: string
  kdfSalt: string
  credentialRevision: number
  privateKeyWrapRevision: number
  memberKeyVersion: number
  publicKey: string
  encryptedPrivateKey: string
}

const fields = ['accountId', 'securityVersion', 'minimumSecurityVersion', 'kdfProfileId',
  'kdfSalt', 'credentialRevision', 'privateKeyWrapRevision', 'memberKeyVersion',
  'publicKey', 'encryptedPrivateKey'] as const

/** Canonical encoding of Identity's typed descriptor, not an API response validator.
 * Account selection, current operation and browser authority belong to the adapter. */
export function encodeSharedUnlockKeyContext(expected: SharedUnlockKeyContext): Uint8Array {
  const encoder = new TextEncoder()
  const parts = [SHARED_UNLOCK_KEY_CONTEXT_PROTOCOL, ...fields.map(field => expected[field])]
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

/** Compare this digest with the independently authorized MK operation context.
 * Passing that comparison does not authorize session issuance or MK installation. */
export async function hashSharedUnlockKeyContext(expected: SharedUnlockKeyContext): Promise<string> {
  const encoded = new Uint8Array(encodeSharedUnlockKeyContext(expected))
  return toBase64Url(new Uint8Array(await crypto.subtle.digest('SHA-256', encoded)))
}
