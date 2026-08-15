/**
 * Binary <-> base64 helpers for the zero-knowledge crypto layer.
 *
 * The backend contract exchanges all key material as base64 strings
 * (JSON serialises `byte[]` this way). Keeping the conversion here avoids
 * scattering btoa/atob throughout the feature code.
 */

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/** Canonical RFC 4648 base64url without padding, used by Vault protocol 2. */
export function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

/**
 * Decode only canonical, unpadded base64url. Legacy padded/base64 fails closed.
 * When supplied, `maximumBytes` is enforced from the encoded length before
 * `atob` allocates the decoded string, and again against the decoded result.
 */
export function fromBase64Url(value: string, maximumBytes?: number): Uint8Array {
  if (maximumBytes !== undefined) {
    if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
      throw new TypeError('Base64url byte limit must be a non-negative safe integer')
    }
    if (value.length > Math.ceil(maximumBytes * 4 / 3)) {
      throw new RangeError('Canonical base64url exceeds the permitted size')
    }
  }
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) {
    throw new TypeError('Invalid canonical base64url')
  }
  const padding = '='.repeat((4 - (value.length % 4)) % 4)
  const decoded = fromBase64(value.replaceAll('-', '+').replaceAll('_', '/') + padding)
  if (maximumBytes !== undefined && decoded.length > maximumBytes) {
    throw new RangeError('Decoded base64url exceeds the permitted size')
  }
  if (toBase64Url(decoded) !== value) throw new TypeError('Non-canonical base64url')
  return decoded
}
