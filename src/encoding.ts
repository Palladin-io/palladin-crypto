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
