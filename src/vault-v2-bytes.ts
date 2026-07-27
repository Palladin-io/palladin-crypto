const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const BASE64URL = /^[A-Za-z0-9_-]*$/

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0))
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

export function encodeU16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error('u16 out of range')
  const result = new Uint8Array(2)
  new DataView(result.buffer).setUint16(0, value, false)
  return result
}

export function encodeU32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new Error('u32 out of range')
  const result = new Uint8Array(4)
  new DataView(result.buffer).setUint32(0, value, false)
  return result
}

export function encodeU64(value: string | bigint): Uint8Array {
  const parsed = typeof value === 'bigint' ? value : BigInt(value)
  if (parsed < 0n || parsed > 0xffffffffffffffffn) throw new Error('u64 out of range')
  if (typeof value === 'string' && value !== parsed.toString()) throw new Error('u64 must be canonical decimal')
  const result = new Uint8Array(8)
  new DataView(result.buffer).setBigUint64(0, parsed, false)
  return result
}

export function decodeUuid(value: string): Uint8Array {
  if (!CANONICAL_UUID.test(value)) throw new Error('UUID must be canonical lowercase RFC 4122 text')
  return decodeHex(value.replaceAll('-', ''))
}

export function decodeHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) throw new Error('invalid lowercase hex')
  return Uint8Array.from(value.match(/.{2}/g)?.map((byte) => Number.parseInt(byte, 16)) ?? [])
}

export function encodeHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function decodeBase64Url(value: string, maximumBytes?: number): Uint8Array {
  if (!BASE64URL.test(value) || value.includes('=')) throw new Error('invalid unpadded base64url')
  if (maximumBytes !== undefined && value.length > Math.ceil(maximumBytes * 4 / 3)) throw new Error('base64url payload exceeds limit')
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4)
  const decoded = atob(padded)
  const bytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0))
  if (maximumBytes !== undefined && bytes.length > maximumBytes) throw new Error('decoded payload exceeds limit')
  if (encodeBase64Url(bytes) !== value) throw new Error('non-canonical base64url')
  return bytes
}

export function encodeBase64Url(value: Uint8Array): string {
  let binary = ''
  for (const byte of value) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export function encodeUtf8(value: string): Uint8Array {
  if (value.normalize('NFC') !== value || value.includes('\0')) throw new Error('string must be NFC without NUL')
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) {
        throw new Error('string contains an unpaired UTF-16 surrogate')
      }
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new Error('string contains an unpaired UTF-16 surrogate')
    }
  }
  return new TextEncoder().encode(value)
}

