import { describe, expect, it } from 'vitest'
import { fromBase64Url, toBase64Url } from './encoding'
import { INJECT_PROVIDER_PROTOCOL } from './inject-provider-channel'
import { loadSodium } from './sodium-loader'
import vector from './vectors/inject-provider-secure-session.json'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

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
  const output = new Uint8Array(4)
  new DataView(output.buffer).setUint32(0, value, false)
  return output
}

function u64be(value: bigint): Uint8Array {
  const output = new Uint8Array(8)
  new DataView(output.buffer).setBigUint64(0, value, false)
  return output
}

function prefixed(value: Uint8Array): Uint8Array {
  return concat(u32be(value.length), value)
}

function transcript(): Uint8Array {
  return concat(
    encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-v1\0`),
    prefixed(encoder.encode(vector.extensionOrigin)),
    prefixed(fromBase64Url(vector.open.extensionNonce)),
    prefixed(fromBase64Url(vector.open.extensionEphemeralPublicKey)),
    prefixed(fromBase64Url(vector.ready.hostNonce)),
    prefixed(fromBase64Url(vector.ready.hostEphemeralPublicKey)),
    prefixed(fromBase64Url(vector.ready.hostSigningPublicKey)),
  )
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(value.length)
  copy.set(value)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', copy.buffer))
}

async function derive(shared: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(shared.length)
  const saltCopy = new Uint8Array(salt.length)
  copy.set(shared)
  saltCopy.set(salt)
  const key = await crypto.subtle.importKey('raw', copy.buffer, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: saltCopy.buffer,
    info: encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-keys-v1\0`),
  }, key, 112 * 8))
}

function nonce(base: Uint8Array): Uint8Array {
  const output = new Uint8Array(base)
  const sequence = u64be(0n)
  for (let index = 0; index < 8; index++) output[16 + index] ^= sequence[index]
  return output
}

function aad(direction: 'host-to-extension' | 'extension-to-host'): Uint8Array {
  return concat(
    encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-secure-frame-v1\0`),
    encoder.encode(vector.ready.sessionId),
    new Uint8Array([0]),
    encoder.encode(direction),
    new Uint8Array([0]),
    u64be(0n),
  )
}

describe('Rust inject-provider secure-session vector', () => {
  it('matches the signed transcript, session ID, key schedule, and first frames', async () => {
    const sodium = await loadSodium()
    expect(vector.protocol).toBe(INJECT_PROVIDER_PROTOCOL)
    const extensionPrivateKey = fromBase64Url(vector.syntheticInputs.extensionEphemeralSecretKey)
    const hostPrivateKey = fromBase64Url(vector.syntheticInputs.hostEphemeralSecretKey)
    const signingSeed = fromBase64Url(vector.syntheticInputs.hostSigningSecretKey)
    const signing = sodium.crypto_sign_seed_keypair(signingSeed)

    expect(toBase64Url(sodium.crypto_scalarmult_base(extensionPrivateKey)))
      .toBe(vector.open.extensionEphemeralPublicKey)
    expect(toBase64Url(sodium.crypto_scalarmult_base(hostPrivateKey)))
      .toBe(vector.ready.hostEphemeralPublicKey)
    expect(toBase64Url(signing.publicKey)).toBe(vector.ready.hostSigningPublicKey)

    const signedTranscript = transcript()
    const signature = fromBase64Url(vector.ready.signature)
    expect(sodium.crypto_sign_verify_detached(signature, signedTranscript, signing.publicKey)).toBe(true)
    expect(toBase64Url(await sha256(concat(
      encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-id-v1\0`),
      signedTranscript,
      signature,
    )))).toBe(vector.ready.sessionId)

    const shared = sodium.crypto_scalarmult(extensionPrivateKey, fromBase64Url(vector.ready.hostEphemeralPublicKey))
    const material = await derive(shared, await sha256(signedTranscript))

    const hostPlaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64Url(vector.firstHostFrame.ciphertext),
      aad('host-to-extension'),
      nonce(material.slice(64, 88)),
      material.slice(0, 32),
    )
    expect(JSON.parse(decoder.decode(hostPlaintext))).toEqual(vector.firstHostPlaintext)

    const extensionPlaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64Url(vector.firstExtensionFrame.ciphertext),
      aad('extension-to-host'),
      nonce(material.slice(88, 112)),
      material.slice(32, 64),
    )
    expect(JSON.parse(decoder.decode(extensionPlaintext))).toEqual(vector.firstExtensionPlaintext)
  })
})
