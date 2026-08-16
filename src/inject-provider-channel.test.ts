import { describe, expect, it } from 'vitest'
import { fromBase64Url, toBase64Url } from './encoding'
import {
  createInjectClientSession,
  injectHostKeyFingerprint,
  INJECT_PROVIDER_PROTOCOL,
  type InjectSecureFrame,
  type InjectSessionOpen,
  type InjectSessionReady,
} from './inject-provider-channel'
import { loadSodium } from './sodium-loader'

const encoder = new TextEncoder()

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

function hostTranscript(
  origin: string,
  open: InjectSessionOpen,
  hostNonce: Uint8Array,
  hostPublicKey: Uint8Array,
  signingPublicKey: Uint8Array,
): Uint8Array {
  return concat(
    encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-v1\0`),
    prefixed(encoder.encode(origin)),
    prefixed(fromBase64Url(open.extensionNonce)),
    prefixed(fromBase64Url(open.extensionEphemeralPublicKey)),
    prefixed(hostNonce),
    prefixed(hostPublicKey),
    prefixed(signingPublicKey),
  )
}

function nonce(base: Uint8Array, sequence: bigint): Uint8Array {
  const output = new Uint8Array(base)
  const sequenceBytes = u64be(sequence)
  for (let index = 0; index < 8; index++) output[16 + index] ^= sequenceBytes[index]
  return output
}

function aad(sessionId: string, direction: string, sequence: bigint): Uint8Array {
  return concat(
    encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-secure-frame-v1\0`),
    encoder.encode(sessionId),
    new Uint8Array([0]),
    encoder.encode(direction),
    new Uint8Array([0]),
    u64be(sequence),
  )
}

async function sha256(value: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(value.length)
  copy.set(value)
  return new Uint8Array(await crypto.subtle.digest('SHA-256', copy.buffer))
}

async function deriveHostMaterial(shared: Uint8Array, transcript: Uint8Array): Promise<Uint8Array> {
  const sodium = await loadSodium()
  const salt = await sha256(transcript)
  const sharedCopy = new Uint8Array(shared.length)
  const saltCopy = new Uint8Array(salt.length)
  sharedCopy.set(shared)
  saltCopy.set(salt)
  const key = await crypto.subtle.importKey('raw', sharedCopy.buffer, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: saltCopy.buffer,
    info: encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-keys-v1\0`),
  }, key, 112 * 8)
  sharedCopy.fill(0)
  saltCopy.fill(0)
  return new Uint8Array(bits)
}

async function readyFor(
  origin: string,
  open: InjectSessionOpen,
  signingKeypair?: { publicKey: Uint8Array; privateKey: Uint8Array },
) {
  const sodium = await loadSodium()
  const signing = signingKeypair ?? sodium.crypto_sign_keypair()
  const hostPrivateKey = sodium.randombytes_buf(32)
  const hostPublicKey = sodium.crypto_scalarmult_base(hostPrivateKey)
  const hostNonce = sodium.randombytes_buf(32)
  const signedTranscript = hostTranscript(origin, open, hostNonce, hostPublicKey, signing.publicKey)
  const signature = sodium.crypto_sign_detached(signedTranscript, signing.privateKey)
  const sessionId = toBase64Url(await sha256(concat(
    encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-id-v1\0`),
    signedTranscript,
    signature,
  )))
  const ready: InjectSessionReady = {
    protocol: INJECT_PROVIDER_PROTOCOL,
    type: 'session.ready',
    extensionNonce: open.extensionNonce,
    hostNonce: toBase64Url(hostNonce),
    hostEphemeralPublicKey: toBase64Url(hostPublicKey),
    hostSigningPublicKey: toBase64Url(signing.publicKey),
    signature: toBase64Url(signature),
    sessionId,
  }
  const shared = sodium.crypto_scalarmult(hostPrivateKey, fromBase64Url(open.extensionEphemeralPublicKey))
  const material = await deriveHostMaterial(shared, signedTranscript)
  return { ready, signing, material, sessionId }
}

async function authenticatedChannel(origin: string) {
  const sodium = await loadSodium()
  const signing = sodium.crypto_sign_keypair()
  const client = await createInjectClientSession({
    protocol: INJECT_PROVIDER_PROTOCOL,
    extensionOrigin: origin,
    pinnedHostSigningPublicKey: toBase64Url(signing.publicKey),
  })
  const host = await readyFor(origin, client.openFrame, signing)
  const channel = await client.acceptReady(host.ready)
  return { channel, host }
}

async function hostFrame(
  host: Awaited<ReturnType<typeof readyFor>>,
  plaintext: Uint8Array,
): Promise<InjectSecureFrame> {
  const sodium = await loadSodium()
  const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad(host.sessionId, 'host-to-extension', 0n),
    null,
    nonce(host.material.slice(64, 88), 0n),
    host.material.slice(0, 32),
  )
  return {
    protocol: INJECT_PROVIDER_PROTOCOL,
    type: 'secure',
    sessionId: host.sessionId,
    sequence: '0',
    ciphertext: toBase64Url(ciphertext),
  }
}

describe('authenticated inject-provider client channel', () => {
  it('authenticates the pinned host and exchanges ordered encrypted frames', async () => {
    const sodium = await loadSodium()
    const origin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/'
    const signing = sodium.crypto_sign_keypair()
    const pinned = toBase64Url(signing.publicKey)
    const client = await createInjectClientSession({
      protocol: INJECT_PROVIDER_PROTOCOL,
      extensionOrigin: origin,
      pinnedHostSigningPublicKey: pinned,
    })

    const hostPrivateKey = sodium.randombytes_buf(32)
    const hostPublicKey = sodium.crypto_scalarmult_base(hostPrivateKey)
    const hostNonce = sodium.randombytes_buf(32)
    const signedTranscript = hostTranscript(origin, client.openFrame, hostNonce, hostPublicKey, signing.publicKey)
    const signature = sodium.crypto_sign_detached(signedTranscript, signing.privateKey)
    const sessionId = toBase64Url(await sha256(concat(
      encoder.encode(`${INJECT_PROVIDER_PROTOCOL}\0extension-session-id-v1\0`),
      signedTranscript,
      signature,
    )))
    const ready: InjectSessionReady = {
      protocol: INJECT_PROVIDER_PROTOCOL,
      type: 'session.ready',
      extensionNonce: client.openFrame.extensionNonce,
      hostNonce: toBase64Url(hostNonce),
      hostEphemeralPublicKey: toBase64Url(hostPublicKey),
      hostSigningPublicKey: pinned,
      signature: toBase64Url(signature),
      sessionId,
    }
    const shared = sodium.crypto_scalarmult(
      hostPrivateKey,
      fromBase64Url(client.openFrame.extensionEphemeralPublicKey),
    )
    const material = await deriveHostMaterial(shared, signedTranscript)
    const channel = await client.acceptReady(ready)

    const hostPlaintext = encoder.encode('{"type":"inject"}')
    const hostCiphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      hostPlaintext,
      aad(sessionId, 'host-to-extension', 0n),
      null,
      nonce(material.slice(64, 88), 0n),
      material.slice(0, 32),
    )
    const hostFrame: InjectSecureFrame = {
      protocol: INJECT_PROVIDER_PROTOCOL,
      type: 'secure',
      sessionId,
      sequence: '0',
      ciphertext: toBase64Url(hostCiphertext),
    }
    await expect(channel.open(hostFrame)).resolves.toEqual(hostPlaintext)
    await expect(channel.open(hostFrame)).rejects.toThrow(/replayed|out of order/)

    const extensionPlaintext = encoder.encode('{"outcome":"filled"}')
    const extensionFrame = await channel.seal(extensionPlaintext)
    expect(extensionFrame.sequence).toBe('0')
    expect(sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      fromBase64Url(extensionFrame.ciphertext),
      aad(sessionId, 'extension-to-host', 0n),
      nonce(material.slice(88, 112), 0n),
      material.slice(32, 64),
    )).toEqual(extensionPlaintext)

    channel.dispose()
    await expect(channel.seal(extensionPlaintext)).rejects.toThrow(/disposed/)
  })

  it('fails closed on an unpaired identity and invalidates the attempted session', async () => {
    const sodium = await loadSodium()
    const origin = 'moz-extension://12345678-abcd-4abc-8def-123456789abc/'
    const pinned = sodium.crypto_sign_keypair()
    const client = await createInjectClientSession({
      protocol: INJECT_PROVIDER_PROTOCOL,
      extensionOrigin: origin,
      pinnedHostSigningPublicKey: toBase64Url(pinned.publicKey),
    })
    const unpaired = await readyFor(origin, client.openFrame)

    await expect(client.acceptReady(unpaired.ready)).rejects.toThrow(/paired key/)
    await expect(client.acceptReady(unpaired.ready)).rejects.toThrow(/disposed/)
  })

  it('claims a ready frame synchronously so concurrent accepts cannot create duplicate channels', async () => {
    const sodium = await loadSodium()
    const origin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/'
    const signing = sodium.crypto_sign_keypair()
    const client = await createInjectClientSession({
      protocol: INJECT_PROVIDER_PROTOCOL,
      extensionOrigin: origin,
      pinnedHostSigningPublicKey: toBase64Url(signing.publicKey),
    })
    const host = await readyFor(origin, client.openFrame, signing)

    const accepted = client.acceptReady(host.ready)
    const replayed = client.acceptReady(host.ready)

    await expect(replayed).rejects.toThrow(/already accepting/)
    const channel = await accepted
    channel.dispose()
  })

  it('fails an in-flight ready acceptance when its session is disposed', async () => {
    const sodium = await loadSodium()
    const origin = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop/'
    const signing = sodium.crypto_sign_keypair()
    const client = await createInjectClientSession({
      protocol: INJECT_PROVIDER_PROTOCOL,
      extensionOrigin: origin,
      pinnedHostSigningPublicKey: toBase64Url(signing.publicKey),
    })
    const host = await readyFor(origin, client.openFrame, signing)

    const accepting = client.acceptReady(host.ready)
    client.dispose()

    await expect(accepting).rejects.toThrow(/disposed/)
  })

  it('accepts a secure frame only once when identical opens run concurrently', async () => {
    const { channel, host } = await authenticatedChannel(
      'chrome-extension://abcdefghijklmnopabcdefghijklmnop/',
    )
    const frame = await hostFrame(host, encoder.encode('one delivery'))

    const first = channel.open(frame)
    const replay = channel.open(frame)

    await expect(first).resolves.toEqual(encoder.encode('one delivery'))
    await expect(replay).rejects.toThrow(/replayed|out of order/)
    channel.dispose()
  })

  it('does not use wiped channel keys when dispose races with seal or open', async () => {
    const sealing = await authenticatedChannel(
      'chrome-extension://abcdefghijklmnopabcdefghijklmnop/',
    )
    const pendingSeal = sealing.channel.seal(encoder.encode('never sealed'))
    sealing.channel.dispose()
    await expect(pendingSeal).rejects.toThrow(/disposed/)

    const opening = await authenticatedChannel(
      'chrome-extension://abcdefghijklmnopabcdefghijklmnop/',
    )
    const frame = await hostFrame(opening.host, encoder.encode('never opened'))
    const pendingOpen = opening.channel.open(frame)
    opening.channel.dispose()
    await expect(pendingOpen).rejects.toThrow(/disposed/)
  })

  it('derives a canonical pairing fingerprint and rejects malformed origins and keys', async () => {
    const sodium = await loadSodium()
    const signing = sodium.crypto_sign_keypair()
    await expect(injectHostKeyFingerprint(toBase64Url(signing.publicKey))).resolves.toBe(
      toBase64Url(await sha256(signing.publicKey)),
    )
    await expect(createInjectClientSession({
      protocol: INJECT_PROVIDER_PROTOCOL,
      extensionOrigin: 'https://example.com',
      pinnedHostSigningPublicKey: toBase64Url(signing.publicKey),
    })).rejects.toThrow(/origin/)
    await expect(createInjectClientSession({
      protocol: INJECT_PROVIDER_PROTOCOL,
      extensionOrigin: 'safari-web-extension://com.palladin.extension/',
      pinnedHostSigningPublicKey: 'not+base64',
    })).rejects.toThrow(/base64url/)
  })
})
