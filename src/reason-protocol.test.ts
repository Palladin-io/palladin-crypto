import { afterEach, describe, expect, it, vi } from 'vitest'
import { ENVELOPE_PURPOSE } from './envelope'
import { openEncryptedReason, verifyEncryptedReasonSignature, type EncryptedReasonContract } from './reason-protocol'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { computeRecipientFingerprint, encodeKeyWrapperContext, generateRecipientKeyPair, sealKey, type KeyWrapperDescriptor } from './key-wrapper/key-wrapper'
import { wrapperContextHash } from './key-wrapper/context'
import { KEY_WRAPPER_SUITE } from './key-wrapper/registry'
import { x25519SealedBoxV1 } from './key-wrapper/suites/x25519-sealed-box-v1'
import { fingerprint32ByteKey, SIGNING_KEY_KIND } from './signing-key-fingerprint'
import { loadSodium } from './sodium-loader'
import { wipe } from './sodium'
import { toBase64, toBase64Url } from './encoding'
import { deriveVaultSubkey } from './hkdf'

describe('openEncryptedReason', () => {
  it('matches the frozen Rust ReasonDEK-to-payload-key vector', async () => {
    const key = await deriveVaultSubkey(new Uint8Array(32).fill(3), {
      protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
      purpose: ENVELOPE_PURPOSE.reason,
      organizationId: '00112233-4455-6677-8899-aabbccddeeff',
      vaultId: '11112222-3333-4444-8555-666677778888',
      entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      grantOrRequestId: '12345678-1234-4234-8234-1234567890ab',
      agentId: 'fedcba98-7654-4321-8765-abcdefabcdef',
      keyVersion: 3, memberKeyGeneration: 9,
    })
    expect(Array.from(key).map((v) => v.toString(16).padStart(2, '0')).join('')).toBe(
      '5fd3de62b3f68eceec8e8ba4ada75ba348ad57095b99abb702c3fb3ccd305ed3',
    )
    wipe(key)
  })
  it('verifies the backend-compatible Ed25519 transcript and rejects tampering', async () => {
    const sodium = await loadSodium()
    const signing = sodium.crypto_sign_keypair()
    const descriptor = new Uint8Array([1, 2, 3])
    const payload = new Uint8Array([4, 5])
    const wrapper = new Uint8Array([6, 7, 8])
    const prefix = new TextEncoder().encode('PLDNV2SIG:ENCRYPTED-REASON:')
    const suite = new TextEncoder().encode(KEY_WRAPPER_SUITE.active)
    const transcript = new Uint8Array(prefix.length + 2 + descriptor.length + payload.length + 2 + suite.length + wrapper.length)
    let offset = 0
    transcript.set(prefix, offset); offset += prefix.length
    new DataView(transcript.buffer).setUint16(offset, 2); offset += 2
    transcript.set(descriptor, offset); offset += descriptor.length
    transcript.set(payload, offset); offset += payload.length
    new DataView(transcript.buffer).setUint16(offset, suite.length); offset += 2
    transcript.set(suite, offset); offset += suite.length
    transcript.set(wrapper, offset)
    const fingerprint = fingerprint32ByteKey(signing.publicKey, SIGNING_KEY_KIND.agentSigning)
    const identity = { publicKey: toBase64(signing.publicKey), keyVersion: 1, keyFingerprint: toBase64Url(fingerprint) }
    const signature = sodium.crypto_sign_detached(transcript, signing.privateKey)
    try {
      await expect(verifyEncryptedReasonSignature(
        descriptor, toBase64Url(payload), KEY_WRAPPER_SUITE.active, toBase64Url(wrapper), toBase64Url(signature), identity,
      )).resolves.toBeUndefined()
      await expect(verifyEncryptedReasonSignature(
        descriptor, toBase64Url(new Uint8Array([4, 9])), KEY_WRAPPER_SUITE.active, toBase64Url(wrapper), toBase64Url(signature), identity,
      )).rejects.toThrow('signature is invalid')
      await expect(verifyEncryptedReasonSignature(
        descriptor, toBase64Url(payload), KEY_WRAPPER_SUITE.legacy, toBase64Url(wrapper), toBase64Url(signature), identity,
      )).rejects.toThrow('signature is invalid')
    } finally {
      wipe(signing.privateKey); wipe(signing.publicKey); wipe(signature); wipe(fingerprint); wipe(transcript)
    }
  })

  it('rejects outer grant substitution before opening any key material', async () => {
    const envelope = {
      descriptor: {
        protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
        purpose: ENVELOPE_PURPOSE.reason,
        scope: {
          organizationId: '00112233-4455-6677-8899-aabbccddeeff',
          vaultId: '11112222-3333-4444-8555-666677778888',
          entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
          grantOrRequestId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
          agentId: 'cccccccc-dddd-4eee-8fff-000000000000',
        },
        resourceRevision: '1', keyVersion: 1, memberKeyGeneration: 1,
        binding: { wrapperSuiteId: KEY_WRAPPER_SUITE.active, recipientKeyVersion: 1, recipientKeyFingerprint: 'AA', requestedMethods: 1 },
      },
      encodedSuitePayload: 'AA', wrappedReasonDek: { descriptor: {}, encodedSealedKeyPackage: 'AA' }, agentSignature: 'AA',
    } as unknown as EncryptedReasonContract
    await expect(openEncryptedReason(envelope, [], new Uint8Array(32), {
      publicKey: '', keyVersion: 1, keyFingerprint: '',
    }, {
      organizationId: envelope.descriptor.scope.organizationId,
      vaultId: envelope.descriptor.scope.vaultId,
      entryId: envelope.descriptor.scope.entryId!,
      grantId: 'dddddddd-eeee-4fff-8000-111111111111',
      agentId: envelope.descriptor.scope.agentId!,
      vaultAgentMessageKeySuiteId: KEY_WRAPPER_SUITE.active,
    })).rejects.toThrow('outer resource scope')
  })
})

import { sealVaultEnvelope, toEnvelopeDescriptor } from './vault-envelope'
import { encodeCanonicalEnvelopeAad } from './canonical-aad'
import { fromBase64Url } from './encoding'
import { sha256Digest } from './portable-sha256'
afterEach(() => vi.unstubAllGlobals())

async function messageKeyPair(suite: string) {
  if (suite === KEY_WRAPPER_SUITE.active) return generateRecipientKeyPair()
  const pair = (await loadSodium()).crypto_box_keypair()
  return { keySuiteId: suite, publicKey: pair.publicKey, privateKey: pair.privateKey }
}

async function signedReasonFixture(plaintext = '{"reason":"Synthetic request"}', suite: string = KEY_WRAPPER_SUITE.active) {
  const sodium = await loadSodium()
  const expected = {
    organizationId: '00112233-4455-6677-8899-aabbccddeeff', vaultId: '11112222-3333-4444-8555-666677778888',
    entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', grantId: '12345678-1234-4234-8234-1234567890ab',
    agentId: 'fedcba98-7654-4321-8765-abcdefabcdef', vaultAgentMessageKeySuiteId: suite,
  }
  const vaultKey = new Uint8Array(32).fill(5), dek = new Uint8Array(32).fill(3)
  const recipient = await messageKeyPair(suite), signing = sodium.crypto_sign_keypair()
  const fingerprint = computeRecipientFingerprint(suite, 4, recipient.publicKey)
  const descriptor: EncryptedReasonContract['descriptor'] = {
    protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1, purpose: ENVELOPE_PURPOSE.reason,
    scope: { organizationId: expected.organizationId, vaultId: expected.vaultId, entryId: expected.entryId,
      grantOrRequestId: expected.grantId, agentId: expected.agentId },
    resourceRevision: '1', keyVersion: 1, memberKeyGeneration: 1,
    binding: { wrapperSuiteId: suite, recipientKeyVersion: 1, recipientKeyFingerprint: toBase64Url(fingerprint), requestedMethods: 1 },
  }
  const extension = { wrapperSuiteId: suite, recipientKeyVersion: 1, recipientKeyFingerprint: fingerprint, methods: 1 }
  const { resourceRevision, ...kdf } = toEnvelopeDescriptor(descriptor)
  void resourceRevision
  const payloadKey = await deriveVaultSubkey(dek, kdf)
  const encrypted = await sealVaultEnvelope(descriptor, new TextEncoder().encode(plaintext), payloadKey, extension)
  const aad = encodeCanonicalEnvelopeAad(toEnvelopeDescriptor(descriptor), extension)
  const parentHash = sha256Digest(aad)
  const wrapper: KeyWrapperDescriptor = { protocolVersion: 2, wrapperSuiteId: suite, purpose: 3,
    scope: descriptor.scope, resourceRevision: '1', wrappedKeyVersion: 1, memberKeyGeneration: 1,
    recipientKeyKind: 4, recipientKeyVersion: 1, recipientFingerprint: toBase64Url(fingerprint),
    parentDescriptorHash: toBase64Url(parentHash) }
  // The Agent runtime writes this wrapper; the frozen suite is produced directly because sealKey refuses it.
  const encodedSealedKeyPackage = suite === KEY_WRAPPER_SUITE.active
    ? await sealKey(wrapper, dek, { keySuiteId: suite, keyKind: 4, keyVersion: 1, publicKey: recipient.publicKey })
    : toBase64Url(await x25519SealedBoxV1.seal(dek, recipient.publicKey, wrapperContextHash(encodeKeyWrapperContext(wrapper))))
  const sealed = fromBase64Url(encodedSealedKeyPackage)
  const prefix = new TextEncoder().encode('PLDNV2SIG:ENCRYPTED-REASON:'), suiteBytes = new TextEncoder().encode(suite)
  const transcript = new Uint8Array([...prefix, 0, 2, ...aad, ...fromBase64Url(encrypted.encodedSuitePayload), 0, suiteBytes.length, ...suiteBytes, ...sealed])
  const envelope: EncryptedReasonContract = { ...encrypted, agentSignature: toBase64Url(sodium.crypto_sign_detached(transcript, signing.privateKey)),
    wrappedReasonDek: { descriptor: wrapper, encodedSealedKeyPackage } }
  const privateDescriptor = { protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1, purpose: ENVELOPE_PURPOSE.agentMessagePrivateByVk,
    scope: { organizationId: expected.organizationId, vaultId: expected.vaultId }, resourceRevision: '1', keyVersion: 1, memberKeyGeneration: 1, binding: { wrappingVaultKeyVersion: 1 } }
  const { resourceRevision: ignored, ...privateKdf } = toEnvelopeDescriptor(privateDescriptor)
  void ignored
  const wrappingKey = await deriveVaultSubkey(vaultKey, privateKdf)
  const privateEnvelope = await sealVaultEnvelope(privateDescriptor, recipient.privateKey, wrappingKey, { wrappingVkVersion: 1 })
  const identity = { publicKey: toBase64(signing.publicKey), keyVersion: 1, keyFingerprint: toBase64Url(fingerprint32ByteKey(signing.publicKey, SIGNING_KEY_KIND.agentSigning)) }
  wipe(recipient.privateKey); wipe(signing.privateKey); wipe(payloadKey); wipe(wrappingKey); wipe(dek)
  return { envelope, privateEnvelope, identity, expected, vaultKey }
}

it.each([KEY_WRAPPER_SUITE.active, KEY_WRAPPER_SUITE.legacy])('opens a reason wrapped with %s without SubtleCrypto', async (suite) => {
  const f = await signedReasonFixture(undefined, suite)
  vi.stubGlobal('crypto', { getRandomValues: crypto.getRandomValues.bind(crypto) })
  try { await expect(openEncryptedReason(f.envelope, [f.privateEnvelope], f.vaultKey, f.identity, f.expected)).resolves.toBe('Synthetic request') }
  finally { wipe(f.vaultKey) }
})

it('rejects a reason wrapped with a suite other than the manifest message key suite', async () => {
  const f = await signedReasonFixture(undefined, KEY_WRAPPER_SUITE.legacy)
  try {
    await expect(openEncryptedReason(f.envelope, [f.privateEnvelope], f.vaultKey, f.identity,
      { ...f.expected, vaultAgentMessageKeySuiteId: KEY_WRAPPER_SUITE.active })).rejects.toThrow('does not match its encrypted reason envelope')
  } finally { wipe(f.vaultKey) }
})

it('opens a complete signed reason without SubtleCrypto', async () => {
  const f = await signedReasonFixture()
  vi.stubGlobal('crypto', { getRandomValues: crypto.getRandomValues.bind(crypto) })
  try { await expect(openEncryptedReason(f.envelope, [f.privateEnvelope], f.vaultKey, f.identity, f.expected)).resolves.toBe('Synthetic request') }
  finally { wipe(f.vaultKey) }
})
it('never exposes decrypted malformed JSON in errors', async () => {
  const f = await signedReasonFixture('PRIVATE_SYNTHETIC_REASON not JSON')
  try { await expect(openEncryptedReason(f.envelope, [f.privateEnvelope], f.vaultKey, f.identity, f.expected)).rejects.toThrow(/^Encrypted reason plaintext contract is invalid$/) }
  finally { wipe(f.vaultKey) }
})

it.each(['payload', 'wrapper', 'signature', 'publicKey'] as const)('rejects oversized %s before decoding its bytes', async field => {
  const oversized = 'A'.repeat(field === 'payload' ? 1_500_000 : 2_048)
  const decode = vi.spyOn(globalThis, 'atob')
  try {
    await expect(verifyEncryptedReasonSignature(new Uint8Array([1]),
      field === 'payload' ? oversized : 'AA', KEY_WRAPPER_SUITE.active, field === 'wrapper' ? oversized : 'AA',
      field === 'signature' ? oversized : 'AA',
      { publicKey: field === 'publicKey' ? oversized : toBase64(new Uint8Array(32)), keyVersion: 1, keyFingerprint: '' },
    )).rejects.toThrow()
    expect(decode.mock.calls.some(([value]) => value.startsWith(oversized))).toBe(false)
  } finally { decode.mockRestore() }
})
