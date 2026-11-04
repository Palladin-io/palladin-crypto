import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js'
import { describe, expect, it } from 'vitest'
import registryJson from '../fixtures/key-wrapper-v1/registry.json'
import publicationJson from '../fixtures/key-wrapper-v1/recipient-key-publication.json'
import vectors from '../fixtures/key-wrapper-v1/vectors.json'
import { sha256Digest } from '../portable-sha256'
import { decodeHex, encodeHex } from '../vault-v2-bytes'
import {
  computeRecipientFingerprint,
  deriveRecipientPublicKey,
  encodeKeyWrapperContext,
  generateRecipientKeyPair,
  openKey,
  sealingSuiteForRecipientKey,
  sealKey,
  type KeyWrapperDescriptor,
  type KeyWrapperRecipient,
} from './key-wrapper'
import {
  KEY_WRAPPER_ERROR_CODES,
  KEY_WRAPPER_PROTOCOL_VERSION,
  KEY_WRAPPER_SUITE,
  KEY_WRAPPER_SUITES,
  KeyWrapperError,
  PURPOSE_RULES,
  RECIPIENT_KEY_KIND,
  SCOPE_BIT,
  SUITE_LIFECYCLE,
} from './registry'
import { xwingDecapsulate } from './suites/xwing-kem'
import { toBase64Url } from '../encoding'

type VectorRecipient = (typeof vectors.positive)[number]['recipient']

const recipientOf = (value: VectorRecipient): KeyWrapperRecipient => ({
  keySuiteId: value.directorySuiteId,
  keyKind: value.keyKind,
  keyVersion: value.keyVersion,
  publicKey: decodeHex(value.publicKeyHex),
  privateKey: decodeHex(value.privateKeyHex),
})

const descriptorOf = (value: unknown) => structuredClone(value) as KeyWrapperDescriptor

async function errorCode(action: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await action()
  } catch (error) {
    return error instanceof KeyWrapperError ? error.code : `unexpected: ${String(error)}`
  }
  return undefined
}

describe('key-wrapper v1 registry', () => {
  it('matches the build-time copy of the protocol registry', () => {
    expect(KEY_WRAPPER_PROTOCOL_VERSION).toBe(registryJson.protocolVersion)
    expect(SCOPE_BIT).toEqual(registryJson.scopeBits)
    expect([...KEY_WRAPPER_ERROR_CODES]).toEqual([...registryJson.errors, ...publicationJson.errors])
    expect(Object.values(RECIPIENT_KEY_KIND).sort()).toEqual(registryJson.recipientKeyKinds.map(({ id }) => id).sort())
    expect(SUITE_LIFECYCLE).toEqual(Object.fromEntries(
      registryJson.suiteLifecycle.map(({ status, seal, open }) => [status, { seal, open }]),
    ))
    expect(KEY_WRAPPER_SUITES).toEqual(Object.fromEntries(
      registryJson.suites.map(({ id, status, purposes }) => [id, { status, purposes }]),
    ))
    expect(KEY_WRAPPER_SUITES[KEY_WRAPPER_SUITE.active].status).toBe('active')
    expect(PURPOSE_RULES).toEqual(Object.fromEntries(registryJson.purposes.map((purpose) => [purpose.id, {
      scopeBitmap: purpose.scopeBitmap,
      recipientKeyKinds: purpose.recipientKeyKinds,
      memberKeyGeneration: purpose.memberKeyGeneration,
      parentDescriptorHash: purpose.parentDescriptorHash,
    }])))
  })
})

describe('X-Wing draft-10 known answer', () => {
  it('matches the first Appendix C vector', () => {
    const kat = vectors.xwingKnownAnswer
    const { publicKey } = xwing.keygen(decodeHex(kat.seedHex))
    expect(encodeHex(publicKey.subarray(0, 16))).toBe(kat.publicKeyPrefixHex)
    expect(encodeHex(sha256Digest(publicKey))).toBe(kat.publicKeySha256Hex)

    const { cipherText, sharedSecret } = xwing.encapsulate(publicKey, decodeHex(kat.encapsulationRandomnessHex))
    expect(encodeHex(cipherText.subarray(0, 16))).toBe(kat.ciphertextPrefixHex)
    expect(encodeHex(sha256Digest(cipherText))).toBe(kat.ciphertextSha256Hex)
    expect(encodeHex(sharedSecret)).toBe(kat.sharedSecretHex)
    expect(encodeHex(xwingDecapsulate(cipherText, decodeHex(kat.seedHex)))).toBe(kat.sharedSecretHex)
  })

  it('rejects wrong-length KEM input before decapsulation', () => {
    const seed = decodeHex(vectors.xwingKnownAnswer.seedHex)
    expect(() => xwingDecapsulate(new Uint8Array(1119), seed)).toThrow(RangeError)
    expect(() => xwingDecapsulate(new Uint8Array(1120), new Uint8Array(31))).toThrow(RangeError)
  })
})

describe.each([...vectors.positive, ...vectors.legacy])('positive vector $name', (vector) => {
  const recipient = recipientOf(vector.recipient)

  it('encodes the context and fingerprint and opens the package', async () => {
    expect(encodeHex(encodeKeyWrapperContext(descriptorOf(vector.descriptor)))).toBe(vector.expectedContextHex)
    expect(toBase64Url(computeRecipientFingerprint(recipient.keySuiteId, recipient.keyKind, recipient.publicKey)))
      .toBe(vector.descriptor.recipientFingerprint)
    const opened = await openKey(descriptorOf(vector.descriptor), vector.encodedSealedKeyPackage, recipient)
    expect(encodeHex(opened)).toBe(vector.wrappedKeyHex)
  })

  it('seals only with the active suite', async () => {
    const wrappedKey = decodeHex(vector.wrappedKeyHex)
    if (vector.descriptor.wrapperSuiteId !== KEY_WRAPPER_SUITE.active) {
      expect(await errorCode(() => sealKey(descriptorOf(vector.descriptor), wrappedKey, recipient))).toBe('suite-not-writable')
      return
    }
    const sealed = await sealKey(descriptorOf(vector.descriptor), wrappedKey, recipient)
    expect(sealed).not.toBe(vector.encodedSealedKeyPackage)
    expect(await openKey(descriptorOf(vector.descriptor), sealed, recipient)).toEqual(wrappedKey)
  })
})

describe.each(vectors.negative)('negative vector $name', (vector) => {
  it(`fails with ${vector.expectedError}`, async () => {
    const recipient = recipientOf(vector.recipient)
    const descriptor = descriptorOf(vector.descriptor)
    const code = vector.operation === 'seal'
      ? await errorCode(() => sealKey(descriptor, decodeHex(vector.wrappedKeyHex!), recipient))
      : await errorCode(() => openKey(descriptor, vector.encodedSealedKeyPackage!, recipient))
    expect(code).toBe(vector.expectedError)
  })
})

describe('recipient keys', () => {
  it('generates an active-suite key pair that round-trips a wrapped key', async () => {
    const pair = await generateRecipientKeyPair()
    expect(pair.keySuiteId).toBe(KEY_WRAPPER_SUITE.active)
    expect(pair.privateKey).toHaveLength(32)
    expect(await deriveRecipientPublicKey(pair.keySuiteId, pair.privateKey)).toEqual(pair.publicKey)

    const member = vectors.positive.find(({ name }) => name === 'palladin-xwing-v1:member-vault-key:key-kind-5')!
    const descriptor = descriptorOf(member.descriptor)
    descriptor.recipientFingerprint = toBase64Url(computeRecipientFingerprint(pair.keySuiteId, 5, pair.publicKey))
    const recipient = { ...pair, keyKind: 5, keyVersion: descriptor.recipientKeyVersion }
    const wrappedKey = new Uint8Array(32).fill(9)
    const sealed = await sealKey(descriptor, wrappedKey, recipient)
    expect(await openKey(descriptor, sealed, recipient)).toEqual(wrappedKey)
    expect(await errorCode(() => openKey({ ...descriptor, resourceRevision: '8' }, sealed, recipient))).toBe('open-failed')
  })

  it('refuses to seal to a published key whose suite is not active', async () => {
    expect(sealingSuiteForRecipientKey(KEY_WRAPPER_SUITE.active)).toBe(KEY_WRAPPER_SUITE.active)
    expect(() => sealingSuiteForRecipientKey(KEY_WRAPPER_SUITE.legacy)).toThrow('key-migration-pending')
    expect(() => sealingSuiteForRecipientKey('palladin-unknown-v1')).toThrow('unsupported-suite')

    const member = vectors.positive.find(({ name }) => name === 'palladin-xwing-v1:member-vault-key:key-kind-5')!
    const legacyRecipient = recipientOf(vectors.positive.find(({ name }) => name === 'palladin-x25519-sealed-box-v1:member-vault-key:key-kind-5')!.recipient)
    expect(await errorCode(() => sealKey(descriptorOf(member.descriptor), new Uint8Array(32), legacyRecipient))).toBe('key-migration-pending')
  })

  it('rejects unknown suites and recipients without a private key', async () => {
    expect(() => computeRecipientFingerprint('palladin-unknown-v1', 5, new Uint8Array(32))).toThrow('unsupported-suite')
    expect(await errorCode(() => deriveRecipientPublicKey('palladin-unknown-v1', new Uint8Array(32)))).toBe('unsupported-suite')
    const member = vectors.positive[0]
    const { privateKey: _omitted, ...publicOnly } = recipientOf(member.recipient)
    expect(await errorCode(() => openKey(descriptorOf(member.descriptor), member.encodedSealedKeyPackage, publicOnly)))
      .toBe('recipient-mismatch')
  })
})
