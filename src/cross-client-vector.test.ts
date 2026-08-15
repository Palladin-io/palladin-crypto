import { describe, expect, it, vi } from 'vitest'
import { encodeCanonicalEnvelopeAad, encodeCanonicalKdfContext } from './canonical-aad'
import { requireCryptoSuite, VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import type { EncodedSuitePayload } from './envelope'
import { ENVELOPE_PURPOSE } from './envelope'
import { deriveVaultSubkey } from './hkdf'
import envelopeVector from './vectors/envelope-xchacha-hkdf.json'
import wrapperVector from './vectors/x25519-sealed-box.json'
import {
  computeVaultKeyFingerprint,
  encodeX25519WrapperContext,
  openKeyFromX25519Recipient,
  VAULT_KEY_KIND,
  WRAPPER_PURPOSE,
  X25519_SEALED_BOX_V1,
  type X25519WrapperContext,
} from './x25519-wrapper'
import { getCryptoProvider } from './provider/active-provider'

const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)?.map((value) => Number.parseInt(value, 16)) ?? [])
const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')

describe(`shared Rust vector: ${envelopeVector.name}`, () => {
  it('matches descriptor AAD, canonical KDF, and XChaCha payload', async () => {
    const descriptor = envelopeVector.descriptor
    const descriptorBase = {
      protocolVersion: descriptor.protocolVersion,
      cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
      purpose: ENVELOPE_PURPOSE.grant,
      organizationId: descriptor.organizationId,
      vaultId: descriptor.vaultId,
      entryId: descriptor.entryId,
      grantOrRequestId: descriptor.grantOrRequestId,
      agentId: descriptor.agentId,
      keyVersion: descriptor.keyVersion,
      memberKeyGeneration: descriptor.memberKeyGeneration,
    } as const
    const aad = encodeCanonicalEnvelopeAad(
      { ...descriptorBase, resourceRevision: descriptor.resourceRevision },
      {
        entryRevision: descriptor.entryRevision,
        wrapperSuiteId: descriptor.wrapperSuiteId,
        recipientKeyVersion: descriptor.recipientKeyVersion,
        recipientKeyFingerprint: bytes(descriptor.recipientFingerprintHex),
        methods: descriptor.approvedMethods,
        fieldSetCommitment: bytes(descriptor.fieldSetCommitmentHex),
        expiresAt: {
          seconds: descriptor.expiresAtUnixSeconds,
          nanoseconds: descriptor.expiresAtNanoseconds,
        },
        remainingUses: descriptor.remainingUses,
      },
    )
    expect(hex(aad)).toBe(envelopeVector.expected.descriptorAadHex)
    expect(hex(encodeCanonicalKdfContext(descriptorBase))).toBe(envelopeVector.expected.kdfContextHex)

    const derivedKey = await deriveVaultSubkey(
      bytes(envelopeVector.inputKeyMaterialHex),
      descriptorBase,
    )
    expect(hex(derivedKey)).toBe(envelopeVector.expected.derivedKeyHex)

    const plaintext = await requireCryptoSuite(VAULT_XCHACHA20_POLY1305_V1).open({
      payload: bytes(envelopeVector.expected.encodedSuitePayloadHex) as EncodedSuitePayload,
      key: derivedKey,
      aad,
    })
    expect(hex(plaintext)).toBe(envelopeVector.plaintextHex)
  })
})

describe(`shared Rust vector: ${wrapperVector.name}`, () => {
  const source = wrapperVector.context
  const context: X25519WrapperContext = {
    protocolVersion: source.protocolVersion,
    wrapperSuiteId: X25519_SEALED_BOX_V1,
    purpose: WRAPPER_PURPOSE.grantDek,
    organizationId: source.organizationId,
    vaultId: source.vaultId,
    entryId: source.entryId,
    grantOrRequestId: source.grantOrRequestId,
    agentId: source.agentId,
    resourceRevision: source.resourceRevision,
    wrappedKeyVersion: source.wrappedKeyVersion,
    memberKeyGeneration: source.memberKeyGeneration,
    recipientKeyKind: VAULT_KEY_KIND.agentX25519,
    recipientKeyVersion: source.recipientKeyVersion,
    recipientFingerprint: bytes(source.recipientFingerprintHex),
    parentDescriptorHash: bytes(source.parentDescriptorHashHex),
  }

  it('matches the domain-separated fingerprint and canonical wrapper context', async () => {
    const fingerprint = await computeVaultKeyFingerprint(
      bytes(wrapperVector.recipientPublicKeyHex),
      VAULT_KEY_KIND.agentX25519,
    )
    expect(hex(fingerprint)).toBe(source.recipientFingerprintHex)
    expect(hex(encodeX25519WrapperContext(context))).toBe(wrapperVector.expectedContextHex)
  })

  it('opens the 120-byte package and fails closed on context tampering', async () => {
    const sealed = bytes(wrapperVector.sealedPackageHex)
    expect(sealed).toHaveLength(120)
    const publicKey = bytes(wrapperVector.recipientPublicKeyHex)
    const privateKey = bytes(wrapperVector.recipientPrivateKeyHex)
    const opened = await openKeyFromX25519Recipient(sealed, publicKey, privateKey, context)
    expect(hex(opened)).toBe(wrapperVector.wrappedKeyHex)
    await expect(openKeyFromX25519Recipient(
      sealed,
      publicKey,
      privateKey,
      { ...context, resourceRevision: 8 },
    )).rejects.toThrow(/context verification/)
  })

  it('wipes an opened package when context encoding fails after unwrap', async () => {
    const provider = getCryptoProvider()
    let openedPackage: Uint8Array | undefined
    const wipe = vi.spyOn(provider, 'wipe').mockImplementation((value) => {
      if (value.length === 72) openedPackage = new Uint8Array(value)
      value.fill(0)
    })
    try {
      await expect(openKeyFromX25519Recipient(
        bytes(wrapperVector.sealedPackageHex),
        bytes(wrapperVector.recipientPublicKeyHex),
        bytes(wrapperVector.recipientPrivateKeyHex),
        { ...context, wrappedKeyVersion: 0 },
      )).rejects.toThrow(/versions must be positive/)
      expect(openedPackage).toBeDefined()
      expect(hex(openedPackage!.slice(8, 40))).toBe(wrapperVector.wrappedKeyHex)
    } finally {
      wipe.mockRestore()
    }
  })
})
