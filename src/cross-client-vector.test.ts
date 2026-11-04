import { describe, expect, it } from 'vitest'
import { encodeCanonicalEnvelopeAad, encodeCanonicalKdfContext } from './canonical-aad'
import { requireCryptoSuite, VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import type { EncodedSuitePayload } from './envelope'
import { ENVELOPE_PURPOSE } from './envelope'
import { deriveVaultSubkey } from './hkdf'
import envelopeVector from './vectors/envelope-xchacha-hkdf.json'

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
