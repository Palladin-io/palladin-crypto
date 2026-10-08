import { sha256Digest } from './portable-sha256'
import { ENVELOPE_PURPOSE } from './envelope'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { encodeCanonicalEnvelopeAad } from './canonical-aad'
import { fromBase64, fromBase64Url, toBase64Url } from './encoding'
import { deriveVaultSubkey } from './hkdf'
import { loadSodium } from './sodium-loader'
import { wipe } from './sodium'
import { assertEnvelopeScope, openVaultEnvelope, toEnvelopeDescriptor, type VaultEnvelopeContract } from './vault-envelope'
import { computeVaultKeyFingerprint, openKeyFromX25519Recipient, VAULT_KEY_KIND, WRAPPER_PURPOSE, X25519_SEALED_BOX_V1, type X25519WrapperDescriptorContract } from './x25519-wrapper'

export type VaultPrivateKeyEnvelopeContract = VaultEnvelopeContract<{ wrappingVaultKeyVersion: number }>

export interface EncryptedReasonContract extends VaultEnvelopeContract<{
  wrapperSuiteId: string
  recipientKeyVersion: number
  recipientKeyFingerprint: string
  requestedMethods: number
}> {
  wrappedReasonDek: {
    descriptor: X25519WrapperDescriptorContract
    encodedSealedKeyPackage: string
  }
  agentSignature: string
}

export interface ExpectedReasonCoordinates {
  organizationId: string
  vaultId: string
  entryId?: string
  grantId: string
  agentId: string
}

export interface AgentSigningIdentity {
  publicKey: string
  keyVersion: number
  keyFingerprint: string
}

export async function verifyEncryptedReasonSignature(
  descriptorBytes: Uint8Array,
  encodedSuitePayload: string,
  encodedSealedKeyPackage: string,
  signatureValue: string,
  agentSigning: AgentSigningIdentity,
): Promise<void> {
  const encodedPayload = fromBase64Url(encodedSuitePayload)
  const encodedWrapper = fromBase64Url(encodedSealedKeyPackage)
  if (agentSigning.keyVersion !== 1) throw new Error('Unsupported Agent signing key version')
  const signingPublicKey = fromBase64(agentSigning.publicKey)
  const signature = fromBase64Url(signatureValue)
  const signaturePrefix = new TextEncoder().encode('PLDNV2SIG:ENCRYPTED-REASON:')
  const wrapperSuite = new TextEncoder().encode(X25519_SEALED_BOX_V1)
  const transcript = new Uint8Array(signaturePrefix.length + 2 + descriptorBytes.length
    + encodedPayload.length + 2 + wrapperSuite.length + encodedWrapper.length)
  let transcriptOffset = 0
  transcript.set(signaturePrefix, transcriptOffset); transcriptOffset += signaturePrefix.length
  new DataView(transcript.buffer).setUint16(transcriptOffset, 2); transcriptOffset += 2
  transcript.set(descriptorBytes, transcriptOffset); transcriptOffset += descriptorBytes.length
  transcript.set(encodedPayload, transcriptOffset); transcriptOffset += encodedPayload.length
  new DataView(transcript.buffer).setUint16(transcriptOffset, wrapperSuite.length); transcriptOffset += 2
  transcript.set(wrapperSuite, transcriptOffset); transcriptOffset += wrapperSuite.length
  transcript.set(encodedWrapper, transcriptOffset)
  const sodium = await loadSodium()
  try {
    const fingerprint = await computeVaultKeyFingerprint(signingPublicKey, VAULT_KEY_KIND.agentEd25519)
    const fingerprintMatches = toBase64Url(fingerprint) === agentSigning.keyFingerprint
    wipe(fingerprint)
    if (signingPublicKey.length !== sodium.crypto_sign_PUBLICKEYBYTES
      || signature.length !== sodium.crypto_sign_BYTES
      || !fingerprintMatches
      || !sodium.crypto_sign_verify_detached(signature, transcript, signingPublicKey)) {
      throw new Error('Encrypted reason signature is invalid')
    }
  } finally {
    wipe(signingPublicKey); wipe(signature); wipe(transcript)
  }
}

export async function openEncryptedReason(
  envelope: EncryptedReasonContract,
  privateKeys: VaultPrivateKeyEnvelopeContract[],
  vaultKey: Uint8Array,
  agentSigning: AgentSigningIdentity,
  expected: ExpectedReasonCoordinates,
): Promise<string> {
  assertEnvelopeScope(envelope.descriptor, {
    purpose: ENVELOPE_PURPOSE.reason, organizationId: expected.organizationId,
    vaultId: expected.vaultId, entryId: expected.entryId,
    grantOrRequestId: expected.grantId, agentId: expected.agentId,
  })
  const wrapper = envelope.wrappedReasonDek.descriptor
  const privateEnvelope = privateKeys.find((candidate) =>
    candidate.descriptor.purpose === ENVELOPE_PURPOSE.agentMessagePrivateByVk
    && candidate.descriptor.keyVersion === wrapper.recipientKeyVersion)
  if (!privateEnvelope) throw new Error('Matching Vault Agent Message private key is unavailable')
  assertEnvelopeScope(privateEnvelope.descriptor, {
    purpose: ENVELOPE_PURPOSE.agentMessagePrivateByVk,
    organizationId: expected.organizationId, vaultId: expected.vaultId,
  })
  if (privateEnvelope.descriptor.memberKeyGeneration !== envelope.descriptor.memberKeyGeneration
    || wrapper.scope.organizationId !== expected.organizationId || wrapper.scope.vaultId !== expected.vaultId
    || wrapper.scope.entryId !== expected.entryId || wrapper.scope.grantOrRequestId !== expected.grantId
    || wrapper.scope.agentId !== expected.agentId || wrapper.protocolVersion !== 2
    || wrapper.wrapperSuiteId !== X25519_SEALED_BOX_V1 || wrapper.purpose !== WRAPPER_PURPOSE.reasonDek
    || wrapper.resourceRevision !== envelope.descriptor.resourceRevision
    || wrapper.wrappedKeyVersion !== envelope.descriptor.keyVersion
    || wrapper.memberKeyGeneration !== envelope.descriptor.memberKeyGeneration
    || wrapper.recipientKeyKind !== VAULT_KEY_KIND.vaultMessageX25519
    || wrapper.recipientKeyVersion !== envelope.descriptor.binding.recipientKeyVersion
    || wrapper.recipientFingerprint !== envelope.descriptor.binding.recipientKeyFingerprint) {
    throw new Error('Reason wrapper does not match its encrypted reason envelope')
  }
  const reasonExtension = {
    wrapperSuiteId: envelope.descriptor.binding.wrapperSuiteId,
    recipientKeyVersion: envelope.descriptor.binding.recipientKeyVersion,
    recipientKeyFingerprint: fromBase64Url(envelope.descriptor.binding.recipientKeyFingerprint),
    methods: envelope.descriptor.binding.requestedMethods,
  }
  const descriptorBytes = encodeCanonicalEnvelopeAad(toEnvelopeDescriptor(envelope.descriptor), reasonExtension)
  const expectedParentHash = sha256Digest(descriptorBytes)
  const suppliedParentHash = wrapper.parentDescriptorHash ? fromBase64Url(wrapper.parentDescriptorHash) : new Uint8Array()
  if (expectedParentHash.length !== suppliedParentHash.length
    || expectedParentHash.some((value, index) => value !== suppliedParentHash[index])) {
    expectedParentHash.fill(0); suppliedParentHash.fill(0)
    throw new Error('Reason wrapper parent descriptor hash does not match')
  }
  expectedParentHash.fill(0); suppliedParentHash.fill(0)
  await verifyEncryptedReasonSignature(
    descriptorBytes, envelope.encodedSuitePayload, envelope.wrappedReasonDek.encodedSealedKeyPackage,
    envelope.agentSignature, agentSigning,
  )
  const privateDescriptor = toEnvelopeDescriptor(privateEnvelope.descriptor)
  const wrappingKey = await deriveVaultSubkey(vaultKey, {
    protocolVersion: privateDescriptor.protocolVersion, cryptoSuiteId: privateDescriptor.cryptoSuiteId,
    purpose: privateDescriptor.purpose, organizationId: privateDescriptor.organizationId,
    vaultId: privateDescriptor.vaultId, keyVersion: privateDescriptor.keyVersion,
    memberKeyGeneration: privateDescriptor.memberKeyGeneration,
  })
  let messagePrivateKey: Uint8Array | undefined
  let messagePublicKey: Uint8Array | undefined
  let reasonDek: Uint8Array | undefined
  let reasonPayloadKey: Uint8Array | undefined
  try {
    const sodium = await loadSodium()
    messagePrivateKey = await openVaultEnvelope(privateEnvelope, wrappingKey, {
      wrappingVkVersion: privateEnvelope.descriptor.binding.wrappingVaultKeyVersion,
    })
    messagePublicKey = sodium.crypto_scalarmult_base(messagePrivateKey)
    reasonDek = await openKeyFromX25519Recipient(
      fromBase64Url(envelope.wrappedReasonDek.encodedSealedKeyPackage), messagePublicKey, messagePrivateKey,
      {
        protocolVersion: 2, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: WRAPPER_PURPOSE.reasonDek,
        organizationId: expected.organizationId, vaultId: expected.vaultId, entryId: expected.entryId,
        grantOrRequestId: expected.grantId, agentId: expected.agentId,
        resourceRevision: BigInt(wrapper.resourceRevision), wrappedKeyVersion: wrapper.wrappedKeyVersion,
        memberKeyGeneration: wrapper.memberKeyGeneration ?? undefined,
        recipientKeyKind: VAULT_KEY_KIND.vaultMessageX25519,
        recipientKeyVersion: wrapper.recipientKeyVersion,
        recipientFingerprint: fromBase64Url(wrapper.recipientFingerprint),
        parentDescriptorHash: wrapper.parentDescriptorHash ? fromBase64Url(wrapper.parentDescriptorHash) : undefined,
      },
    )
    // Canonical Rust writers treat the unwrapped ReasonDEK as root key
    // material and derive the actual payload key from the full descriptor.
    // Using the raw DEK here authenticates neither the KDF scope nor the wire
    // payload and fails XChaCha authentication for cross-client requests.
    reasonPayloadKey = await deriveVaultSubkey(reasonDek, {
      protocolVersion: envelope.descriptor.protocolVersion,
      cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
      purpose: envelope.descriptor.purpose,
      organizationId: expected.organizationId,
      vaultId: expected.vaultId,
      entryId: expected.entryId,
      grantOrRequestId: expected.grantId,
      agentId: expected.agentId,
      keyVersion: envelope.descriptor.keyVersion,
      memberKeyGeneration: envelope.descriptor.memberKeyGeneration ?? undefined,
    })
    const plaintext = await openVaultEnvelope(envelope, reasonPayloadKey, reasonExtension)
    try {
      if (plaintext.length === 0 || plaintext.length > 4096) throw new Error('Encrypted reason plaintext is out of bounds')
      const decoded: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext))
      if (!decoded || typeof decoded !== 'object' || Object.keys(decoded).length !== 1
        || !('reason' in decoded) || typeof decoded.reason !== 'string'
        || decoded.reason.length === 0 || decoded.reason.length > 4096) {
        throw new Error('Encrypted reason plaintext contract is invalid')
      }
      return decoded.reason
    } catch {
      // JSON parser diagnostics may contain decrypted input.
      throw new Error('Encrypted reason plaintext contract is invalid')
    } finally { wipe(plaintext) }
  } finally {
    wipe(wrappingKey)
    if (messagePrivateKey) wipe(messagePrivateKey)
    if (messagePublicKey) wipe(messagePublicKey)
    if (reasonDek) wipe(reasonDek)
    if (reasonPayloadKey) wipe(reasonPayloadKey)
  }
}
