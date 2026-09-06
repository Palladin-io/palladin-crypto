import { describe, expect, it } from 'vitest'
import { fromBase64Url, toBase64 } from './encoding'
import { buildCanonicalGrantEnvelope } from './grant-protocol'
import { encodeDeliveryBoundGrantAad } from './canonical-aad'
import { requireCryptoSuite } from './crypto-suite'
import { deriveVaultSubkey } from './hkdf'
import { loadSodium } from './sodium-loader'
import { wipe } from './sodium'
import { toEnvelopeDescriptor } from './vault-envelope'
import { openKeyFromX25519Recipient, X25519_SEALED_BOX_V1, type X25519WrapperContext } from './x25519-wrapper'
import type { MemberSecretV1 } from './vault-plaintext'

const secret: MemberSecretV1 = {
  schema: 'palladin.member-secret.v1', memberLabel: 'Database', agentLabel: 'Database',
  discoverable: true, description: null, icon: null, color: null, entryType: 'credential',
  agentFieldAccess: {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
    entryType: 'discovery', 'credential.username': 'onGrantValue',
    'credential.password': 'onGrantValue', 'credential.url': 'never',
    'credential.urlDomain': 'discovery', 'credential.totp': 'never', notes: 'never',
  },
  content: {
    username: 'alice', password: 'secret', url: null, urlDomain: null, totp: null,
    notes: null, customFields: [],
  },
}

describe('canonical Grant protocol', () => {
  it('binds the selected fields and caller-provided revision/key version', async () => {
    const sodium = await loadSodium()
    const agent = sodium.crypto_box_keypair()
    try {
      const envelope = await buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000',
        entryRevision: '7', memberKeyGeneration: 3,
        agentPublicKey: toBase64(agent.publicKey), recipientKeyVersion: 4,
        grantEnvelopeRevision: '8', grantKeyVersion: 5,
        approvedFieldIds: ['credential.password'], approvedMethods: 1, secret,
      })
      expect(envelope.descriptor.resourceRevision).toBe('8')
      expect(envelope.descriptor.keyVersion).toBe(5)
      expect(envelope.wrappedGrantDek.descriptor.resourceRevision).toBe('8')
      expect(envelope.wrappedGrantDek.descriptor.wrappedKeyVersion).toBe(5)
      expect(envelope.fieldIds).toEqual(['credential.password'])
      const wrapper = envelope.wrappedGrantDek.descriptor
      const grantDek = await openKeyFromX25519Recipient(
        fromBase64Url(envelope.wrappedGrantDek.encodedSealedKeyPackage),
        agent.publicKey,
        agent.privateKey,
        {
          protocolVersion: wrapper.protocolVersion,
          wrapperSuiteId: X25519_SEALED_BOX_V1,
          purpose: wrapper.purpose,
          organizationId: wrapper.scope.organizationId,
          vaultId: wrapper.scope.vaultId,
          entryId: wrapper.scope.entryId ?? undefined,
          grantOrRequestId: wrapper.scope.grantOrRequestId ?? undefined,
          agentId: wrapper.scope.agentId ?? undefined,
          resourceRevision: BigInt(wrapper.resourceRevision),
          wrappedKeyVersion: wrapper.wrappedKeyVersion,
          memberKeyGeneration: wrapper.memberKeyGeneration ?? undefined,
          recipientKeyKind: wrapper.recipientKeyKind,
          recipientKeyVersion: wrapper.recipientKeyVersion,
          recipientFingerprint: fromBase64Url(wrapper.recipientFingerprint),
          parentDescriptorHash: fromBase64Url(wrapper.parentDescriptorHash!),
        } satisfies X25519WrapperContext,
      )
      const descriptor = toEnvelopeDescriptor(envelope.descriptor)
      const { resourceRevision, ...kdfContext } = descriptor
      void resourceRevision
      const payloadKey = await deriveVaultSubkey(grantDek, kdfContext)
      try {
        const aad = encodeDeliveryBoundGrantAad(descriptor, {
          entryRevision: 7n,
          wrapperSuiteId: envelope.descriptor.binding.wrapperSuiteId,
          recipientKeyVersion: envelope.descriptor.binding.recipientKeyVersion,
          recipientKeyFingerprint: fromBase64Url(envelope.descriptor.binding.recipientKeyFingerprint),
          methods: envelope.descriptor.binding.approvedMethods,
          deliveryPolicy: envelope.descriptor.binding.deliveryPolicy,
          fieldSetCommitment: fromBase64Url(envelope.descriptor.binding.fieldSetCommitment),
        })
        const suite = requireCryptoSuite(envelope.descriptor.cryptoSuiteId)
        const plaintext = await suite.open({ key: payloadKey, aad,
          payload: suite.validateEncodedPayload(fromBase64Url(envelope.encodedSuitePayload)) })
        expect(new TextDecoder().decode(plaintext)).toBe(
          '{"entryType":"credential","fields":[{"id":"credential.password","kind":"concealed","mode":"value","value":"secret"}],"schema":"palladin.grant-payload.v1"}',
        )
        wipe(plaintext)
      } finally {
        wipe(payloadKey)
        wipe(grantDek)
      }
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('preserves selected methods with standard delivery for Script payloads', async () => {
    const sodium = await loadSodium()
    const agent = sodium.crypto_box_keypair()
    const scriptSecret: MemberSecretV1 = {
      schema: 'palladin.member-secret.v1', memberLabel: 'Deploy', agentLabel: 'Deploy',
      discoverable: true, description: null, icon: null, color: null, entryType: 'script',
      agentFieldAccess: {
        memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
        entryType: 'discovery', 'script.source': 'onGrantRuntime', 'script.interpreter': 'onGrantRuntime',
        'script.refs': 'onGrantRuntime', notes: 'never',
      },
      content: { source: 'echo ok', interpreter: 'bash', refs: [], notes: null, customFields: [] },
    }
    try {
      const envelope = await buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000', entryRevision: '1',
        memberKeyGeneration: 1, agentPublicKey: toBase64(agent.publicKey), recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['script.source'], approvedMethods: 6, secret: scriptSecret,
      })
      expect(envelope.fieldIds).toEqual(['script.source'])
      expect(envelope.descriptor.binding.approvedMethods).toBe(6)
      expect(envelope.descriptor.binding.deliveryPolicy).toBe(0)
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('derives structural field IDs from the namespaced payload', async () => {
    const sodium = await loadSodium()
    const agent = sodium.crypto_box_keypair()
    const notesSecret: MemberSecretV1 = {
      ...secret,
      content: { ...secret.content, notes: 'private note' },
      agentFieldAccess: { ...secret.agentFieldAccess, notes: 'onGrantValue' },
    }
    try {
      const envelope = await buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000',
        entryRevision: '1', memberKeyGeneration: 1,
        agentPublicKey: toBase64(agent.publicKey), recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['notes'], approvedMethods: 1, secret: notesSecret,
      })

      expect(envelope.fieldIds).toEqual(['credential.notes'])
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('rejects the unregistered Credit Card preview from GrantPayload v1', async () => {
    const sodium = await loadSodium()
    const agent = sodium.crypto_box_keypair()
    const cardSecret: MemberSecretV1 = {
      schema: 'palladin.member-secret.v1', memberLabel: 'Company card', agentLabel: 'Company card',
      discoverable: true, description: null, icon: null, color: null, entryType: 'creditCard',
      agentFieldAccess: {
        memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
        entryType: 'discovery', 'creditCard.cardholderName': 'onGrantRuntime',
        'creditCard.cardNumber': 'onGrantRuntime', 'creditCard.expiryMonth': 'onGrantRuntime',
        'creditCard.expiryYear': 'onGrantRuntime', 'creditCard.billingAddress': 'never', notes: 'never',
      },
      content: {
        cardholderName: 'Ada Lovelace', cardNumber: '4242424242424242', expiryMonth: '12',
        expiryYear: '2030', billingAddress: null,
        notes: null, customFields: [],
      },
    }
    try {
      await expect(buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000', entryRevision: '1',
        memberKeyGeneration: 1, agentPublicKey: toBase64(agent.publicKey), recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['creditCard.cardNumber'], approvedMethods: 6, secret: cardSecret,
      })).rejects.toThrow(/not registered/)
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('rejects fields outside the approved Agent policy', async () => {
    const sodium = await loadSodium()
    const agent = sodium.crypto_box_keypair()
    try {
      await expect(buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000', entryRevision: '1',
        memberKeyGeneration: 1, agentPublicKey: toBase64(agent.publicKey), recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['credential.url'], approvedMethods: 1, secret,
      })).rejects.toThrow('not grantable')
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })
})
