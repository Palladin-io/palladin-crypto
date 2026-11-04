import { describe, expect, it, vi } from 'vitest'
import { getCryptoProvider } from './provider/active-provider'
import { fromBase64Url, toBase64 } from './encoding'
import { buildCanonicalGrantEnvelope, buildCanonicalGrantEnvelopeV2 } from './grant-protocol'
import { encodeDeliveryBoundGrantAad } from './canonical-aad'
import { requireCryptoSuite } from './crypto-suite'
import { deriveVaultSubkey } from './hkdf'
import { wipe } from './sodium'
import { toEnvelopeDescriptor } from './vault-envelope'
import { generateRecipientKeyPair, openKey } from './key-wrapper/key-wrapper'
import { KEY_WRAPPER_SUITE } from './key-wrapper/registry'
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
  it.each([1, 2])('binds the selected fields and caller-provided revision/key version (payload v%i)', async (version) => {
    const agent = await generateRecipientKeyPair()
    try {
      const build = version === 2 ? buildCanonicalGrantEnvelopeV2 : buildCanonicalGrantEnvelope
      const totpSource = { source: 'totp', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 8, period: 30 } as const
      const inputSecret: MemberSecretV1 = version === 1 ? secret : {
        ...secret, agentFieldAccess: { ...secret.agentFieldAccess, 'credential.totp': 'onGrantDerived' },
        content: { ...secret.content, totp: { secret: totpSource.secret, algorithm: totpSource.algorithm, digits: totpSource.digits, period: totpSource.period, issuer: null, account: null } },
      }
      // Source is supplied by the Member; the grant endpoint receives only ciphertext.
      const selected = version === 1 ? ['credential.password'] : ['credential.password', 'credential.totp']
      const envelope = await build({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000',
        entryRevision: '7', memberKeyGeneration: 3,
        agentPublicKey: toBase64(agent.publicKey), agentKeySuiteId: agent.keySuiteId, recipientKeyVersion: 4,
        grantEnvelopeRevision: '8', grantKeyVersion: 5,
        approvedFieldIds: selected, approvedMethods: 1, secret: inputSecret,
      })
      expect(envelope.descriptor.resourceRevision).toBe('8')
      expect(envelope.descriptor.keyVersion).toBe(5)
      expect(envelope.wrappedGrantDek.descriptor.resourceRevision).toBe('8')
      expect(envelope.wrappedGrantDek.descriptor.wrappedKeyVersion).toBe(5)
      expect(envelope.fieldIds).toEqual(selected)
      const wrapper = envelope.wrappedGrantDek.descriptor
      expect(wrapper.wrapperSuiteId).toBe(KEY_WRAPPER_SUITE.active)
      expect(envelope.descriptor.binding.wrapperSuiteId).toBe(KEY_WRAPPER_SUITE.active)
      const grantDek = await openKey(wrapper, envelope.wrappedGrantDek.encodedSealedKeyPackage, {
        keySuiteId: agent.keySuiteId, keyKind: 1, keyVersion: 4, publicKey: agent.publicKey, privateKey: agent.privateKey,
      })
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
        const decoded = JSON.parse(new TextDecoder().decode(plaintext))
        expect(decoded).toEqual({
          schema: `palladin.grant-payload.v${version}`, entryType: 'credential', fields: [
            { id: 'credential.password', kind: 'concealed', mode: 'value', value: 'secret' },
            ...(version === 2 ? [{ id: 'credential.totp', kind: 'totp', mode: 'derived', value: totpSource }] : []),
          ],
        })
        // The same ciphertext must not open under another scope or revision.
        for (const offset of [10, Math.floor(aad.length / 2), aad.length - 1]) {
          const substituted = new Uint8Array(aad); substituted[offset] ^= 1
          await expect(suite.open({ key: payloadKey, aad: substituted as typeof aad,
            payload: suite.validateEncodedPayload(fromBase64Url(envelope.encodedSuitePayload)) })).rejects.toThrow()
        }
        wipe(plaintext)
      } finally {
        wipe(payloadKey)
        wipe(grantDek)
      }
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('refuses to seal a grant to an Agent key still published under the read-only suite', async () => {
    await getCryptoProvider().ready()
    const legacyAgent = getCryptoProvider().boxKeypair()
    const sealSpy = vi.spyOn(getCryptoProvider(), 'boxSeal')
    try {
      await expect(buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000', entryRevision: '1', memberKeyGeneration: 1,
        agentPublicKey: toBase64(legacyAgent.publicKey), agentKeySuiteId: KEY_WRAPPER_SUITE.legacy,
        recipientKeyVersion: 1, grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['credential.password'], approvedMethods: 1, secret,
      })).rejects.toThrow('key-migration-pending')
      expect(sealSpy).not.toHaveBeenCalled()
    } finally {
      sealSpy.mockRestore()
      wipe(legacyAgent.privateKey); wipe(legacyAgent.publicKey)
    }
  })

  it('preserves selected methods with standard delivery for Script payloads', async () => {
    const agent = await generateRecipientKeyPair()
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
        memberKeyGeneration: 1, agentPublicKey: toBase64(agent.publicKey), agentKeySuiteId: agent.keySuiteId, recipientKeyVersion: 1,
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
    const agent = await generateRecipientKeyPair()
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
        agentPublicKey: toBase64(agent.publicKey), agentKeySuiteId: agent.keySuiteId, recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['notes'], approvedMethods: 1, secret: notesSecret,
      })

      expect(envelope.fieldIds).toEqual(['credential.notes'])
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('rejects the unregistered Credit Card preview from GrantPayload v1', async () => {
    const agent = await generateRecipientKeyPair()
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
        memberKeyGeneration: 1, agentPublicKey: toBase64(agent.publicKey), agentKeySuiteId: agent.keySuiteId, recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['creditCard.cardNumber'], approvedMethods: 6, secret: cardSecret,
      })).rejects.toThrow(/not registered/)
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })

  it('rejects fields outside the approved Agent policy', async () => {
    const agent = await generateRecipientKeyPair()
    try {
      await expect(buildCanonicalGrantEnvelope({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff',
        agentId: 'cccccccc-dddd-4eee-8fff-000000000000', entryRevision: '1',
        memberKeyGeneration: 1, agentPublicKey: toBase64(agent.publicKey), agentKeySuiteId: agent.keySuiteId, recipientKeyVersion: 1,
        grantEnvelopeRevision: '1', grantKeyVersion: 1,
        approvedFieldIds: ['credential.url'], approvedMethods: 1, secret,
      })).rejects.toThrow('not grantable')
    } finally {
      wipe(agent.privateKey); wipe(agent.publicKey)
    }
  })
})
