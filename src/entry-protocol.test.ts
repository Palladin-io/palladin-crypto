import { describe, expect, it, vi } from 'vitest'
import { openMemberIndex, openMemberSecret, sealCanonicalEntry } from './entry-protocol'
import { deriveVaultSubkey } from './hkdf'
import { randomBytes, wipe } from './sodium'
import { openVaultEnvelope } from './vault-envelope'
import type { KdfContextDescriptor } from './envelope'
import type { EnvelopeDescriptorContract } from './vault-envelope'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { getCryptoProvider } from './provider/active-provider'
import type { MemberSecretV1 } from './vault-plaintext'

describe('canonical Entry protocol', () => {
  it('wipes a generated Entry DEK when plaintext validation fails early', async () => {
    const generatedDek = new Uint8Array(32).fill(0x5a)
    const provider = getCryptoProvider()
    const randomBytes = vi.spyOn(provider, 'randomBytes').mockReturnValue(generatedDek)
    try {
      const invalidSecret = {
        entryType: 'key',
        content: { customFields: [] },
        agentFieldAccess: {},
      } as unknown as MemberSecretV1
      await expect(sealCanonicalEntry({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        revision: '1', vaultKeyVersion: 1, vdkVersion: 1, memberKeyGeneration: 1,
      }, invalidSecret, new Uint8Array(32), new Uint8Array(32), 1)).rejects.toThrow()
      expect(generatedDek).toEqual(new Uint8Array(32))
    } finally {
      randomBytes.mockRestore()
    }
  })

  it('round-trips independently keyed MemberIndex and MemberSecret envelopes', async () => {
    const vaultKey = await randomBytes(32)
    const discoveryKey = await randomBytes(32)
    const secret = {
      schema: 'palladin.member-secret.v1' as const,
      memberLabel: 'Database', agentLabel: null, discoverable: false,
      description: null, icon: null, color: null, entryType: 'credential' as const,
      agentFieldAccess: {
        memberLabel: 'never' as const, agentLabel: 'never' as const, description: 'never' as const,
        icon: 'never' as const, color: 'never' as const, entryType: 'never' as const,
        'credential.username': 'never' as const, 'credential.password': 'never' as const,
        'credential.url': 'never' as const, 'credential.urlDomain': 'never' as const,
        'credential.totp': 'never' as const, notes: 'never' as const,
      },
      content: { username: 'alice', password: 'secret', url: null, urlDomain: null, totp: null, notes: null, customFields: [] },
    }
    try {
      const coordinates = {
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', revision: '1',
        vaultKeyVersion: 1, vdkVersion: 1, memberKeyGeneration: 1,
      }
      const envelopes = await sealCanonicalEntry(coordinates, secret, vaultKey, discoveryKey, 1)
      expect(envelopes.agentDiscovery).toBeNull()
      const descriptorContext = (descriptor: EnvelopeDescriptorContract<unknown>): KdfContextDescriptor => ({
        protocolVersion: descriptor.protocolVersion,
        cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
        purpose: descriptor.purpose,
        organizationId: descriptor.scope.organizationId,
        vaultId: descriptor.scope.vaultId,
        entryId: descriptor.scope.entryId ?? undefined,
        keyVersion: descriptor.keyVersion,
        memberKeyGeneration: descriptor.memberKeyGeneration ?? undefined,
      })
      const wrapKey = await deriveVaultSubkey(vaultKey, descriptorContext(envelopes.entryKey.descriptor))
      const entryDek = await openVaultEnvelope(envelopes.entryKey, wrapKey, { wrappingVkVersion: 1 })
      const indexKey = await deriveVaultSubkey(entryDek, descriptorContext(envelopes.memberIndex.descriptor))
      const secretKey = await deriveVaultSubkey(entryDek, descriptorContext(envelopes.memberSecret.descriptor))
      await expect(openVaultEnvelope(envelopes.memberIndex, indexKey)).resolves.toBeInstanceOf(Uint8Array)
      await expect(openVaultEnvelope(envelopes.memberSecret, secretKey, { operation: 1 })).resolves.toBeInstanceOf(Uint8Array)
      await expect(openVaultEnvelope(envelopes.memberSecret, entryDek, { operation: 1 })).rejects.toThrow()
      wipe(wrapKey); wipe(entryDek); wipe(indexKey); wipe(secretKey)
      expect((await openMemberIndex(envelopes.entryKey, envelopes.memberIndex, vaultKey, coordinates)).memberLabel).toBe('Database')
      const openedSecret = await openMemberSecret(envelopes.entryKey, envelopes.memberSecret, vaultKey, coordinates)
      expect(openedSecret.entryType).toBe('credential')
      if (openedSecret.entryType !== 'credential') throw new Error('Expected credential fixture')
      expect(openedSecret.content.password).toBe('secret')
      await expect(openMemberIndex(envelopes.entryKey, envelopes.memberIndex, vaultKey, { ...coordinates, entryId: 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff' }))
        .rejects.toThrow('outer resource scope')
      await expect(openMemberSecret(envelopes.entryKey, envelopes.memberSecret, vaultKey, { ...coordinates, revision: '2' }))
        .rejects.toThrow('outer Entry revision')
    } finally { wipe(vaultKey); wipe(discoveryKey) }
  })

  it('binds update projections to their independent monotonic revisions', async () => {
    const vaultKey = await randomBytes(32)
    const discoveryKey = await randomBytes(32)
    const secret = {
      schema: 'palladin.member-secret.v1' as const, memberLabel: 'Token', agentLabel: null,
      discoverable: false, description: null, icon: null, color: null, entryType: 'key' as const,
      agentFieldAccess: {
        memberLabel: 'never' as const, agentLabel: 'never' as const, description: 'never' as const,
        icon: 'never' as const, color: 'never' as const, entryType: 'never' as const,
        'key.value': 'onGrantValue' as const, notes: 'never' as const,
      },
      content: { value: 'secret', notes: null, customFields: [] },
    }
    try {
      const envelopes = await sealCanonicalEntry({
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', revision: '9',
        entryKeyRevision: '4', entryKeyVersion: 3, memberIndexRevision: '6', agentDiscoveryRevision: '8',
        vaultKeyVersion: 2, vdkVersion: 5, memberKeyGeneration: 7,
      }, secret, vaultKey, discoveryKey, 2)
      expect(envelopes.entryKey.descriptor.resourceRevision).toBe('4')
      expect(envelopes.entryKey.descriptor.keyVersion).toBe(3)
      expect(envelopes.memberSecret.descriptor.resourceRevision).toBe('9')
      expect(envelopes.memberSecret.descriptor.keyVersion).toBe(3)
      expect(envelopes.memberIndex.descriptor.resourceRevision).toBe('6')
      expect(envelopes.memberIndex.descriptor.keyVersion).toBe(3)
      expect(envelopes.agentDiscovery).toBeNull()
      await expect(openMemberSecret(envelopes.entryKey, envelopes.memberSecret, vaultKey, {
        organizationId: envelopes.entryKey.descriptor.scope.organizationId,
        vaultId: envelopes.entryKey.descriptor.scope.vaultId,
        entryId: envelopes.entryKey.descriptor.scope.entryId!,
        revision: '9',
      })).resolves.toMatchObject({ memberLabel: 'Token' })
    } finally { wipe(vaultKey); wipe(discoveryKey) }
  })

  it('seals and opens the canonical credit-card schema without CVV or PIN', async () => {
    const vaultKey = await randomBytes(32)
    const discoveryKey = await randomBytes(32)
    const card = {
      schema: 'palladin.member-secret.v1' as const,
      memberLabel: 'Travel card', agentLabel: 'Travel card', discoverable: true,
      description: null, icon: null, color: null, entryType: 'creditCard' as const,
      agentFieldAccess: {
        memberLabel: 'never' as const, agentLabel: 'discovery' as const,
        description: 'never' as const, icon: 'never' as const, color: 'never' as const,
        entryType: 'discovery' as const,
        'creditCard.cardholderName': 'onGrantRuntime' as const,
        'creditCard.cardNumber': 'onGrantRuntime' as const,
        'creditCard.expiryMonth': 'onGrantRuntime' as const,
        'creditCard.expiryYear': 'onGrantRuntime' as const,
        'creditCard.billingAddress': 'never' as const,
        notes: 'never' as const,
      },
      content: {
        cardholderName: 'Ada Lovelace', cardNumber: '4242424242424242',
        expiryMonth: '12', expiryYear: '2030', billingAddress: null,
        notes: null, customFields: [],
      },
    }
    const coordinates = {
      organizationId: '00112233-4455-6677-8899-aabbccddeeff',
      vaultId: '11112222-3333-4444-8555-666677778888',
      entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', revision: '1',
      vaultKeyVersion: 1, vdkVersion: 1, memberKeyGeneration: 1,
    }
    try {
      const envelopes = await sealCanonicalEntry(coordinates, card, vaultKey, discoveryKey, 1)
      await expect(openMemberSecret(
        envelopes.entryKey, envelopes.memberSecret, vaultKey, coordinates,
      )).resolves.toEqual(card)
      expect(envelopes.agentDiscovery).not.toBeNull()
    } finally { wipe(vaultKey); wipe(discoveryKey) }
  })
})
