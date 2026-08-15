import { describe, expect, it, vi } from 'vitest'
import { ENVELOPE_PURPOSE } from './envelope'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { toBase64Url } from './encoding'
import { deriveVaultSubkey } from './hkdf'
import { wipe } from './sodium'
import { loadSodium } from './sodium-loader'
import { encodeMemberVaultMetadata } from './vault-plaintext'
import { sealVaultEnvelope } from './vault-envelope'
import { openVaultProjection, sealMemberVaultMetadata } from './vault-protocol'
import { getCryptoProvider } from './provider/active-provider'
import {
  computeVaultKeyFingerprint,
  sealKeyToX25519Recipient,
  VAULT_KEY_KIND,
  wrapperContextFromMemberVaultKey,
  X25519_SEALED_BOX_V1,
} from './x25519-wrapper'

describe('openVaultProjection', () => {
  it('authenticates outer scope, unwraps VK and decrypts metadata', async () => {
    const sodium = await loadSodium()
    const member = sodium.crypto_box_keypair()
    const vaultKey = sodium.randombytes_buf(32)
    const organizationId = '00112233-4455-6677-8899-aabbccddeeff'
    const vaultId = '11112222-3333-4444-8555-666677778888'
    const memberId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
    const memberContract = { wrappedVaultKey: { descriptor: {
      protocolVersion: 2, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: 1 as const,
      scope: { organizationId, vaultId, memberId }, resourceRevision: '1', wrappedKeyVersion: 1,
      memberKeyGeneration: 1, recipientKeyKind: 5 as const, recipientKeyVersion: 1,
      recipientFingerprint: toBase64Url(await computeVaultKeyFingerprint(member.publicKey, VAULT_KEY_KIND.memberX25519)),
      parentDescriptorHash: null,
    }, encodedSealedKeyPackage: '' } }
    memberContract.wrappedVaultKey.encodedSealedKeyPackage = toBase64Url(await sealKeyToX25519Recipient(
      vaultKey, member.publicKey, wrapperContextFromMemberVaultKey(memberContract),
    ))
    const descriptor = {
      protocolVersion: 2, cryptoSuiteId: 'palladin-vault-xchacha-v1',
      purpose: ENVELOPE_PURPOSE.memberVaultMetadata,
      scope: { organizationId, vaultId },
      resourceRevision: '1', keyVersion: 1, memberKeyGeneration: 1, binding: {},
    } as const
    const metadataKey = await deriveVaultSubkey(vaultKey, {
      protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
      purpose: ENVELOPE_PURPOSE.memberVaultMetadata, organizationId,
      vaultId, keyVersion: 1, memberKeyGeneration: 1,
    })
    const envelope = await sealVaultEnvelope(descriptor, encodeMemberVaultMetadata({
      schema: 'palladin.member-vault-metadata.v1', name: 'Personal', description: null,
      icon: null, color: '#AABBCC', grantMode: 'granular',
    }), metadataKey)
    const opened = await openVaultProjection({
      id: vaultId, organizationId,
      memberKeyGeneration: 1, memberVaultMetadata: envelope, memberVaultKey: memberContract,
    }, member.privateKey, memberId)
    expect(opened.metadata.name).toBe('Personal')
    expect(Array.from(opened.vaultKey)).toEqual(Array.from(vaultKey))
    wipe(opened.vaultKey); wipe(vaultKey); wipe(metadataKey); wipe(member.privateKey)
  })
})

describe('sealMemberVaultMetadata', () => {
  it('wipes the derived metadata key when metadata validation fails', async () => {
    const vaultKey = new Uint8Array(32).fill(0x5a)
    const organizationId = '00112233-4455-6677-8899-aabbccddeeff'
    const vaultId = '11112222-3333-4444-8555-666677778888'
    const descriptor = {
      protocolVersion: 2, cryptoSuiteId: 'palladin-vault-xchacha-v1',
      purpose: ENVELOPE_PURPOSE.memberVaultMetadata, scope: { organizationId, vaultId },
      resourceRevision: '4', keyVersion: 1, memberKeyGeneration: 2, binding: {},
    } as const
    const expectedKey = await deriveVaultSubkey(vaultKey, {
      protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
      purpose: descriptor.purpose, organizationId, vaultId, keyVersion: 1, memberKeyGeneration: 2,
    })
    const provider = getCryptoProvider()
    const originalWipe = provider.wipe.bind(provider)
    const wiped: Uint8Array[] = []
    const wipeSpy = vi.spyOn(provider, 'wipe').mockImplementation((value) => {
      wiped.push(new Uint8Array(value))
      originalWipe(value)
    })
    try {
      await expect(sealMemberVaultMetadata(
        { id: vaultId, organizationId, memberKeyGeneration: 2 },
        { descriptor, encodedSuitePayload: '' },
        {
          schema: 'palladin.member-vault-metadata.v1', name: '', description: null,
          icon: null, color: '#AABBCC', grantMode: 'granular',
        },
        vaultKey,
      )).rejects.toThrow()
      expect(wiped).toContainEqual(expectedKey)
    } finally {
      wipeSpy.mockRestore()
      wipe(expectedKey); wipe(vaultKey)
    }
  })

  it('advances the authenticated revision without exposing metadata', async () => {
    const vaultKey = await (await loadSodium()).randombytes_buf(32)
    const organizationId = '00112233-4455-6677-8899-aabbccddeeff'
    const vaultId = '11112222-3333-4444-8555-666677778888'
    const descriptor = {
      protocolVersion: 2, cryptoSuiteId: 'palladin-vault-xchacha-v1',
      purpose: ENVELOPE_PURPOSE.memberVaultMetadata, scope: { organizationId, vaultId },
      resourceRevision: '4', keyVersion: 1, memberKeyGeneration: 2, binding: {},
    } as const
    const key = await deriveVaultSubkey(vaultKey, {
      protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
      purpose: descriptor.purpose, organizationId, vaultId, keyVersion: 1, memberKeyGeneration: 2,
    })
    const current = await sealVaultEnvelope(descriptor, encodeMemberVaultMetadata({
      schema: 'palladin.member-vault-metadata.v1', name: 'Old', description: null,
      icon: null, color: '#AABBCC', grantMode: 'granular',
    }), key)
    const next = await sealMemberVaultMetadata({ id: vaultId, organizationId, memberKeyGeneration: 2 }, current, {
      schema: 'palladin.member-vault-metadata.v1', name: 'New', description: null,
      icon: null, color: '#AABBCC', grantMode: 'granular',
    }, vaultKey)
    expect(next.descriptor.resourceRevision).toBe('5')
    expect(JSON.stringify(next)).not.toContain('New')
    wipe(key); wipe(vaultKey)
  })
})
