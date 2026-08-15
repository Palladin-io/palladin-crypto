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
  type MemberVaultKeyEnvelopeContract,
  sealKeyToX25519Recipient,
  VAULT_KEY_KIND,
  wrapperContextFromMemberVaultKey,
  X25519_SEALED_BOX_V1,
} from './x25519-wrapper'

const organizationId = '00112233-4455-6677-8899-aabbccddeeff'
const vaultId = '11112222-3333-4444-8555-666677778888'
const memberId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

async function createEncryptedVaultProjection(vaultKeyVersion = 1, memberKeyGeneration = 1) {
  const sodium = await loadSodium()
  const member = sodium.crypto_box_keypair()
  const vaultKey = sodium.randombytes_buf(32)
  const memberContract: MemberVaultKeyEnvelopeContract = { wrappedVaultKey: { descriptor: {
    protocolVersion: 2, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: 1,
    scope: { organizationId, vaultId, memberId },
    resourceRevision: String(vaultKeyVersion), wrappedKeyVersion: vaultKeyVersion,
    memberKeyGeneration, recipientKeyKind: 5, recipientKeyVersion: 1,
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
    resourceRevision: '1', keyVersion: vaultKeyVersion, memberKeyGeneration, binding: {},
  } as const
  const metadataKey = await deriveVaultSubkey(vaultKey, {
    protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
    purpose: ENVELOPE_PURPOSE.memberVaultMetadata, organizationId,
    vaultId, keyVersion: vaultKeyVersion, memberKeyGeneration,
  })
  try {
    const envelope = await sealVaultEnvelope(descriptor, encodeMemberVaultMetadata({
      schema: 'palladin.member-vault-metadata.v1', name: 'Personal', description: null,
      icon: null, color: '#AABBCC', grantMode: 'granular',
    }), metadataKey)
    return {
      projection: {
        id: vaultId, organizationId, metadataRevision: descriptor.resourceRevision, memberKeyGeneration,
        currentKeyEpoch: { vaultKeyVersion },
        memberVaultMetadata: envelope, memberVaultKey: memberContract,
      },
      memberPrivateKey: member.privateKey,
      vaultKey,
    }
  } finally {
    wipe(metadataKey)
    wipe(member.publicKey)
  }
}

describe('openVaultProjection', () => {
  it('authenticates outer scope, unwraps VK and decrypts metadata', async () => {
    const fixture = await createEncryptedVaultProjection()
    try {
      const opened = await openVaultProjection(fixture.projection, fixture.memberPrivateKey, memberId)
      expect(opened.metadata.name).toBe('Personal')
      expect(Array.from(opened.vaultKey)).toEqual(Array.from(fixture.vaultKey))
      wipe(opened.vaultKey)
    } finally {
      wipe(fixture.vaultKey); wipe(fixture.memberPrivateKey)
    }
  })

  it.each([
    { name: 'only the authoritative Vault key version', memberKeyGeneration: 1 },
    { name: 'the Vault key version and Member-key generation together', memberKeyGeneration: 2 },
  ])('rejects the previous encrypted pair before unwrap when $name advances', async ({ memberKeyGeneration }) => {
    const fixture = await createEncryptedVaultProjection()
    const sodium = await loadSodium()
    const unwrap = vi.spyOn(sodium, 'crypto_box_seal_open')
    try {
      await expect(openVaultProjection({
        ...fixture.projection,
        memberKeyGeneration,
        currentKeyEpoch: { vaultKeyVersion: 2 },
      }, fixture.memberPrivateKey, memberId)).rejects.toThrow('does not match the outer Vault')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(fixture.vaultKey); wipe(fixture.memberPrivateKey)
    }
  })

  it('rejects old metadata before unwrap when the Member wrapper targets the current epoch', async () => {
    const old = await createEncryptedVaultProjection()
    const current = await createEncryptedVaultProjection(2, 2)
    const sodium = await loadSodium()
    const unwrap = vi.spyOn(sodium, 'crypto_box_seal_open')
    try {
      await expect(openVaultProjection({
        ...current.projection,
        memberVaultMetadata: old.projection.memberVaultMetadata,
      }, current.memberPrivateKey, memberId)).rejects.toThrow('metadata key version does not match')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(old.vaultKey); wipe(old.memberPrivateKey)
      wipe(current.vaultKey); wipe(current.memberPrivateKey)
    }
  })

  it('rejects a previous metadata revision within the current key epoch before unwrap', async () => {
    const fixture = await createEncryptedVaultProjection()
    const currentMetadata = await sealMemberVaultMetadata(
      fixture.projection,
      fixture.projection.memberVaultMetadata,
      {
        schema: 'palladin.member-vault-metadata.v1', name: 'Updated', description: null,
        icon: null, color: '#AABBCC', grantMode: 'granular',
      },
      fixture.vaultKey,
    )
    const sodium = await loadSodium()
    const unwrap = vi.spyOn(sodium, 'crypto_box_seal_open')
    try {
      await expect(openVaultProjection({
        ...fixture.projection,
        metadataRevision: currentMetadata.descriptor.resourceRevision,
      }, fixture.memberPrivateKey, memberId)).rejects.toThrow('metadata revision does not match')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(fixture.vaultKey); wipe(fixture.memberPrivateKey)
    }
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
