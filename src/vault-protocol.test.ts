import { describe, expect, it, vi } from 'vitest'
import { ENVELOPE_PURPOSE } from './envelope'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { toBase64Url } from './encoding'
import { deriveVaultSubkey } from './hkdf'
import { randomBytes, wipe } from './sodium'
import { encodeMemberVaultMetadata } from './vault-plaintext'
import { sealVaultEnvelope } from './vault-envelope'
import {
  openMemberVaultKey,
  openMemberVaultMetadata,
  openVaultProjection,
  sealMemberVaultMetadata,
  type MemberVaultKeyEnvelopeContract,
} from './vault-protocol'
import { getCryptoProvider } from './provider/active-provider'
import {
  computeRecipientFingerprint,
  encodeKeyWrapperContext,
  generateRecipientKeyPair,
  sealKey,
  type KeyWrapperRecipient,
} from './key-wrapper/key-wrapper'
import { wrapperContextHash } from './key-wrapper/context'
import { KEY_WRAPPER_SUITE } from './key-wrapper/registry'
import { x25519SealedBoxV1 } from './key-wrapper/suites/x25519-sealed-box-v1'
import { xwingV1 } from './key-wrapper/suites/xwing-v1'

const organizationId = '00112233-4455-6677-8899-aabbccddeeff'
const vaultId = '11112222-3333-4444-8555-666677778888'
const memberId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

async function memberKeyFor(suite: string): Promise<KeyWrapperRecipient> {
  if (suite === KEY_WRAPPER_SUITE.active) {
    const pair = await generateRecipientKeyPair()
    return { ...pair, keyKind: 5, keyVersion: 1 }
  }
  const pair = getCryptoProvider().boxKeypair()
  return { keySuiteId: suite, keyKind: 5, keyVersion: 1, publicKey: pair.publicKey, privateKey: pair.privateKey }
}

async function createEncryptedVaultProjection(
  vaultKeyVersion = 1,
  memberKeyGeneration = 1,
  suite: string = KEY_WRAPPER_SUITE.active,
) {
  await getCryptoProvider().ready()
  const memberKey = await memberKeyFor(suite)
  const vaultKey = getCryptoProvider().randomBytes(32)
  const memberContract: MemberVaultKeyEnvelopeContract = { wrappedVaultKey: { descriptor: {
    protocolVersion: 2, wrapperSuiteId: suite, purpose: 1,
    scope: { organizationId, vaultId, memberId },
    resourceRevision: String(vaultKeyVersion), wrappedKeyVersion: vaultKeyVersion,
    memberKeyGeneration, recipientKeyKind: 5, recipientKeyVersion: 1,
    recipientFingerprint: toBase64Url(computeRecipientFingerprint(suite, 5, memberKey.publicKey)),
    parentDescriptorHash: null,
  }, encodedSealedKeyPackage: '' } }
  const descriptor0 = memberContract.wrappedVaultKey.descriptor
  // Existing read-only envelopes are produced directly by the frozen suite; sealKey refuses it.
  memberContract.wrappedVaultKey.encodedSealedKeyPackage = suite === KEY_WRAPPER_SUITE.active
    ? await sealKey(descriptor0, vaultKey, memberKey)
    : toBase64Url(await x25519SealedBoxV1.seal(vaultKey, memberKey.publicKey, wrapperContextHash(encodeKeyWrapperContext(descriptor0))))
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
      memberKey,
      vaultKey,
    }
  } finally {
    wipe(metadataKey)
  }
}

describe('openVaultProjection', () => {
  it('authenticates outer scope, unwraps VK and decrypts metadata', async () => {
    const fixture = await createEncryptedVaultProjection()
    try {
      const opened = await openVaultProjection(fixture.projection, fixture.memberKey, memberId)
      expect(opened.metadata.name).toBe('Personal')
      expect(Array.from(opened.vaultKey)).toEqual(Array.from(fixture.vaultKey))
      wipe(opened.vaultKey)
    } finally {
      wipe(fixture.vaultKey); wipe(fixture.memberKey.privateKey!)
    }
  })

  it('opens a legacy read-only Member envelope with the directory key of that suite', async () => {
    const fixture = await createEncryptedVaultProjection(1, 1, KEY_WRAPPER_SUITE.legacy)
    try {
      const vaultKey = await openMemberVaultKey(fixture.projection.memberVaultKey, fixture.memberKey)
      expect(vaultKey).toEqual(fixture.vaultKey)
      expect((await openMemberVaultMetadata(fixture.projection, vaultKey)).name).toBe('Personal')
      wipe(vaultKey)
    } finally {
      wipe(fixture.vaultKey); wipe(fixture.memberKey.privateKey!)
    }
  })

  it('rejects a directory key of another suite or kind before unwrap', async () => {
    const fixture = await createEncryptedVaultProjection()
    const unwrap = vi.spyOn(xwingV1, 'open')
    try {
      await expect(openVaultProjection(fixture.projection, { ...fixture.memberKey, keySuiteId: KEY_WRAPPER_SUITE.legacy }, memberId))
        .rejects.toThrow('recipient-mismatch')
      await expect(openMemberVaultKey(fixture.projection.memberVaultKey, { ...fixture.memberKey, keyKind: 1 }))
        .rejects.toThrow('Invalid Member Vault-key wrapper descriptor')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(fixture.vaultKey); wipe(fixture.memberKey.privateKey!)
    }
  })

  it.each([
    { name: 'only the authoritative Vault key version', memberKeyGeneration: 1 },
    { name: 'the Vault key version and Member-key generation together', memberKeyGeneration: 2 },
  ])('rejects the previous encrypted pair before unwrap when $name advances', async ({ memberKeyGeneration }) => {
    const fixture = await createEncryptedVaultProjection()
    const unwrap = vi.spyOn(xwingV1, 'open')
    try {
      await expect(openVaultProjection({
        ...fixture.projection,
        memberKeyGeneration,
        currentKeyEpoch: { vaultKeyVersion: 2 },
      }, fixture.memberKey, memberId)).rejects.toThrow('does not match the outer Vault')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(fixture.vaultKey); wipe(fixture.memberKey.privateKey!)
    }
  })

  it('rejects old metadata before unwrap when the Member wrapper targets the current epoch', async () => {
    const old = await createEncryptedVaultProjection()
    const current = await createEncryptedVaultProjection(2, 2)
    const unwrap = vi.spyOn(xwingV1, 'open')
    try {
      await expect(openVaultProjection({
        ...current.projection,
        memberVaultMetadata: old.projection.memberVaultMetadata,
      }, current.memberKey, memberId)).rejects.toThrow('metadata key version does not match')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(old.vaultKey); wipe(old.memberKey.privateKey!)
      wipe(current.vaultKey); wipe(current.memberKey.privateKey!)
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
    const unwrap = vi.spyOn(xwingV1, 'open')
    try {
      await expect(openVaultProjection({
        ...fixture.projection,
        metadataRevision: currentMetadata.descriptor.resourceRevision,
      }, fixture.memberKey, memberId)).rejects.toThrow('metadata revision does not match')
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(fixture.vaultKey); wipe(fixture.memberKey.privateKey!)
    }
  })

  it.each([
    { name: 'non-canonical', revision: '01', error: /canonical decimal/ },
    { name: 'out-of-range', revision: '18446744073709551616', error: /exceeds UInt64/ },
  ])('rejects matching $name metadata revisions before unwrap', async ({ revision, error }) => {
    const fixture = await createEncryptedVaultProjection()
    const unwrap = vi.spyOn(xwingV1, 'open')
    try {
      await expect(openVaultProjection({
        ...fixture.projection,
        metadataRevision: revision,
        memberVaultMetadata: {
          ...fixture.projection.memberVaultMetadata,
          descriptor: {
            ...fixture.projection.memberVaultMetadata.descriptor,
            resourceRevision: revision,
          },
        },
      }, fixture.memberKey, memberId)).rejects.toThrow(error)
      expect(unwrap).not.toHaveBeenCalled()
    } finally {
      unwrap.mockRestore()
      wipe(fixture.vaultKey); wipe(fixture.memberKey.privateKey!)
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
    const vaultKey = await randomBytes(32)
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
