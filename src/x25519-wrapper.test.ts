import { describe, expect, it } from 'vitest'
import { toBase64Url } from './encoding'
import {
  computeVaultKeyFingerprint,
  VAULT_KEY_KIND,
  wrapperContextFromMemberVaultKey,
  X25519_SEALED_BOX_V1,
} from './x25519-wrapper'

describe('Member Vault-key wrapper context', () => {
  it('uses the frozen vkVersion rule and domain-separated Member fingerprint', async () => {
    const publicKey = new Uint8Array(32).fill(0x44)
    const fingerprint = await computeVaultKeyFingerprint(publicKey, VAULT_KEY_KIND.memberX25519)
    const context = wrapperContextFromMemberVaultKey({
      wrappedVaultKey: {
        descriptor: {
          protocolVersion: 2, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: 1,
          scope: { organizationId: '00112233-4455-6677-8899-aabbccddeeff', vaultId: '11112222-3333-4444-8555-666677778888', memberId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' },
          resourceRevision: '7', wrappedKeyVersion: 7, memberKeyGeneration: 3,
          recipientKeyKind: 5, recipientKeyVersion: 2,
          recipientFingerprint: toBase64Url(fingerprint), parentDescriptorHash: null,
        }, encodedSealedKeyPackage: toBase64Url(new Uint8Array(120)),
      },
    })
    expect(context).toMatchObject({
      purpose: 1,
      resourceRevision: 7n,
      wrappedKeyVersion: 7,
      recipientKeyKind: 5,
      recipientKeyVersion: 2,
    })
    expect(context.parentDescriptorHash).toBeUndefined()
  })

  it('rejects a downgraded wrapper protocol before any unwrap attempt', async () => {
    const fingerprint = await computeVaultKeyFingerprint(new Uint8Array(32), VAULT_KEY_KIND.memberX25519)
    expect(() => wrapperContextFromMemberVaultKey({
      wrappedVaultKey: {
        descriptor: {
          protocolVersion: 1, wrapperSuiteId: X25519_SEALED_BOX_V1, purpose: 1,
          scope: { organizationId: '00112233-4455-6677-8899-aabbccddeeff', vaultId: '11112222-3333-4444-8555-666677778888', memberId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' },
          resourceRevision: '1', wrappedKeyVersion: 1, memberKeyGeneration: 1,
          recipientKeyKind: 5, recipientKeyVersion: 1,
          recipientFingerprint: toBase64Url(fingerprint),
        }, encodedSealedKeyPackage: toBase64Url(new Uint8Array(120)),
      },
    })).toThrow('downgraded')
  })
})

