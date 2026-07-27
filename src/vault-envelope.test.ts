import { describe, expect, it } from 'vitest'
import { ENVELOPE_PURPOSE } from './envelope'
import { assertEnvelopeScope, openVaultEnvelope, sealVaultEnvelope } from './vault-envelope'

const descriptor = {
  protocolVersion: 2,
  cryptoSuiteId: 'palladin-vault-xchacha-v1',
  purpose: ENVELOPE_PURPOSE.memberIndex,
  scope: {
    organizationId: '00112233-4455-6677-8899-aabbccddeeff',
    vaultId: '11112222-3333-4444-8555-666677778888',
    entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  },
  resourceRevision: '1',
  keyVersion: 1,
  memberKeyGeneration: 1,
  binding: {},
} as const

describe('canonical Vault envelope boundary', () => {
  it('round-trips and binds the outer structural scope', async () => {
    const key = new Uint8Array(32).fill(7)
    const plaintext = new TextEncoder().encode('{"label":"local only"}')
    const envelope = await sealVaultEnvelope(descriptor, plaintext, key)
    assertEnvelopeScope(envelope.descriptor, {
      purpose: ENVELOPE_PURPOSE.memberIndex,
      organizationId: descriptor.scope.organizationId,
      vaultId: descriptor.scope.vaultId,
      entryId: descriptor.scope.entryId,
    })
    const opened = await openVaultEnvelope(envelope, key)
    expect(Array.from(opened)).toEqual(Array.from(plaintext))
  })

  it('rejects scope substitution, downgrade, and non-canonical revisions', async () => {
    expect(() => assertEnvelopeScope(descriptor, {
      purpose: ENVELOPE_PURPOSE.memberIndex,
      organizationId: descriptor.scope.organizationId,
      vaultId: descriptor.scope.vaultId,
      entryId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    })).toThrow(/outer resource scope/)
    await expect(sealVaultEnvelope({ ...descriptor, cryptoSuiteId: 'legacy' }, new Uint8Array(), new Uint8Array(32))).rejects.toThrow(/Unsupported/)
    await expect(sealVaultEnvelope({ ...descriptor, resourceRevision: '01' }, new Uint8Array(), new Uint8Array(32))).rejects.toThrow(/canonical decimal/)
  })
})

