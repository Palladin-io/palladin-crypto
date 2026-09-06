import { describe, expect, it } from 'vitest'
import { encodeCanonicalEnvelopeAad, encodeDeliveryBoundGrantAad, X25519_WRAPPER_SUITE_ID } from './canonical-aad'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { ENVELOPE_PURPOSE, type EnvelopeDescriptor, type GrantAadExtension } from './envelope'

const descriptor: EnvelopeDescriptor = {
  protocolVersion: 2, cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1, purpose: ENVELOPE_PURPOSE.grant,
  organizationId: '00112233-4455-6677-8899-aabbccddeeff', vaultId: '11112222-3333-4444-8555-666677778888',
  entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', grantOrRequestId: '12345678-1234-4234-8234-1234567890ab',
  agentId: 'fedcba98-7654-4321-8765-abcdefabcdef', resourceRevision: 7n, keyVersion: 3, memberKeyGeneration: 9,
}
const extension: GrantAadExtension & { deliveryPolicy: 0 | 1 | 2 } = {
  entryRevision: 6n, wrapperSuiteId: X25519_WRAPPER_SUITE_ID, recipientKeyVersion: 4,
  recipientKeyFingerprint: new Uint8Array(32).fill(0x5a), methods: 3, deliveryPolicy: 0,
  fieldSetCommitment: new Uint8Array(32).fill(0xa5), expiresAt: { seconds: 1_700_000_000n, nanoseconds: 123_456_789 },
  remainingUses: 5,
}
const hex = (value: Uint8Array) => [...value].map((byte) => byte.toString(16).padStart(2, '0')).join('')

describe('canonical API delivery-bound Grant AAD', () => {
  it('matches the backend EnvelopeDescriptorCodecTests frozen vector', () => {
    expect(hex(encodeDeliveryBoundGrantAad(descriptor, extension))).toBe(
      '504c444e454e56320002001970616c6c6164696e2d7661756c742d786368616368612d7631' +
      '000a001f00112233445566778899aabbccddeeff11112222333344448555666677778888' +
      'aaaaaaaabbbb4ccc8dddeeeeeeeeeeee123456781234423482341234567890abfedcba98765443218765abcdefabcdef' +
      '00000000000000070000000301000000090000000000000006001d70616c6c6164696e2d7832353531392d7365616c65642d626f782d7631' +
      '000000045a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a00030000' +
      'a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5' +
      '01000000006553f100075bcd150100000005',
    )
  })
  it('keeps the published generic encoder stable and binds policy only in the new API', () => {
    const previous = encodeCanonicalEnvelopeAad(descriptor, extension)
    const current = encodeDeliveryBoundGrantAad(descriptor, extension)
    expect(current.length).toBe(previous.length + 2)
    expect(encodeCanonicalEnvelopeAad(descriptor, { ...extension, deliveryPolicy: 2 } as GrantAadExtension)).toEqual(previous)
    expect(encodeDeliveryBoundGrantAad(descriptor, { ...extension, deliveryPolicy: 2 })).not.toEqual(current)
  })
  it('rejects other purposes and invalid policies', () => {
    expect(() => encodeDeliveryBoundGrantAad({ ...descriptor, purpose: ENVELOPE_PURPOSE.memberSecret }, extension)).toThrow()
    expect(() => encodeDeliveryBoundGrantAad(descriptor, { ...extension, deliveryPolicy: 3 as 0 })).toThrow()
  })
})
