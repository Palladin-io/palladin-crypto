import { describe, expect, it } from 'vitest'
import { computeFieldSetCommitment, encodeCanonicalEnvelopeAad } from './canonical-aad'
import { VAULT_XCHACHA20_POLY1305_V1 } from './crypto-suite'
import { ENVELOPE_PURPOSE } from './envelope'

const hex = (value: Uint8Array): string =>
  Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('')

const base = {
  protocolVersion: 2,
  cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
  organizationId: '00112233-4455-6677-8899-aabbccddeeff',
  vaultId: '10213243-5465-7687-98a9-bacbdcedfe0f',
  entryId: 'ffeeddcc-bbaa-4988-8776-665544332211',
  resourceRevision: 0x0102030405060708n,
  keyVersion: 0x10203040,
  memberKeyGeneration: 9,
} as const

describe('PLDNENV2 canonical AAD', () => {
  it('encodes stable scope and MemberSecret fields in network byte order', () => {
    const aad = encodeCanonicalEnvelopeAad(
      { ...base, purpose: ENVELOPE_PURPOSE.memberSecret },
      { operation: 3 },
    )
    expect(hex(aad)).toBe(
      '504c444e454e56320002001970616c6c6164696e2d7661756c742d786368616368612d7631' +
      '0006000700112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f' +
      'ffeeddccbbaa4988877666554433221101020304050607081020304001000000090003',
    )
  })

  it('sorts field IDs by ASCII bytes and matches the shared commitment vector', async () => {
    const commitment = await computeFieldSetCommitment(['password', 'user.name', 'a:1'])
    expect(hex(commitment)).toBe('9fb1d61da6459d78c887a94ee6f73ce509cdc2e584d250ed2b8c39b54373a9ad')
    await expect(computeFieldSetCommitment(['same', 'same'])).rejects.toThrow(/distinct/)
    await expect(computeFieldSetCommitment([])).rejects.toThrow(/empty/)
    await expect(computeFieldSetCommitment(['contains space'])).rejects.toThrow(/Invalid/)
  })

  it('matches the canonical backend Grant descriptor and field-set vectors', async () => {
    const fieldSetCommitment = await computeFieldSetCommitment(['password', 'username'])
    expect(hex(fieldSetCommitment)).toBe('f4efe1b64791880d2f2bcd96905ae75bb39a8c5212a9b77831e9376699372708')

    const aad = encodeCanonicalEnvelopeAad(
      {
        protocolVersion: 2,
        cryptoSuiteId: VAULT_XCHACHA20_POLY1305_V1,
        purpose: ENVELOPE_PURPOSE.grant,
        organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888',
        entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        grantOrRequestId: '12345678-1234-4234-8234-1234567890ab',
        agentId: 'fedcba98-7654-4321-8765-abcdefabcdef',
        resourceRevision: 7,
        keyVersion: 3,
        memberKeyGeneration: 9,
      },
      {
        entryRevision: 6,
        wrapperSuiteId: 'palladin-x25519-sealed-box-v1',
        recipientKeyVersion: 4,
        recipientKeyFingerprint: new Uint8Array(32).fill(0x5a),
        methods: 3,
        fieldSetCommitment: new Uint8Array(32).fill(0xa5),
        expiresAt: { seconds: 1_700_000_000, nanoseconds: 123_456_789 },
        remainingUses: 5,
      },
    )
    expect(hex(aad)).toBe(
      '504c444e454e56320002001970616c6c6164696e2d7661756c742d786368616368612d7631' +
      '000a001f00112233445566778899aabbccddeeff11112222333344448555666677778888' +
      'aaaaaaaabbbb4ccc8dddeeeeeeeeeeee123456781234423482341234567890ab' +
      'fedcba98765443218765abcdefabcdef0000000000000007000000030100000009' +
      '0000000000000006001d70616c6c6164696e2d7832353531392d7365616c65642d626f782d7631' +
      '000000045a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a' +
      '0003a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5' +
      '01000000006553f100075bcd150100000005',
    )
  })

  it('rejects missing purpose extensions and non-RFC UUIDs', () => {
    expect(() => encodeCanonicalEnvelopeAad({ ...base, purpose: ENVELOPE_PURPOSE.memberSecret })).toThrow(/operation/)
    expect(() => encodeCanonicalEnvelopeAad({ ...base, organizationId: 'not-a-uuid', purpose: ENVELOPE_PURPOSE.memberIndex })).toThrow(/RFC 4122/)
  })
})

