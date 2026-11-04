import { describe, expect, it } from 'vitest'
import vectors from '../fixtures/key-wrapper-v1/vectors.json'
import { encodeKeyWrapperContext, type KeyWrapperDescriptor } from './key-wrapper'
import { KEY_WRAPPER_PURPOSE, RECIPIENT_KEY_KIND } from './registry'
import { fromWireKeyWrapperDescriptor, toWireKeyWrapperDescriptor, type WireKeyWrapperDescriptor } from './wire'

const descriptors = vectors.positive.map(({ descriptor }) => descriptor as KeyWrapperDescriptor)

describe('key-wrapper wire descriptors', () => {
  it.each(descriptors.map((descriptor) => [descriptor.purpose, descriptor.recipientKeyKind, descriptor] as const))(
    'round-trips purpose %i to key kind %i without changing the encoded context',
    (_purpose, _kind, descriptor) => {
      const wire = toWireKeyWrapperDescriptor(descriptor)
      expect(KEY_WRAPPER_PURPOSE[wire.purpose]).toBe(descriptor.purpose)
      expect(RECIPIENT_KEY_KIND[wire.recipientKeyKind]).toBe(descriptor.recipientKeyKind)
      const back = fromWireKeyWrapperDescriptor(wire)
      expect(back).toEqual(descriptor)
      expect(encodeKeyWrapperContext(back)).toEqual(encodeKeyWrapperContext(descriptor))
    },
  )

  it('uses the backend names', () => {
    const member = toWireKeyWrapperDescriptor(descriptors[0])
    expect([member.purpose, member.recipientKeyKind]).toEqual(['memberVaultKey', 'memberEncryption'])
  })

  it.each([
    ['an unknown purpose name', { purpose: 'memberX25519VaultKey' }, 'unsupported-purpose'],
    ['a numeric purpose', { purpose: 1 }, 'unsupported-purpose'],
    ['an inherited property name', { purpose: 'toString' }, 'unsupported-purpose'],
    ['a legacy key kind name', { recipientKeyKind: 'memberX25519' }, 'malformed-descriptor'],
    ['a signing key kind name', { recipientKeyKind: 'agentSigning' }, 'malformed-descriptor'],
  ])('rejects %s from the wire', (_case, change, code) => {
    const wire = { ...toWireKeyWrapperDescriptor(descriptors[0]), ...change } as unknown as WireKeyWrapperDescriptor
    expect(() => fromWireKeyWrapperDescriptor(wire)).toThrow(code)
  })

  it('rejects unregistered numeric values when writing to the wire', () => {
    expect(() => toWireKeyWrapperDescriptor({ ...descriptors[0], purpose: 10 })).toThrow('unsupported-purpose')
    expect(() => toWireKeyWrapperDescriptor({ ...descriptors[0], recipientKeyKind: 2 })).toThrow('malformed-descriptor')
  })
})
