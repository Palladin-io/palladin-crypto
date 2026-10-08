import { describe, expect, it } from 'vitest'
import { createEntryShareSnapshot } from './entry-share-selection'
import type { MemberSecretV1 } from './current-vault-plaintext'

const common = {
  schema: 'palladin.member-secret.v1' as const, memberLabel: 'Private title',
  agentLabel: 'Do not share', discoverable: true, description: 'Private description',
  icon: null, color: null, agentFieldAccess: { 'credential.password': 'onGrantValue' as const },
}
const totp = { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1' as const, digits: 6 as const, period: 30, issuer: null, account: null }
const source: MemberSecretV1 = { ...common, entryType: 'credential', content: {
  username: 'alice', password: '  secret\u0301  ', url: 'https://example.test', urlDomain: 'example.test',
  notes: 'Private notes', totp,
  customFields: [
    { id: 'custom:recovery', label: 'Recovery codes', type: 'concealed', value: 'Recovery secret' },
    { id: 'custom:otp', label: 'Second TOTP', type: 'totp', value: totp },
  ],
} }

describe('Whole Entry sharing', () => {
  it('includes every content field, preserving secrets without source policies', () => {
    const snapshot = createEntryShareSnapshot(source)
    expect(snapshot.title).toBe('Private title')
    expect(snapshot.fields.map((field) => field.id)).toEqual([
      'credential.username', 'credential.password', 'credential.url', 'credential.totp',
      'description', 'notes', 'custom:recovery', 'custom:otp',
    ])
    expect(snapshot.fields.find((field) => field.id === 'credential.password')?.value).toBe('  secret\u0301  ')
    expect(snapshot.fields.find((field) => field.id === 'notes')?.value).toBe('Private notes')
    expect(snapshot.fields.find((field) => field.id === 'description')?.value).toBe('Private description')
    const json = JSON.stringify(snapshot)
    for (const excluded of ['agentFieldAccess', 'discoverable', 'agentLabel', 'urlDomain']) {
      expect(json).not.toContain(excluded)
    }
  })

  it('includes native/custom TOTP and recovery codes without opt-in', () => {
    const snapshot = createEntryShareSnapshot(source)
    expect(snapshot.fields.find((field) => field.id === 'credential.totp')?.value).toContain('otpauth://totp/')
    expect(snapshot.fields.find((field) => field.id === 'custom:otp')?.value).toContain('otpauth://totp/')
    expect(snapshot.fields.find((field) => field.id === 'custom:recovery')?.value).toBe('Recovery secret')
  })

  it.each([
    { id: 'custom:future', label: 'Unknown', type: 'future', value: { unknown: true } },
    { id: 'custom:invalid', label: 'Invalid TOTP', type: 'totp', value: {} },
    { id: 'credential.password', label: 'Duplicate', type: 'text', value: 'duplicate' },
  ])('rejects the whole entry instead of silently omitting an unsupported or duplicate field', (field) => {
      const unsupported: MemberSecretV1 = { ...source, content: {
        ...source.content, customFields: [...source.content.customFields, field],
      } }
      expect(() => createEntryShareSnapshot(unsupported)).toThrow('Entry cannot be shared in full')
    },
  )

  it('does not include Script references, source scopes or execution policy', () => {
    const script: MemberSecretV1 = { ...common, entryType: 'script', content: {
      source: 'echo "$TOKEN"', interpreter: 'bash', notes: null, customFields: [],
      refs: [{ env: 'TOKEN', vaultId: 'private-vault', entryId: 'private-entry', fieldId: 'key.value' }],
      execution: { contractVersion: 1, description: 'private execution', parameters: [], returnResultToAgent: true },
    } }
    const snapshot = createEntryShareSnapshot(script)
    expect(snapshot.fields.map((field) => field.id)).toEqual(['script.source', 'script.interpreter', 'description'])
    for (const excluded of ['private-vault', 'private-entry', 'private execution', 'returnResultToAgent']) {
      expect(JSON.stringify(snapshot)).not.toContain(excluded)
    }
  })

  it('supports Key and Credit Card snapshots without adding other fields', () => {
    const key: MemberSecretV1 = { ...common, entryType: 'key', content: {
      value: 'key-secret', url: null, notes: null, customFields: [],
    } }
    expect(createEntryShareSnapshot(key).fields[0].value).toBe('key-secret')
    const card: MemberSecretV1 = { ...common, entryType: 'creditCard', content: {
      cardholderName: 'Test Person', cardNumber: '4111111111111111', expiryMonth: '09', expiryYear: '2030',
      billingAddress: 'Private address', notes: null, customFields: [],
      cvv: '007',
    } }
    const snapshot = createEntryShareSnapshot(card)
    expect(snapshot.fields.find((field) => field.id === 'creditCard.billingAddress')?.value).toBe('Private address')
    expect(snapshot.fields.find((field) => field.id === 'creditCard.cvv')).toMatchObject({ type: 'concealed', value: '007' })
    expect(snapshot.fields).toHaveLength(7)
  })
})
