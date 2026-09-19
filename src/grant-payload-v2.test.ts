import { describe, expect, it } from 'vitest'
import {
  encodeGrantPayloadV2, parseGrantPayloadV2, projectGrantPayloadV2,
  parseGrantPayload, type MemberSecretV1,
} from './current-vault-plaintext'

const customId = 'custom:11111111-2222-4333-8444-555555555555'
// RFC 6238 published test material, never a user credential.
const source = { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 8, period: 30 } as const
const secret: MemberSecretV1 = {
  schema: 'palladin.member-secret.v1', entryType: 'credential', memberLabel: 'Test',
  agentLabel: 'Test', description: null, icon: null, color: null, discoverable: true,
  agentFieldAccess: {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
    entryType: 'discovery', 'credential.username': 'onGrantValue', 'credential.password': 'onGrantValue',
    'credential.url': 'never', 'credential.urlDomain': 'discovery', 'credential.totp': 'onGrantDerived',
    notes: 'never', [customId]: 'onGrantDerived',
  },
  content: { username: 'test', password: 'synthetic-password', url: null, urlDomain: null,
    totp: { ...source, issuer: null, account: null }, notes: null,
    customFields: [{ id: customId, label: 'MFA', type: 'totp', value: { ...source, issuer: null, account: null } }],
  },
}

describe('operation-time GrantPayload v2', () => {
  it('projects only the explicitly approved primary/custom TOTP sources', async () => {
    const payload = await projectGrantPayloadV2(secret, [customId, 'credential.totp'])
    expect(payload).toEqual({ schema: 'palladin.grant-payload.v2', entryType: 'credential', fields: [
      { id: 'credential.totp', kind: 'totp', mode: 'derived', value: { source: 'totp', ...source } },
      { id: customId, kind: 'totp', mode: 'derived', value: { source: 'totp', ...source } },
    ] })
    expect(parseGrantPayloadV2(encodeGrantPayloadV2(payload))).toEqual(payload)
    expect(() => parseGrantPayload(encodeGrantPayloadV2(payload))).toThrow()
  })
  it('does not add a TOTP source to a restricted password grant', async () => {
    const payload = await projectGrantPayloadV2(secret, ['credential.password'])
    expect(payload.fields.map(({ id }) => id)).toEqual(['credential.password'])
    expect(new TextDecoder().decode(encodeGrantPayloadV2(payload))).not.toContain(source.secret)
    await expect(projectGrantPayloadV2({ ...secret, agentFieldAccess: { ...secret.agentFieldAccess, 'credential.totp': 'never' } }, ['credential.totp'])).rejects.toThrow()
  })
  it.each([
    { ...source, source: 'unknown' }, { ...source, source: 'totp', issuer: 'extra' },
    { ...source, source: 'totp', digits: 7 }, { ...source, source: 'totp', period: 0 },
    { ...source, source: 'totp', secret: 'MY======' }, { ...source, source: 'totp', secret: 'MZ' },
    { code: '12345678', expiresIn: 30 },
  ])('rejects malformed/frozen source without exposing its value', (value) => {
    const payload = { schema: 'palladin.grant-payload.v2', entryType: 'credential', fields: [
      { id: 'credential.totp', kind: 'totp', mode: 'derived', value },
    ] }
    expect(() => encodeGrantPayloadV2(payload as Parameters<typeof encodeGrantPayloadV2>[0])).toThrow()
  })
})

describe('protocol repository v2 vectors', () => {
  it('accepts exact shared canonical bytes and rejects every invalid source', async () => {
    const { default: fixture } = await import('./fixtures/grant-payload-v2/vectors.json')
    for (const vector of fixture.vectors) {
      const bytes = new TextEncoder().encode(vector.plaintextCanonical)
      expect(parseGrantPayloadV2(bytes)).toEqual(vector.plaintext)
      expect(encodeGrantPayloadV2(parseGrantPayloadV2(bytes))).toEqual(bytes)
      expect(() => parseGrantPayload(bytes)).toThrow()
      expect(() => parseGrantPayloadV2(new TextEncoder().encode(' ' + vector.plaintextCanonical))).toThrow()
    }
    for (const vector of fixture.invalidSources) {
      try {
        encodeGrantPayloadV2(vector.plaintext as Parameters<typeof encodeGrantPayloadV2>[0])
        throw new Error('Expected source rejection')
      } catch (error) {
        expect((error as Error).message).toBe('Invalid GrantPayload v2')
        expect((error as Error).message).not.toContain(source.secret)
      }
    }
  })
})
