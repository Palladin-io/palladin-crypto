import { describe, expect, it } from 'vitest'
import {
  encodeMemberSecret,
  parseMemberSecret,
  projectAgentDiscovery,
  projectGrantPayload,
  projectMemberIndex,
  type MemberSecretV1,
} from './vault-plaintext'

const secret: MemberSecretV1 = {
  schema: 'palladin.member-secret.v1',
  entryType: 'credential',
  memberLabel: 'GitHub work',
  agentLabel: 'GitHub account',
  discoverable: true,
  description: null,
  icon: { kind: 'glyph', value: 'key' },
  color: '#AABBCC',
  content: {
    username: 'member@example.com', password: 'secret', url: 'https://github.com/login',
    urlDomain: 'github.com', totp: { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, issuer: null, account: null }, notes: null,
    customFields: [{ id: 'custom:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', label: 'Tenant', type: 'text', value: 'Acme' }],
  },
  agentFieldAccess: {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never', entryType: 'discovery',
    'credential.username': 'discovery', 'credential.password': 'onGrantValue', 'credential.url': 'onGrantValue',
    'credential.urlDomain': 'discovery', 'credential.totp': 'onGrantDerived', notes: 'never',
    'custom:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee': 'onGrantValue',
  },
}

describe('Vault plaintext v1', () => {
  it('serializes JCS deterministically and round-trips the closed MemberSecret', () => {
    const encoded = encodeMemberSecret(secret)
    const json = new TextDecoder().decode(encoded)
    expect(json.indexOf('"agentFieldAccess"')).toBeLessThan(json.indexOf('"agentLabel"'))
    expect(parseMemberSecret(encoded)).toEqual(secret)
  })

  it('rejects duplicate properties, unknown top-level fields, and unsafe policy maps', () => {
    expect(() => parseMemberSecret(new TextEncoder().encode('{"schema":"x","schema":"y"}'))).toThrow(/Duplicate/)
    expect(() => encodeMemberSecret({ ...secret, unexpected: true } as MemberSecretV1)).toThrow()
    expect(() => encodeMemberSecret({ ...secret, agentFieldAccess: { ...secret.agentFieldAccess, extra: 'never' } })).toThrow(/exactly match/)
    expect(() => encodeMemberSecret({ ...secret, agentFieldAccess: { ...secret.agentFieldAccess, 'credential.password': 'discovery' } })).toThrow(/Unsafe/)
  })

  it('projects bounded MemberIndex and only explicitly allowed Agent fields', () => {
    expect(projectMemberIndex(secret)).toMatchObject({
      memberLabel: 'GitHub work', username: 'member@example.com', urlDomain: 'github.com',
      customIndex: [{ id: 'custom:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', value: 'Acme' }],
    })
    expect(projectAgentDiscovery(secret)).toEqual({
      schema: 'palladin.agent-discovery.v1', entryType: 'credential', agentLabel: 'GitHub account',
      capabilities: ['get', 'exec'],
      fields: [
        { id: 'credential.urlDomain', value: 'github.com' },
        { id: 'credential.username', value: 'member@example.com' },
      ],
    })
  })

  it('builds a sorted least-privilege GrantPayload and rejects Discovery fields', () => {
    expect(projectGrantPayload(secret, ['credential.totp', 'credential.password'])).toEqual({
      schema: 'palladin.grant-payload.v1', entryType: 'credential',
      fields: [
        { id: 'credential.password', kind: 'concealed', mode: 'value', value: 'secret' },
        { id: 'credential.totp', kind: 'totp', mode: 'derived', value: { secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, issuer: null, account: null } },
      ],
    })
    expect(() => projectGrantPayload(secret, ['credential.username'])).toThrow(/not grantable/)
  })

  it('round-trips cards without dedicated CVV or PIN and keeps delivery inject-only', () => {
    const card: MemberSecretV1 = {
      ...secret,
      entryType: 'creditCard',
      content: {
        cardholderName: 'Ada Lovelace',
        cardNumber: '4242424242424242',
        expiryMonth: '12',
        expiryYear: '2030',
        billingAddress: '1 Main St',
        notes: null,
        customFields: [],
      },
      agentFieldAccess: {
        memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never',
        color: 'never', entryType: 'discovery',
        'creditCard.cardholderName': 'onGrantRuntime',
        'creditCard.cardNumber': 'onGrantRuntime',
        'creditCard.expiryMonth': 'onGrantRuntime',
        'creditCard.expiryYear': 'onGrantRuntime',
        'creditCard.billingAddress': 'onGrantRuntime',
        notes: 'never',
      },
    }

    const encoded = encodeMemberSecret(card)
    expect(new TextDecoder().decode(encoded)).not.toMatch(/securityCode|CVV|CVC|"pin"/i)
    expect(parseMemberSecret(encoded)).toEqual(card)
    expect(projectMemberIndex(card)).toMatchObject({ entryType: 'creditCard', username: null, urlDomain: null })
    expect(projectAgentDiscovery(card)).toMatchObject({ capabilities: ['inject'], fields: [] })
    expect(projectGrantPayload(card, ['creditCard.cardNumber']).fields[0]).toMatchObject({
      kind: 'concealed', mode: 'runtime', value: '4242424242424242',
    })
    expect(() => encodeMemberSecret({
      ...card,
      content: { ...card.content, securityCode: '123' },
    } as MemberSecretV1)).toThrow()
    expect(() => encodeMemberSecret({
      ...card,
      agentFieldAccess: { ...card.agentFieldAccess, 'creditCard.cardNumber': 'onGrantValue' },
    })).toThrow(/Unsafe/)
  })
})
