import { describe, expect, it } from 'vitest'
import { createCapturedCredentialSecret, defaultCredentialAgentFieldAccess } from './credential-policy'
import { encodeMemberSecret, parseMemberSecret, projectAgentDiscovery, projectGrantPayload } from './vault-plaintext'

describe('shared Credential capture defaults', () => {
  const input = { label: ' Example ', username: ' alice ', password: ' p ',
    url: 'https://accounts.example.com', urlDomain: 'accounts.example.com' }

  it('matches the canonical web Credential policy', () => {
    expect(defaultCredentialAgentFieldAccess()).toEqual({
      memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
      entryType: 'discovery', notes: 'onGrantValue',
      'credential.username': 'discovery', 'credential.urlDomain': 'discovery',
      'credential.url': 'onGrantValue', 'credential.password': 'onGrantValue', 'credential.totp': 'onGrantDerived',
    })
  })
  it('preserves literal password bytes through the canonical encoder', () => {
    const secret = createCapturedCredentialSecret(input)
    expect(parseMemberSecret(encodeMemberSecret(secret))).toEqual(secret)
    expect(secret.content.password).toBe(' p ')
    expect(secret.memberLabel).toBe('Example')
    expect(secret.content.username).toBe('alice')
  })
  it('projects password only into an explicitly selected grant, never discovery', async () => {
    const secret = createCapturedCredentialSecret(input)
    expect(JSON.stringify(projectAgentDiscovery(secret))).not.toContain(' p ')
    expect(await projectGrantPayload(secret, ['credential.password'])).toMatchObject({
      fields: [{ id: 'credential.password', kind: 'concealed', mode: 'value', value: ' p ' }],
    })
  })
  it('returns independent policy objects', () => {
    const policy = defaultCredentialAgentFieldAccess()
    policy['credential.password'] = 'never'
    expect(defaultCredentialAgentFieldAccess()['credential.password']).toBe('onGrantValue')
  })
  it('shares custom-field defaults without double-prefixing IDs', () => {
    expect(defaultCredentialAgentFieldAccess([{ id: 'tenant', type: 'text' }, { id: 'custom:otp', type: 'totp' }]))
      .toMatchObject({ 'custom:tenant': 'onGrantValue', 'custom:otp': 'onGrantDerived' })
  })
})
