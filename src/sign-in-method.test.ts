import { describe, expect, it } from 'vitest'
import * as current from './current-vault-plaintext'
import * as legacy from './vault-plaintext'
import { createCapturedCredentialSecret, defaultCredentialAgentFieldAccess } from './credential-policy'
import { projectCanonicalCredentialDiscovery } from './credential-discovery'
import { sealCanonicalCredentialEntry } from './entry-protocol'
import { canonicalSignInDiscovery, SIGN_IN_FIELD_TYPE } from './sign-in-method'

const FIELD = 'custom:22222222-2222-4222-8222-222222222222'
const OTHER = 'custom:33333333-3333-4333-8333-333333333333'
const VAULT = '44444444-4444-4444-8444-444444444444'
const ENTRY = '55555555-5555-4555-8555-555555555555'

function credential(value: unknown, access: 'never' | 'discovery', extra: Partial<{ discoverable: boolean }> = {}) {
  const base = createCapturedCredentialSecret({ label: 'Example', username: '', password: '',
    url: 'https://app.example.com', urlDomain: 'app.example.com' })
  const discoverable = extra.discoverable ?? true
  return {
    ...base,
    discoverable,
    agentLabel: discoverable ? base.agentLabel : null,
    agentFieldAccess: { ...base.agentFieldAccess, [FIELD]: access,
      ...(discoverable ? {} : { agentLabel: 'never' as const, entryType: 'never' as const,
        'credential.username': 'never' as const, 'credential.urlDomain': 'never' as const }) },
    content: { ...base.content, customFields: [{ id: FIELD, label: 'Sign-in method', type: SIGN_IN_FIELD_TYPE, value }] },
  } as current.MemberSecretV1
}

const linked = { provider: 'google', account: 'work@corp.example', entry: { vaultId: VAULT, entryId: ENTRY } }

describe('palladin.signin.v1 discovery contract', () => {
  it.each([['current', current], ['legacy', legacy]] as const)(
    '%s projection exposes only the provider and the provider Credential reference', (_name, module) => {
      const secret = credential(linked, 'discovery')
      const discovery = module.projectAgentDiscovery(secret as never)!
      const field = discovery.fields.find((candidate) => candidate.id === 'signIn')!
      expect(JSON.parse(String(field.value))).toEqual({ schema: SIGN_IN_FIELD_TYPE, provider: 'google',
        entry: { vaultId: VAULT, entryId: ENTRY } })
      expect(field.value).toBe(canonicalSignInDiscovery({ schema: SIGN_IN_FIELD_TYPE, provider: 'google',
        entry: { vaultId: VAULT, entryId: ENTRY } }))
      expect(JSON.stringify(discovery)).not.toContain('work@corp.example')
      expect(discovery.fields.map((candidate) => candidate.id)).not.toContain(FIELD)
      expect(module.listGrantableFieldIds(secret as never)).not.toContain(FIELD)
    })

  it('keeps the method private with never and for a non-discoverable Credential', () => {
    expect(current.projectAgentDiscovery(credential(linked, 'never'))!.fields.map((field) => field.id)).not.toContain('signIn')
    expect(current.projectAgentDiscovery(credential(linked, 'discovery', { discoverable: false }))).toBeNull()
  })

  it('exposes a provider-only method without an Entry reference', () => {
    const field = current.projectAgentDiscovery(credential({ provider: 'apple', account: null, entry: null }, 'discovery'))!
      .fields.find((candidate) => candidate.id === 'signIn')!
    expect(JSON.parse(field.value)).toEqual({ schema: SIGN_IN_FIELD_TYPE, provider: 'apple', entry: null })
  })

  it.each([
    ['unknown provider', { provider: 'myspace', account: null, entry: null }],
    ['extra key', { ...linked, token: 'x' }],
    ['missing entry key', { provider: 'google', account: null }],
    ['bad entry id', { ...linked, entry: { vaultId: VAULT, entryId: 'not-a-uuid' } }],
    ['untrimmed account', { ...linked, account: ' a ' }],
  ])('rejects discovery for a malformed value (%s) but still allows never', (_name, value) => {
    expect(() => current.encodeMemberSecret(credential(value, 'discovery'))).toThrow(/Unsafe AgentFieldAccess/)
    expect(() => legacy.encodeMemberSecret(credential(value, 'discovery') as never)).toThrow(/Unsafe AgentFieldAccess/)
    expect(() => current.encodeMemberSecret(credential(value, 'never'))).not.toThrow()
  })

  it.each(['onGrantValue', 'onGrantRuntime', 'onGrantDerived'])('never allows %s', (access) => {
    const secret = credential(linked, 'discovery')
    expect(() => current.encodeMemberSecret({ ...secret, agentFieldAccess: { ...secret.agentFieldAccess, [FIELD]: access } } as never))
      .toThrow(/Unsafe AgentFieldAccess/)
  })

  it('does not allow discovery for the type on other Entry types', () => {
    const key = {
      schema: 'palladin.member-secret.v1', entryType: 'key', memberLabel: 'K', agentLabel: 'K', discoverable: true,
      description: null, icon: null, color: null,
      agentFieldAccess: { memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
        entryType: 'discovery', 'key.value': 'never', notes: 'never', [FIELD]: 'discovery' },
      content: { value: 'v', url: null, notes: null, customFields: [{ id: FIELD, label: 'x', type: SIGN_IN_FIELD_TYPE, value: linked }] },
    } as current.MemberSecretV1
    expect(() => current.encodeMemberSecret(key)).toThrow(/Unsafe AgentFieldAccess/)
  })

  it('exposes nothing when two methods are discoverable', () => {
    const secret = credential(linked, 'discovery')
    const two = { ...secret, agentFieldAccess: { ...secret.agentFieldAccess, [OTHER]: 'discovery' as const },
      content: { ...secret.content, customFields: [...secret.content.customFields,
        { id: OTHER, label: 'Sign-in method', type: SIGN_IN_FIELD_TYPE, value: { provider: 'github', account: null, entry: null } }] } }
    expect(current.projectAgentDiscovery(two as current.MemberSecretV1)!.fields.map((field) => field.id)).not.toContain('signIn')
  })

  it('defaults non-standard custom types to never', () => {
    expect(defaultCredentialAgentFieldAccess([{ id: FIELD, type: SIGN_IN_FIELD_TYPE }, { id: OTHER, type: 'text' }]))
      .toMatchObject({ [FIELD]: 'never', [OTHER]: 'onGrantValue' })
  })

  it('seals the canonical Credential Discovery with the sign-in field', async () => {
    const secret = credential(linked, 'discovery') as Extract<current.MemberSecretV1, { entryType: 'credential' }>
    expect(projectCanonicalCredentialDiscovery(secret)!.fields.some((field) => field.id === 'signIn')).toBe(true)
    const vaultKey = new Uint8Array(32).fill(1)
    const discoveryKey = new Uint8Array(32).fill(2)
    const sealed = await sealCanonicalCredentialEntry({ organizationId: '66666666-6666-4666-8666-666666666666', vaultId: VAULT,
      entryId: ENTRY, revision: '1', vaultKeyVersion: 1, vdkVersion: 1, memberKeyGeneration: 1 }, secret, vaultKey, discoveryKey, 1)
    expect(sealed.agentDiscovery).not.toBeNull()
  })
})
