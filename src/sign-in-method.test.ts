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

describe('multiple sign-in methods', () => {
  function multiple() {
    const secret = credential(linked, 'discovery')
    secret.content.customFields.push({ id: OTHER, label: 'Private label', type: 'palladin.signin.v2',
      value: { ...linked, account: 'second@corp.example' } })
    secret.agentFieldAccess[OTHER] = 'discovery'
    secret.content.customFields.reverse()
    return secret
  }
  it.each([['current', current], ['legacy', legacy]] as const)('%s projects mixed methods sorted by ID without accounts or labels', (_, module) => {
    const projected = module.projectAgentDiscovery(multiple() as never)!
    expect(projected.fields.find(f => f.id === 'signIn')).toBeUndefined()
    expect(JSON.parse(String(projected.fields.find(f => f.id === 'signInMethods')!.value))).toEqual({
      schema: 'palladin.signin.v2', methods: [FIELD, OTHER].map(id => ({ id, provider: 'google', entry: linked.entry })),
    })
    expect(JSON.stringify(projected)).not.toMatch(/corp.example|Private label/)
  })
  it('keeps hidden methods private and suppresses singleton even if the v2 field is hidden', () => {
    const secret = multiple()
    secret.agentFieldAccess[OTHER] = 'never'
    const fields = current.projectAgentDiscovery(secret)!.fields
    expect(fields.some(f => f.id === 'signIn')).toBe(false)
    expect(JSON.parse(fields.find(f => f.id === 'signInMethods')!.value).methods.map((m: {id:string}) => m.id)).toEqual([FIELD])
  })
  it.each([['current', current], ['legacy', legacy]] as const)('%s preserves legacy UUID spelling when a hidden v2 method is added', (_, module) => {
    const secret = multiple()
    const originalId = 'custom:AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'
    secret.content.customFields.find(field => field.id === FIELD)!.id = originalId
    delete secret.agentFieldAccess[FIELD]
    secret.agentFieldAccess[originalId] = 'discovery'
    secret.agentFieldAccess[OTHER] = 'never'
    const parsed = module.parseMemberSecret(module.encodeMemberSecret(secret as never))
    const fields = module.projectAgentDiscovery(parsed as never)!.fields
    expect(fields.some(field => field.id === 'signIn')).toBe(false)
    expect(JSON.parse(String(fields.find(field => field.id === 'signInMethods')?.value)).methods)
      .toEqual([{ id: originalId, provider: 'google', entry: linked.entry }])
  })
  it('preserves opaque types and rejects their discovery', () => {
    const secret = multiple()
    secret.content.customFields[0]!.type = 'palladin.signin.v99'
    expect(() => current.encodeMemberSecret(secret)).toThrow(/Unsafe AgentFieldAccess/)
    secret.agentFieldAccess[OTHER] = 'never'
    expect(current.parseMemberSecret(current.encodeMemberSecret(secret))).toEqual(secret)
  })
  it('rejects malformed v2 discovery but preserves it when hidden', () => {
    const secret = multiple()
    secret.content.customFields[0]!.value = { ...linked, token: 'synthetic' }
    expect(() => current.encodeMemberSecret(secret)).toThrow(/Unsafe AgentFieldAccess/)
    secret.agentFieldAccess[OTHER] = 'never'
    expect(() => current.encodeMemberSecret(secret)).not.toThrow()
  })
})

describe('strict v2 helpers', () => {
  it('accepts multiple same-provider methods without exposing their accounts', async () => {
    const { projectSignInMethodsDiscovery, canonicalSignInMethodsDiscovery, signInMethodsDiscoverySchema } = await import('./sign-in-method')
    const fields = [OTHER, FIELD].map(id => ({ id, type: 'palladin.signin.v2', value: linked }))
    const projected = projectSignInMethodsDiscovery('credential', fields, { [FIELD]: 'discovery', [OTHER]: 'discovery' })!
    const wire = canonicalSignInMethodsDiscovery(projected.value)
    expect(wire).toBe(`{"methods":[{"entry":{"entryId":"${ENTRY}","vaultId":"${VAULT}"},"id":"${FIELD}","provider":"google"},{"entry":{"entryId":"${ENTRY}","vaultId":"${VAULT}"},"id":"${OTHER}","provider":"google"}],"schema":"palladin.signin.v2"}`)
    expect(signInMethodsDiscoverySchema.safeParse(JSON.parse(wire)).success).toBe(true)
    for (const invalid of [
      { ...projected.value, schema: 'palladin.signin.v3' },
      { ...projected.value, account: 'synthetic' },
      { ...projected.value, methods: [...projected.value.methods].reverse() },
      { ...projected.value, methods: [projected.value.methods[0], projected.value.methods[0]] },
      { ...projected.value, methods: [{ ...projected.value.methods[0], label: 'private' }] },
      { ...projected.value, methods: [{ ...projected.value.methods[0], id: 'custom:not-a-uuid' }] },
    ]) expect(signInMethodsDiscoverySchema.safeParse(invalid).success).toBe(false)
    expect(projectSignInMethodsDiscovery('key', fields, { [FIELD]: 'discovery' })).toBeNull()
    expect(projectSignInMethodsDiscovery('credential', fields, { [FIELD]: 'never', [OTHER]: 'never' })).toBeNull()
    expect(projectSignInMethodsDiscovery('credential', [fields[0]!, fields[0]!], { [OTHER]: 'discovery' })).toBeNull()
  })
  it.each(['onGrantValue', 'onGrantRuntime', 'onGrantDerived'])('rejects v2 %s while defaulting to never', access => {
    const secret = credential(linked, 'discovery')
    secret.content.customFields[0]!.type = 'palladin.signin.v2'
    expect(defaultCredentialAgentFieldAccess(secret.content.customFields)[FIELD]).toBe('never')
    expect(() => current.encodeMemberSecret({ ...secret, agentFieldAccess: { ...secret.agentFieldAccess, [FIELD]: access } } as never)).toThrow(/Unsafe AgentFieldAccess/)
  })
})

describe('protocol v2 conformance fixtures', () => {
  it('accepts the language-neutral positives and rejects all negative vectors', async () => {
    const { signInMethodsDiscoverySchema } = await import('./sign-in-method')
    const { default: fixtures } = await import('./sign-in-method-v2.fixtures.json')
    for (const value of fixtures.positive) expect(signInMethodsDiscoverySchema.safeParse(value).success).toBe(true)
    for (const value of fixtures.negative) expect(signInMethodsDiscoverySchema.safeParse(value).success).toBe(false)
  })
})

it('legacy singleton helper fails closed on a mixed collection even when v2 is hidden', async () => {
  const { projectSignInDiscovery } = await import('./sign-in-method')
  expect(projectSignInDiscovery('credential', [
    { id: FIELD, type: SIGN_IN_FIELD_TYPE, value: linked },
    { id: OTHER, type: 'palladin.signin.v2', value: linked },
  ], { [FIELD]: 'discovery', [OTHER]: 'never' })).toBeNull()
})
