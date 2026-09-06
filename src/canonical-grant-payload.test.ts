import { describe, expect, it } from 'vitest'
import { createCapturedCredentialSecret } from './credential-policy'
import { canonicalGrantPolicyFieldId, listCanonicalGrantableFieldIds, projectCanonicalGrantPayload } from './canonical-grant-payload'
import { projectGrantPayload } from './vault-plaintext'
import { encodeMemberSecret, parseMemberSecret } from './current-vault-plaintext'

const secret = createCapturedCredentialSecret({ label: 'Example', username: 'alice', password: 'secret',
  url: 'https://example.com', urlDomain: 'example.com' })

describe('production Credential grant projection', () => {
  it('namespaces notes without changing the older projection API', async () => {
    expect(projectGrantPayload(secret, ['notes']).fields[0].id).toBe('notes')
    expect((await projectCanonicalGrantPayload(secret, ['notes'])).fields[0].id).toBe('credential.notes')
    expect(canonicalGrantPolicyFieldId('credential', 'credential.notes')).toBe('notes')
  })
  it('derives TOTP and never gives a grant the seed', async () => {
    const totpSecret = { ...secret, content: { ...secret.content,
      totp: { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', algorithm: 'SHA1' as const, // RFC 6238 public vector; gitleaks:allow
        digits: 8 as const, period: 30, issuer: null, account: null } } }
    const payload = await projectCanonicalGrantPayload(totpSecret, ['credential.totp'], 59_000)
    expect(payload.fields[0].value).toEqual({ code: '94287082', expiresIn: 1 })
    expect(JSON.stringify(payload)).not.toContain(totpSecret.content.totp.secret)
  })
  it('does not widen discovery-only fields into grants', async () => {
    expect(listCanonicalGrantableFieldIds(secret)).not.toContain('credential.username')
    await expect(projectCanonicalGrantPayload(secret, ['credential.username'])).rejects.toThrow('not grantable')
    await expect(projectCanonicalGrantPayload(secret, ['credential.urlDomain'])).rejects.toThrow('not registered')
  })
  it('keeps readable legacy custom IDs but never offers them as canonical grant fields', async () => {
    const id = 'custom:AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE'
    const legacy = { ...secret, content: { ...secret.content,
      customFields: [{ id, label: 'Legacy field', type: 'text', value: 'value' }] },
      agentFieldAccess: { ...secret.agentFieldAccess, [id]: 'onGrantValue' as const } }
    expect(parseMemberSecret(encodeMemberSecret(legacy))).toEqual(legacy)
    expect(listCanonicalGrantableFieldIds(legacy)).not.toContain(id)
    await expect(projectCanonicalGrantPayload(legacy, [id])).rejects.toThrow(/not registered/)
    const canonicalId = id.toLowerCase()
    const current = { ...legacy, content: { ...legacy.content,
      customFields: [{ ...legacy.content.customFields[0], id: canonicalId }] },
      agentFieldAccess: { ...secret.agentFieldAccess, [canonicalId]: 'onGrantValue' as const } }
    expect(listCanonicalGrantableFieldIds(current)).toContain(canonicalId)
    expect((await projectCanonicalGrantPayload(current, [canonicalId])).fields[0].id).toBe(canonicalId)
  })
})
