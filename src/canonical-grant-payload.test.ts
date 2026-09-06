import { describe, expect, it } from 'vitest'
import { createCapturedCredentialSecret } from './credential-policy'
import { canonicalGrantPolicyFieldId, listCanonicalGrantableFieldIds, projectCanonicalGrantPayload } from './canonical-grant-payload'
import { projectGrantPayload } from './vault-plaintext'

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
})
