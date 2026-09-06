import { describe, expect, it } from 'vitest'
import { createCapturedCredentialSecret } from './credential-policy'
import { projectCanonicalCredentialDiscovery } from './credential-discovery'
import { projectAgentDiscovery, parseAgentDiscovery } from './vault-plaintext'
import { sealCanonicalCredentialEntry, openMemberSecret } from './entry-protocol'
import { randomBytes, wipe } from './sodium'
import { deriveVaultSubkey } from './hkdf'
import { openVaultEnvelope, toEnvelopeDescriptor } from './vault-envelope'

describe('current Credential discovery contract', () => {
  const secret = createCapturedCredentialSecret({ label: 'Example', username: 'alice', password: 'private-value',
    url: 'https://example.test', urlDomain: 'example.test' })

  it('advertises Inject without changing the published generic projection', () => {
    expect(projectCanonicalCredentialDiscovery(secret)?.capabilities).toEqual(['get', 'exec', 'inject'])
    expect(projectAgentDiscovery(secret)?.capabilities).toEqual(['get', 'exec'])
    expect(JSON.stringify(projectCanonicalCredentialDiscovery(secret))).not.toContain(secret.content.password)
  })

  it('omits absent discovery values and honors disabled discovery', () => {
    expect(projectCanonicalCredentialDiscovery({ ...secret, content: { ...secret.content, urlDomain: null } })?.fields)
      .toEqual([{ id: 'credential.username', value: 'alice' }])
    expect(projectCanonicalCredentialDiscovery({ ...secret, discoverable: false, agentLabel: null,
      agentFieldAccess: { ...secret.agentFieldAccess, agentLabel: 'never', entryType: 'never' } })).toBeNull()
  })

  it('seals the current discovery beside the unchanged MemberSecret', async () => {
    const vk = await randomBytes(32)
    const vdk = await randomBytes(32)
    let discoveryKey: Uint8Array | undefined
    let plaintext: Uint8Array | undefined
    try {
      const coordinates = { organizationId: '00112233-4455-6677-8899-aabbccddeeff',
        vaultId: '11112222-3333-4444-8555-666677778888', entryId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
        revision: '1', vaultKeyVersion: 1, vdkVersion: 1, memberKeyGeneration: 1 }
      const material = await sealCanonicalCredentialEntry(coordinates, secret, vk, vdk, 1)
      expect(await openMemberSecret(material.entryKey, material.memberSecret, vk, coordinates)).toEqual(secret)
      if (!material.agentDiscovery) throw new Error('Expected discovery')
      const { resourceRevision, ...kdf } = toEnvelopeDescriptor(material.agentDiscovery.descriptor)
      void resourceRevision
      discoveryKey = await deriveVaultSubkey(vdk, kdf)
      plaintext = await openVaultEnvelope(material.agentDiscovery, discoveryKey)
      expect(parseAgentDiscovery(plaintext)).toEqual(projectCanonicalCredentialDiscovery(secret))
    } finally {
      wipe(vk); wipe(vdk)
      if (discoveryKey) wipe(discoveryKey)
      if (plaintext) wipe(plaintext)
    }
  })
})
