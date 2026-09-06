import { projectAgentDiscovery, type AgentDiscoveryV1, type MemberSecretV1 } from './current-vault-plaintext'

export type CredentialMemberSecret = Extract<MemberSecretV1, { entryType: 'credential' }>
export interface CredentialDiscovery extends Omit<AgentDiscoveryV1, 'fields' | 'entryType'> {
  entryType: 'credential'
  fields: { id: string; value: string }[]
}

// Current web contract; the original generic projector retains its published bytes.
export function projectCanonicalCredentialDiscovery(secret: CredentialMemberSecret): CredentialDiscovery | null {
  const discovery = projectAgentDiscovery(secret)
  return discovery && {
    ...discovery,
    entryType: 'credential',
  }
}
