import type { AgentFieldAccess, MemberSecretV1 } from './vault-plaintext'

export function defaultCredentialAgentFieldAccess(
  customFields: readonly { id: string; type: string }[] = [],
): Record<string, AgentFieldAccess> {
  const fields: Record<string, AgentFieldAccess> = {
    memberLabel: 'never', agentLabel: 'discovery', description: 'never', icon: 'never', color: 'never',
    entryType: 'discovery', notes: 'onGrantValue',
    'credential.username': 'discovery', 'credential.urlDomain': 'discovery',
    'credential.url': 'onGrantValue', 'credential.password': 'onGrantValue', 'credential.totp': 'onGrantDerived',
  }
  for (const field of customFields) {
    fields[field.id.startsWith('custom:') ? field.id : `custom:${field.id}`] = field.type === 'totp' ? 'onGrantDerived' : 'onGrantValue'
  }
  return fields
}

export interface CapturedCredentialInput {
  readonly label: string
  readonly username: string
  readonly password: string
  readonly url: string
  readonly urlDomain: string
}

export function createCapturedCredentialSecret(input: CapturedCredentialInput): Extract<MemberSecretV1, { entryType: 'credential' }> {
  const label = input.label.trim().normalize('NFC')
  return {
    schema: 'palladin.member-secret.v1', entryType: 'credential',
    memberLabel: label, agentLabel: label, discoverable: true,
    description: null, icon: null, color: null, agentFieldAccess: defaultCredentialAgentFieldAccess(),
    content: {
      username: input.username.trim(), password: input.password,
      url: input.url, urlDomain: input.urlDomain, totp: null, notes: null, customFields: [],
    },
  }
}
