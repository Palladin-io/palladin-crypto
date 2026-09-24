import { describe, expect, it } from 'vitest'
import * as current from './current-vault-plaintext'
import * as legacy from './vault-plaintext'

const card: current.MemberSecretV1 = {
  schema: 'palladin.member-secret.v1', entryType: 'creditCard', memberLabel: 'Test card',
  agentLabel: null, discoverable: false, description: null, icon: null, color: null,
  content: { cardholderName: 'Test', cardNumber: '4242424242424242', expiryMonth: '12',
    expiryYear: '2030', billingAddress: null, notes: null, customFields: [] },
  agentFieldAccess: Object.fromEntries(['memberLabel', 'agentLabel', 'description', 'icon',
    'color', 'entryType', 'notes', 'creditCard.cardholderName', 'creditCard.cardNumber',
    'creditCard.expiryMonth', 'creditCard.expiryYear', 'creditCard.billingAddress'].map(id => [id, 'never'])),
}

describe.each([['current', current], ['extension adapter', legacy]] as const)('%s CVV', (_, codec) => {
  it('preserves old cards and round-trips optional CVV with leading zeroes', () => {
    expect(codec.parseMemberSecret(codec.encodeMemberSecret(card))).toEqual(card)
    for (const cvv of ['012', '0123']) {
      const next = { ...card, content: { ...card.content, cvv },
        agentFieldAccess: { ...card.agentFieldAccess, 'creditCard.cvv': 'never' as const } }
      expect(codec.parseMemberSecret(codec.encodeMemberSecret(next))).toEqual(next)
      expect(JSON.stringify(codec.projectMemberIndex(next))).not.toContain(cvv)
      expect(codec.projectAgentDiscovery(next)).toBeNull()
    }
  })
  it('rejects malformed CVV and exposure through Agent policy', () => {
    for (const cvv of ['', '12', '12345', '1a2', '１２３']) {
      expect(() => codec.encodeMemberSecret({ ...card, content: { ...card.content, cvv },
        agentFieldAccess: { ...card.agentFieldAccess, 'creditCard.cvv': 'never' } })).toThrow()
    }
    for (const access of ['discovery', 'onGrantRuntime', 'onGrantValue'] as const) {
      expect(() => codec.encodeMemberSecret({ ...card, content: { ...card.content, cvv: '012' },
        agentFieldAccess: { ...card.agentFieldAccess, 'creditCard.cvv': access } })).toThrow()
    }
  })
})
