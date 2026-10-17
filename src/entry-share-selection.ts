import { z } from 'zod'
import type { EntryShareField, EntryShareSnapshot } from './entry-share'
import { formatOtpauthUri } from './totp'
import type { MemberSecretV1 } from './current-vault-plaintext'

const totpSchema = z.strictObject({
  secret: z.string().regex(/^[A-Z2-7]+$/), algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']),
  digits: z.union([z.literal(6), z.literal(8)]), period: z.number().int().min(15).max(120),
  issuer: z.string().nullish(), account: z.string().nullish(),
})

export function entryShareFields(source: MemberSecretV1): {
  fields: EntryShareField[]
  unsupported: { id: string; label: string }[]
} {
  const fields: EntryShareField[] = []
  const unsupported: { id: string; label: string }[] = []
  const add = (id: string, value: string | null | undefined,
    type: EntryShareField['type'], label = '') => {
    if (value !== null && value !== undefined) fields.push({ id, label, value, type })
  }

  if (source.entryType === 'credential') {
    add('credential.username', source.content.username, 'text')
    add('credential.password', source.content.password, 'concealed')
    add('credential.url', source.content.url, 'text')
    if (source.content.totp) add('credential.totp', formatOtpauthUri(source.content.totp), 'totp')
  } else if (source.entryType === 'key') {
    add('key.value', source.content.value, 'concealed')
    add('key.url', source.content.url, 'text')
  } else if (source.entryType === 'creditCard') {
    add('creditCard.cardholderName', source.content.cardholderName, 'text')
    add('creditCard.cardNumber', source.content.cardNumber, 'concealed')
    add('creditCard.cvv', source.content.cvv, 'concealed')
    add('creditCard.expiryMonth', source.content.expiryMonth, 'text')
    add('creditCard.expiryYear', source.content.expiryYear, 'text')
    add('creditCard.billingAddress', source.content.billingAddress, 'multiline')
  } else {
    add('script.source', source.content.source, 'multiline')
    add('script.interpreter', source.content.interpreter, 'text')
  }
  add('description', source.description, 'multiline')
  add('notes', source.content.notes, 'multiline')
  for (const field of source.content.customFields) {
    if (['text', 'multiline', 'concealed'].includes(field.type) && typeof field.value === 'string') {
      add(field.id, field.value, field.type as 'text' | 'multiline' | 'concealed', field.label)
    } else if (field.type === 'totp') {
      const value = totpSchema.safeParse(field.value)
      if (value.success) add(field.id, formatOtpauthUri(value.data), 'totp', field.label)
      else unsupported.push({ id: field.id, label: field.label })
    } else unsupported.push({ id: field.id, label: field.label })
  }
  return { fields, unsupported }
}

export function createEntryShareSnapshot(source: MemberSecretV1): EntryShareSnapshot {
  const { fields, unsupported } = entryShareFields(source)
  const known = new Set(fields.map((field) => field.id))
  if (!fields.length || unsupported.length || fields.length !== known.size) throw new Error('Entry cannot be shared in full')
  return {
    schema: 'palladin.entry-share.v1', title: source.memberLabel, entryType: source.entryType,
    fields,
  }
}
