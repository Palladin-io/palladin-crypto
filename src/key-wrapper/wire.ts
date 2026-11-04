import type { KeyWrapperDescriptor } from './key-wrapper'
import { KEY_WRAPPER_PURPOSE, KeyWrapperError, RECIPIENT_KEY_KIND } from './registry'

export type WireKeyWrapperPurpose = keyof typeof KEY_WRAPPER_PURPOSE
export type WireRecipientKeyKind = keyof typeof RECIPIENT_KEY_KIND

/** Backend JSON form of a descriptor: registry names instead of numeric purpose and key kind. */
export interface WireKeyWrapperDescriptor extends Omit<KeyWrapperDescriptor, 'purpose' | 'recipientKeyKind'> {
  purpose: WireKeyWrapperPurpose
  recipientKeyKind: WireRecipientKeyKind
}

function valueOf(table: Readonly<Record<string, number>>, name: unknown): number | undefined {
  return typeof name === 'string' && Object.hasOwn(table, name) ? table[name] : undefined
}

function nameOf<T extends string>(table: Readonly<Record<T, number>>, value: unknown): T | undefined {
  return (Object.keys(table) as T[]).find((name) => table[name] === value)
}

/** Maps backend names to the numeric descriptor; unknown names fail closed. */
export function fromWireKeyWrapperDescriptor(wire: WireKeyWrapperDescriptor): KeyWrapperDescriptor {
  if (typeof wire !== 'object' || wire === null) throw new KeyWrapperError('malformed-descriptor')
  const purpose = valueOf(KEY_WRAPPER_PURPOSE, wire.purpose)
  if (purpose === undefined) throw new KeyWrapperError('unsupported-purpose')
  const recipientKeyKind = valueOf(RECIPIENT_KEY_KIND, wire.recipientKeyKind)
  if (recipientKeyKind === undefined) throw new KeyWrapperError('malformed-descriptor')
  return { ...wire, purpose, recipientKeyKind }
}

/** Maps a numeric descriptor to the backend names; unregistered values fail closed. */
export function toWireKeyWrapperDescriptor(descriptor: KeyWrapperDescriptor): WireKeyWrapperDescriptor {
  if (typeof descriptor !== 'object' || descriptor === null) throw new KeyWrapperError('malformed-descriptor')
  const purpose = nameOf(KEY_WRAPPER_PURPOSE, descriptor.purpose)
  if (purpose === undefined) throw new KeyWrapperError('unsupported-purpose')
  const recipientKeyKind = nameOf(RECIPIENT_KEY_KIND, descriptor.recipientKeyKind)
  if (recipientKeyKind === undefined) throw new KeyWrapperError('malformed-descriptor')
  return { ...descriptor, purpose, recipientKeyKind }
}
