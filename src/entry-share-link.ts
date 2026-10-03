import { decodeBase64Url, decodeUuid, encodeBase64Url } from './vault-v2-bytes'
import { wipe } from './sodium'

export interface EntryShareLinkSecrets {
  key: Uint8Array
  accessToken: Uint8Array
}

export function entrySharePath(shareId: string): string {
  decodeUuid(shareId)
  return `/share/${shareId}`
}

export function entryShareFragment(secrets: EntryShareLinkSecrets): string {
  if (secrets.key.byteLength !== 32 || secrets.accessToken.byteLength !== 32) {
    throw new Error('Invalid Entry sharing link')
  }
  return `#v=1&key=${encodeBase64Url(secrets.key)}&access=${encodeBase64Url(secrets.accessToken)}`
}

export function parseEntryShareFragment(fragment: string): EntryShareLinkSecrets {
  const match = /^#v=1&key=([A-Za-z0-9_-]{43})&access=([A-Za-z0-9_-]{43})$/.exec(fragment)
  if (!match) throw new Error('Invalid Entry sharing link')
  let key: Uint8Array | undefined
  try {
    key = decodeBase64Url(match[1], 32)
    const accessToken = decodeBase64Url(match[2], 32)
    return { key, accessToken }
  } catch {
    if (key) wipe(key)
    throw new Error('Invalid Entry sharing link')
  }
}

export function clearEntryShareLink(secrets: EntryShareLinkSecrets): void {
  wipe(secrets.key)
  wipe(secrets.accessToken)
}
