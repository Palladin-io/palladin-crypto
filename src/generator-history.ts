import { fromBase64Url, toBase64Url } from './encoding'
import { getCryptoProvider } from './provider/active-provider'
import { decryptWithKey, encryptWithKey, wipe } from './sodium'

const PURPOSE = 'palladin/local-generator-history/v1'
export const GENERATOR_HISTORY_MAX_BYTES = 2 * 1024 * 1024

export interface GeneratorHistoryContext {
  readonly accountId: string
  readonly apiUrl: string
}

export interface GeneratorHistoryEnvelope {
  readonly version: 1
  readonly ciphertext: string
}

async function historyKey(privateKey: Uint8Array, expected: GeneratorHistoryContext): Promise<Uint8Array> {
  if (privateKey.length !== 32 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(expected.accountId)
    || expected.apiUrl.length > 2048) throw new Error('Invalid generator history context')
  const url = new URL(expected.apiUrl)
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password
    || url.search || url.hash) throw new Error('Invalid generator history context')
  const root = new Uint8Array(privateKey)
  const info = new TextEncoder().encode(JSON.stringify([PURPOSE, expected.accountId, expected.apiUrl]))
  try {
    const key = await crypto.subtle.importKey('raw', root, 'HKDF', false, ['deriveBits'])
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info }, key, 256,
    ))
  } finally {
    wipe(root)
    wipe(info)
  }
}

/** Expected context must come from the authenticated session, never stored ciphertext. */
export async function sealGeneratorHistory(
  plaintext: Uint8Array,
  privateKey: Uint8Array,
  expected: GeneratorHistoryContext,
): Promise<GeneratorHistoryEnvelope> {
  if (plaintext.length > GENERATOR_HISTORY_MAX_BYTES) throw new Error('Generator history exceeds size limit')
  await getCryptoProvider().ready()
  const key = await historyKey(privateKey, expected)
  try {
    return { version: 1, ciphertext: toBase64Url(await encryptWithKey(plaintext, key)) }
  } finally {
    wipe(key)
  }
}

export async function openGeneratorHistory(
  envelope: unknown,
  privateKey: Uint8Array,
  expected: GeneratorHistoryContext,
): Promise<Uint8Array> {
  if (typeof envelope !== 'object' || envelope === null || Array.isArray(envelope)) {
    throw new Error('Invalid generator history envelope')
  }
  const candidate = envelope as Record<string, unknown>
  if (candidate.version !== 1 || typeof candidate.ciphertext !== 'string'
    || Object.keys(candidate).length !== 2) throw new Error('Invalid generator history envelope')
  const ciphertext = fromBase64Url(candidate.ciphertext, GENERATOR_HISTORY_MAX_BYTES + 40)
  if (ciphertext.length < 40) throw new Error('Invalid generator history envelope')
  await getCryptoProvider().ready()
  const key = await historyKey(privateKey, expected)
  try {
    return await decryptWithKey(ciphertext, key)
  } finally {
    wipe(key)
  }
}
