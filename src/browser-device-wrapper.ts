import { ACCOUNT_SECRET_BYTES } from './identity-account-secret'
import { concatBytes, decodeUuid, encodeU16, encodeUtf8 } from './vault-v2-bytes'

/**
 * `identity-kdf/v3` `deviceAssistance.browserNonExtractableWrapper`: the
 * Account Secret persists only as AES-256-GCM ciphertext under a
 * non-extractable WebCrypto key kept in IndexedDB. Script in the same origin
 * or malware controlling the browser profile can still use the key; the
 * wrapper keeps the raw secret out of storage dumps and off the backend.
 */
const DATABASE = 'palladin-device'
const STORE = 'account-secrets'
const AAD_MAGIC = encodeUtf8('PLDNID3BW')
const AAD_VERSION = encodeU16(2)
const IV_BYTES = 12

interface StoredAccountSecret {
  accountId: string
  key: CryptoKey
  iv: Uint8Array
  ciphertext: ArrayBuffer
}

export class DeviceWrapperError extends Error {
  readonly code = 'device-wrapper-unavailable'

  constructor() {
    super('device-wrapper-unavailable')
    this.name = 'DeviceWrapperError'
  }
}

function request<T>(operation: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    operation.onsuccess = () => resolve(operation.result)
    operation.onerror = () => reject(operation.error)
  })
}

async function withStore<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const open = indexedDB.open(DATABASE, 1)
  open.onupgradeneeded = () => open.result.createObjectStore(STORE, { keyPath: 'accountId' })
  const database = await request(open)
  try {
    const transaction = database.transaction(STORE, mode)
    const result = request(action(transaction.objectStore(STORE)))
    await new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(transaction.error)
      transaction.onabort = () => reject(transaction.error)
    })
    return await result
  } finally {
    database.close()
  }
}

function aad(accountId: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(concatBytes(AAD_MAGIC, AAD_VERSION, decodeUuid(accountId)))
}

/** Replaces this browser's wrapped Account Secret for `accountId`. */
export async function storeAccountSecretOnDevice(accountId: string, accountSecret: Uint8Array): Promise<void> {
  if (accountSecret.length !== ACCOUNT_SECRET_BYTES) throw new TypeError('Invalid Account Secret length')
  const additionalData = aad(accountId)
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES))
  const plaintext = new Uint8Array(accountSecret)
  try {
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData }, key, plaintext)
    const record: StoredAccountSecret = { accountId, key, iv, ciphertext }
    await withStore('readwrite', (store) => store.put(record))
  } finally {
    plaintext.fill(0)
  }
}

/** Returns the Account Secret, or `null` when this browser holds none for `accountId`. */
export async function loadAccountSecretFromDevice(accountId: string): Promise<Uint8Array | null> {
  const additionalData = aad(accountId)
  const record = await withStore<StoredAccountSecret | undefined>('readonly', (store) => store.get(accountId))
  if (!record) return null
  try {
    if (record.accountId !== accountId || record.iv.length !== IV_BYTES) throw new Error()
    const plaintext = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(record.iv), additionalData }, record.key, record.ciphertext,
    ))
    if (plaintext.length !== ACCOUNT_SECRET_BYTES) {
      plaintext.fill(0)
      throw new Error()
    }
    return plaintext
  } catch {
    throw new DeviceWrapperError()
  }
}

/** Removes the wrapped Account Secret and its key (sign-out, forget device, recovery, deletion). */
export async function deleteAccountSecretFromDevice(accountId: string): Promise<void> {
  decodeUuid(accountId)
  await withStore('readwrite', (store) => store.delete(accountId))
}
