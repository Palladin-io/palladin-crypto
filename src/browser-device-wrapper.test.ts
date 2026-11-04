import 'fake-indexeddb/auto'
import { describe, expect, it } from 'vitest'
import {
  DeviceWrapperError,
  deleteAccountSecretFromDevice,
  loadAccountSecretFromDevice,
  storeAccountSecretOnDevice,
} from './browser-device-wrapper'

const accountId = '00112233-4455-6677-8899-aabbccddeeff'
const otherAccountId = '0f0e0d0c-0b0a-4908-8706-050403020100'
const secret = new Uint8Array(32).fill(7)

function readRecord(id: string): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('palladin-device', 1)
    open.onerror = () => reject(open.error)
    open.onsuccess = () => {
      const get = open.result.transaction('account-secrets').objectStore('account-secrets').get(id)
      get.onsuccess = () => { open.result.close(); resolve(get.result) }
      get.onerror = () => reject(get.error)
    }
  })
}

function writeRecord(record: Record<string, unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('palladin-device', 1)
    open.onsuccess = () => {
      const transaction = open.result.transaction('account-secrets', 'readwrite')
      transaction.objectStore('account-secrets').put(record)
      transaction.oncomplete = () => { open.result.close(); resolve() }
      transaction.onerror = () => reject(transaction.error)
    }
  })
}

describe('browser device wrapper', () => {
  it('stores only ciphertext under a non-extractable key and round-trips per account', async () => {
    await storeAccountSecretOnDevice(accountId, secret)
    const record = await readRecord(accountId)
    expect((record.key as CryptoKey).extractable).toBe(false)
    expect((record.key as CryptoKey).algorithm).toMatchObject({ name: 'AES-GCM', length: 256 })
    expect(new Uint8Array(record.ciphertext as ArrayBuffer)).toHaveLength(48)
    expect(Object.keys(record).sort()).toEqual(['accountId', 'ciphertext', 'iv', 'key'])

    expect(await loadAccountSecretFromDevice(accountId)).toEqual(secret)
    expect(await loadAccountSecretFromDevice(otherAccountId)).toBeNull()

    await deleteAccountSecretFromDevice(accountId)
    expect(await loadAccountSecretFromDevice(accountId)).toBeNull()
  })

  it('binds the ciphertext to its account id', async () => {
    await storeAccountSecretOnDevice(accountId, secret)
    const moved = { ...(await readRecord(accountId)), accountId: otherAccountId }
    await writeRecord(moved)
    await expect(loadAccountSecretFromDevice(otherAccountId)).rejects.toThrow(DeviceWrapperError)
    await deleteAccountSecretFromDevice(otherAccountId)
    await deleteAccountSecretFromDevice(accountId)
  })
})
