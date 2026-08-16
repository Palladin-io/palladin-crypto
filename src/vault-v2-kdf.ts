import { concatBytes, decodeUuid, encodeU16, encodeU32, encodeUtf8 } from './vault-v2-bytes'
import { VAULT_PROTOCOL_VERSION } from './vault-v2-protocol'

export type VaultKdfPurpose = 'member-vault-metadata' | 'member-index' | 'member-secret' | 'agent-discovery' | 'encrypted-asset'
const purposeIds: Record<VaultKdfPurpose, number> = { 'member-vault-metadata': 1, 'member-index': 2, 'member-secret': 3, 'agent-discovery': 4, 'encrypted-asset': 5 }

export interface DeriveVaultProjectionKeyParams {
  baseKey: Uint8Array
  purpose: VaultKdfPurpose
  resourceKind: 1 | 2
  organizationId: string
  vaultId: string
  entryId?: string
  keyVersion: number
  memberKeyGeneration: number
}

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer
}

export async function deriveVaultProjectionKey(params: DeriveVaultProjectionKeyParams): Promise<Uint8Array> {
  if (params.baseKey.length !== 32) throw new Error('Vault protocol base key must be 32 bytes')
  const needsEntry = params.resourceKind === 2
  if (needsEntry !== Boolean(params.entryId)) throw new Error('entryId presence must match resource kind')
  const saltInput = concatBytes(
    encodeUtf8('PLDNV2HK'), encodeU16(VAULT_PROTOCOL_VERSION), encodeU16(params.resourceKind),
    decodeUuid(params.organizationId), decodeUuid(params.vaultId), params.entryId ? decodeUuid(params.entryId) : new Uint8Array(16),
    encodeU32(params.keyVersion), encodeU32(params.memberKeyGeneration),
  )
  const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', ownedBuffer(saltInput)))
  const info = concatBytes(encodeUtf8('palladin:vault-v2:'), encodeU16(purposeIds[params.purpose]))
  const imported = await crypto.subtle.importKey('raw', ownedBuffer(params.baseKey), 'HKDF', false, ['deriveBits'])
  const derived = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ownedBuffer(salt), info: ownedBuffer(info) }, imported, 256)
  return new Uint8Array(derived)
}

