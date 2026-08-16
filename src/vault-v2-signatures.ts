import { concatBytes, decodeBase64Url, encodeBase64Url, encodeU16, encodeUtf8 } from './vault-v2-bytes'
import { loadSodium } from './sodium-loader'
import { VAULT_PROTOCOL_VERSION } from './vault-v2-protocol'

export type CanonicalJson = null | boolean | number | string | CanonicalJson[] | { [key: string]: CanonicalJson }

export function canonicalizeVaultJson(value: CanonicalJson): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'string') return JSON.stringify(new TextDecoder().decode(encodeUtf8(value)))
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) throw new Error('Vault canonical JSON permits non-negative safe integers only')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeVaultJson).join(',')}]`
  const keys = Object.keys(value).sort()
  return `{${keys.map((key) => `${canonicalizeVaultJson(key)}:${canonicalizeVaultJson(value[key])}`).join(',')}}`
}

export function vaultSignatureInput(domainPrefix: string, unsignedObject: CanonicalJson): Uint8Array {
  return concatBytes(encodeUtf8(domainPrefix), encodeU16(VAULT_PROTOCOL_VERSION), encodeUtf8(canonicalizeVaultJson(unsignedObject)))
}

export async function verifyVaultSignature(domainPrefix: string, unsignedObject: CanonicalJson, signature: string, publicKey: Uint8Array): Promise<boolean> {
  if (publicKey.length !== 32) throw new Error('Ed25519 public key must be 32 bytes')
  const signatureBytes = decodeBase64Url(signature)
  if (signatureBytes.length !== 64) throw new Error('Ed25519 signature must be 64 bytes')
  const sodium = await loadSodium()
  return sodium.crypto_sign_verify_detached(signatureBytes, vaultSignatureInput(domainPrefix, unsignedObject), publicKey)
}

export async function signVaultObject(domainPrefix: string, unsignedObject: CanonicalJson, privateKey: Uint8Array): Promise<string> {
  if (privateKey.length !== 64) throw new Error('Ed25519 private key must be 64 bytes')
  const sodium = await loadSodium()
  return encodeBase64Url(sodium.crypto_sign_detached(vaultSignatureInput(domainPrefix, unsignedObject), privateKey))
}
