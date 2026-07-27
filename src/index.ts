/**
 * @palladin/crypto — candidate shared package for Palladin's client-side
 * zero-knowledge crypto. Consumer cutover and Protocol 2 integration are
 * pending; this package is not yet the production single source.
 *
 * The public API routes through a swappable {@link CryptoProvider}
 * (default {@link LibsodiumProvider}); TOTP and the password generator are
 * standalone standard utilities.
 *
 * SECURITY: this package defines the wire crypto contract (KDF parameters,
 * secretbox/sealed-box formats) shared with the mobile and MCP-agent clients.
 * Never change the behaviour of an existing operation without a migration.
 */

// --- Provider abstraction ---
export type { CryptoProvider, Argon2Params, KeyPair } from './provider/crypto-provider'
export { NotImplementedError } from './provider/crypto-provider'
export { LibsodiumProvider } from './provider/libsodium-provider'
export { WebCryptoProvider } from './provider/webcrypto-provider'
export { getCryptoProvider, setCryptoProvider } from './provider/active-provider'

// --- libsodium lifecycle ---
export { loadSodium } from './sodium-loader'

// --- Low-level symmetric/keypair helpers ---
export {
  generateKeyPair,
  encryptWithKey,
  decryptWithKey,
  randomBytes,
  wipe,
} from './sodium'

// --- Key derivation (Argon2id) ---
export {
  ARGON2_PARAMS,
  MASTER_KEY_SALT_BYTES,
  RECOVERY_KEY_SALT_BYTES,
  AUTH_SALT_BYTES,
  deriveKey,
} from './argon2'

// --- Encoding ---
export { toBase64, fromBase64, toBase64Url, fromBase64Url } from './encoding'

// --- Canonical Vault protocol 2 (additive; legacy APIs above remain unchanged) ---
export * from './vault-v2-bytes'
export * from './vault-v2-signatures'
export * from './vault-v2-protocol'
export * from './crypto-suite'
export * from './canonical-aad'
export * from './envelope'
export * from './hkdf'
export * from './vault-envelope'
export * from './x25519-wrapper'
export * from './vault-v2-kdf'
export * from './vault-plaintext'
export * from './vault-protocol'
export * from './entry-protocol'

// --- Entry encryption ---
export { encryptEntry, decryptEntry } from './entry-crypto'

// --- Vault key sealing ---
export { sealVaultKey, unsealVaultKey } from './vault-key'

// --- Grant envelopes ---
export { produceGrantEntryEnvelope } from './grant-envelope'
export type {
  GrantEntryEnvelope,
  SealedEntryContent,
  ProduceGrantEntryEnvelopeParams,
} from './grant-envelope'

// --- Password generator ---
export {
  generatePassword,
  PASSWORD_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
  PASSWORD_DEFAULT_LENGTH,
} from './password-generator'
export type { PasswordOptions } from './password-generator'

// --- Passphrase generator ---
export {
  generatePassphrase,
  PASSPHRASE_MIN_WORDS,
  PASSPHRASE_MAX_WORDS,
  PASSPHRASE_DEFAULT_WORDS,
  PASSPHRASE_SEPARATORS,
} from './passphrase-generator'
export type { PassphraseOptions, PassphraseSeparator } from './passphrase-generator'

// --- TOTP (RFC 6238) ---
export { base32Decode, parseOtpauthUri, totpParamsFromSecret, generateTotp } from './totp'
export type { TotpCode } from './totp'

// --- Crypto payload types (structurally match the app's vault types) ---
export {
  ENTRY_TYPE_KEY,
  ENTRY_TYPE_CREDENTIAL,
  ENTRY_TYPE_SCRIPT,
  BLOB_VERSION_V2,
  SCRIPT_INTERPRETERS,
} from './payload-types'
export type {
  EntryType,
  CustomFieldType,
  TotpParams,
  CustomField,
  ScriptInterpreter,
  ScriptRef,
  EntryContent,
  EntryPlaintextV2Common,
  EntryPlaintext,
} from './payload-types'
