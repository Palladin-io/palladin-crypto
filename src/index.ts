/**
 * @palladin/crypto — single source of Palladin's client-side zero-knowledge
 * crypto, shared by the web panel and the browser extension.
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
export { toBase64, fromBase64 } from './encoding'

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
