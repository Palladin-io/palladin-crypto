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

// --- Identity password KDF v1 (Argon2id account root + HKDF domains) ---
export {
  IDENTITY_SECURITY_VERSION,
  IDENTITY_KDF_PROFILE_ID,
  IDENTITY_KDF_SALT_BYTES,
  IDENTITY_MAXIMUM_PASSWORD_UTF8_BYTES,
  IDENTITY_KDF_PROFILE,
  assertIdentityKdfProfile,
  deriveIdentityOutputsFromRoot,
  deriveIdentityV1,
} from './identity-kdf'
export type { IdentityKdfMetadata, IdentityKdfOutputs } from './identity-kdf'

// --- Identity Account Secret KDF v2, Secret Key and Emergency Kit encodings ---
export {
  IDENTITY_ACCOUNT_SECRET_PROFILE,
  ACCOUNT_SECRET_BYTES,
  SecretKeyError,
  assertIdentityAccountSecretProfile,
  identityKdfProfileVersion,
  generateAccountSecret,
  deriveIdentityV2,
  formatSecretKey,
  parseSecretKey,
  encodeEmergencyKitQr,
  parseEmergencyKitQr,
} from './identity-account-secret'
export type { SecretKeyErrorCode } from './identity-account-secret'

// --- Secret Key transfer between devices (device pairing v2) ---
export {
  DEVICE_PAIRING_PROTOCOL_VERSION,
  PairingError,
  generatePairingKeyPair,
  encodePairingQr,
  parsePairingQr,
  pairingRecipientKeyDigest,
  encodePairingOffer,
  computePairingSas,
  sealAccountSecretForPairing,
  openPairingEnvelope,
} from './device-pairing'
export type {
  PairingErrorCode,
  PairingKeyPair,
  PairingQr,
  PairingSession,
  PairingEnvelope,
  SealPairingInput,
} from './device-pairing'

// --- Browser device wrapper for the Account Secret (web panel and extension) ---
export {
  DeviceWrapperError,
  storeAccountSecretOnDevice,
  loadAccountSecretFromDevice,
  deleteAccountSecretFromDevice,
} from './browser-device-wrapper'

// --- Algorithm-neutral key wrapper (key-wrapper v1 suite registry) ---
export {
  KEY_WRAPPER_PROTOCOL_VERSION,
  KEY_WRAPPER_SUITE,
  KEY_WRAPPER_PURPOSE,
  RECIPIENT_KEY_KIND,
  KEY_WRAPPER_ERROR_CODES,
  KeyWrapperError,
} from './key-wrapper/registry'
export type {
  KeyWrapperSuiteId,
  KeyWrapperPurpose,
  KeyWrapperErrorCode,
  RecipientKeyKind,
} from './key-wrapper/registry'
export {
  sealKey,
  openKey,
  encodeKeyWrapperContext,
  computeRecipientFingerprint,
  generateRecipientKeyPair,
  deriveRecipientPublicKey,
} from './key-wrapper/key-wrapper'
export type { KeyWrapperDescriptor, KeyWrapperRecipient, RecipientKeyPair } from './key-wrapper/key-wrapper'

// --- Encoding ---
export { toBase64, fromBase64, toBase64Url, fromBase64Url } from './encoding'

// --- Canonical Vault protocol 2 (frozen PLDNENV2 / PLDNKDF2 contract) ---
export * from './crypto-suite'
export * from './canonical-aad'
export * from './inject-provider-channel'
export * from './shared-unlock'
export * from './envelope'
export * from './hkdf'
export * from './portable-sha256'
export * from './generator-history'
export * from './vault-envelope'
export * from './account-recovery-challenge'
export * from './vault-plaintext'
export * from './vault-protocol'
export * from './entry-protocol'
export * from './script-execution'
export * from './browser-session-envelope'
export * from './grant-protocol'
export * from './credential-policy'
export * from './credential-discovery'
export * from './sign-in-method'
export * from './canonical-grant-payload'
export * as currentVaultPlaintext from './current-vault-plaintext'

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
export { base32Decode, formatOtpauthUri, parseOtpauthUri, totpParamsFromSecret, generateTotp } from './totp'
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

// --- Browser shared unlock receiver proof (candidate Identity contract) ---
export * from './shared-unlock-identity-proof'
export * from './shared-unlock-key-context'

export * from './entry-share'
export * from './entry-share-selection'
export * from './entry-share-link'
export * from './reason-protocol'
