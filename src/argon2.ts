import { getCryptoProvider } from './provider/active-provider'

/**
 * KDF parameters used across the app. Keep these in one place so onboarding,
 * unlock, and recovery all derive identical keys from the same inputs.
 *
 * These match the values specified in the zero-knowledge spec:
 *   m = 19456 (KiB, ~19MB), t = 2 iterations, p = 1 lane, 32-byte output.
 *
 * SECURITY: these parameters are baked into every already-derived master key.
 * Changing any of them silently breaks unlock for existing users — never touch
 * them without a versioned migration.
 */
export const ARGON2_PARAMS = {
  memorySize: 19456,
  iterations: 2,
  parallelism: 1,
  hashLength: 32,
} as const

export const MASTER_KEY_SALT_BYTES = 16
export const RECOVERY_KEY_SALT_BYTES = 16

/**
 * Salt length for the authentication hash. In the email+password model
 * (Variant A) the one password feeds two independent Argon2id derivations:
 *   • MK        = deriveKey(password, salt)      — never leaves the client
 *   • authHash  = deriveKey(password, authSalt)  — sent to the server for login
 * Distinct salts guarantee the two outputs are unrelated, so the authHash the
 * server sees can never be used to recover the master key.
 */
export const AUTH_SALT_BYTES = 16

/**
 * Derive a 32-byte key from a password + salt using Argon2id.
 * Returns raw bytes (not hex/base64) so callers can feed it directly
 * into libsodium's crypto_secretbox.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const provider = getCryptoProvider()
  await provider.ready()
  return provider.deriveKey(password, salt, ARGON2_PARAMS)
}
