/**
 * Crypto provider abstraction.
 *
 * The whole vault key hierarchy (symmetric AEAD, X25519 sealed boxes, keypair
 * generation, the Argon2id KDF) is expressed as a narrow provider interface so
 * the underlying primitive family can be swapped without touching the
 * higher-level flows (entry encryption, grant envelopes, vault-key sealing).
 *
 * Today the only implementation is {@link LibsodiumProvider} (XSalsa20-Poly1305
 * secretbox + X25519 `crypto_box_seal` + Argon2id). A second, still-empty
 * {@link WebCryptoProvider} slot is reserved for the passkeys work (ECDSA P-256
 * via WebCrypto). Keeping the contract here means the browser extension and the
 * web panel share one audited crypto surface.
 *
 * SECURITY: changing KDF parameters or the wire format of any operation is a
 * breaking change to already-stored ciphertext — never alter behaviour of an
 * existing provider without a migration. See AGENTS.md.
 */

export interface KeyPair {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

/** Argon2id cost parameters fed to {@link CryptoProvider.deriveKey}. */
export interface Argon2Params {
  /** Memory cost in KiB. */
  memorySize: number
  /** Time cost (passes). */
  iterations: number
  /** Degree of parallelism (lanes). */
  parallelism: number
  /** Output length in bytes. */
  hashLength: number
}

/**
 * The primitive operations every provider must supply. All byte buffers are
 * plain `Uint8Array`; encoding to/from base64 for the wire is handled one layer
 * up (see `encoding.ts`).
 */
export interface CryptoProvider {
  /** Stable identifier for diagnostics/audit (`'libsodium'`, `'webcrypto'`). */
  readonly id: string

  /** Resolve once the provider's async runtime (e.g. libsodium WASM) is ready. */
  ready(): Promise<void>

  randomBytes(length: number): Uint8Array

  /** Symmetric key length for {@link secretboxEasy}. */
  secretboxKeyBytes(): number
  /** Nonce length for {@link secretboxEasy}. */
  secretboxNonceBytes(): number
  /** Authenticated symmetric encryption (nonce supplied by the caller). */
  secretboxEasy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array
  /** Inverse of {@link secretboxEasy}; throws on a failed MAC check. */
  secretboxOpenEasy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array

  boxKeypair(): KeyPair
  /** Anonymous sealed box to `recipientPublicKey` (X25519). */
  boxSeal(message: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array
  /** Open a sealed box; throws if it was not sealed to this keypair. */
  boxSealOpen(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array
  /** Derive the X25519 public key from a private key. */
  scalarMultBase(privateKey: Uint8Array): Uint8Array

  deriveKey(password: string, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array>

  /** Zero a sensitive buffer in a way resistant to dead-store elimination. */
  wipe(arr: Uint8Array): void
}

/** Thrown by provider slots whose primitives are not implemented yet. */
export class NotImplementedError extends Error {
  constructor(provider: string, operation: string) {
    super(`${provider}.${operation} is not implemented yet`)
    this.name = 'NotImplementedError'
  }
}
