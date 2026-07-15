import sodium from 'libsodium-wrappers'
import { argon2id } from 'hash-wasm'
import { loadSodium } from '../sodium-loader'
import type { Argon2Params, CryptoProvider, KeyPair } from './crypto-provider'

/**
 * The production provider: XSalsa20-Poly1305 `crypto_secretbox` for symmetric
 * AEAD, X25519 `crypto_box_seal` for anonymous sealed boxes, and Argon2id for
 * password derivation. Byte formats here are the zero-knowledge wire contract
 * shared with the mobile and MCP-agent clients — do not change them.
 *
 * Argon2id runs on `hash-wasm` (not libsodium's `crypto_pwhash`) because that
 * is what the web panel shipped; keeping the same implementation guarantees
 * identical derived keys for already-onboarded users.
 */
export class LibsodiumProvider implements CryptoProvider {
  readonly id = 'libsodium'

  private instance: typeof sodium | null = null

  async ready(): Promise<void> {
    this.instance = await loadSodium()
  }

  private get s(): typeof sodium {
    if (!this.instance) {
      throw new Error('LibsodiumProvider.ready() must be awaited before use')
    }
    return this.instance
  }

  randomBytes(length: number): Uint8Array {
    return this.s.randombytes_buf(length)
  }

  secretboxKeyBytes(): number {
    return this.s.crypto_secretbox_KEYBYTES
  }

  secretboxNonceBytes(): number {
    return this.s.crypto_secretbox_NONCEBYTES
  }

  secretboxEasy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
    return this.s.crypto_secretbox_easy(message, nonce, key)
  }

  secretboxOpenEasy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array {
    return this.s.crypto_secretbox_open_easy(ciphertext, nonce, key)
  }

  boxKeypair(): KeyPair {
    const kp = this.s.crypto_box_keypair()
    return { publicKey: kp.publicKey, privateKey: kp.privateKey }
  }

  boxSeal(message: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
    return this.s.crypto_box_seal(message, recipientPublicKey)
  }

  boxSealOpen(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return this.s.crypto_box_seal_open(ciphertext, publicKey, privateKey)
  }

  scalarMultBase(privateKey: Uint8Array): Uint8Array {
    return this.s.crypto_scalarmult_base(privateKey)
  }

  async deriveKey(password: string, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
    return argon2id({
      password,
      salt,
      parallelism: params.parallelism,
      iterations: params.iterations,
      memorySize: params.memorySize,
      hashLength: params.hashLength,
      outputType: 'binary',
    })
  }

  /**
   * Uses the top-level libsodium binding directly (not the ready-gated
   * instance) so it behaves exactly like the original standalone `wipe`:
   * `memzero` is resistant to compiler dead-store elimination.
   */
  wipe(arr: Uint8Array): void {
    sodium.memzero(arr)
  }
}
