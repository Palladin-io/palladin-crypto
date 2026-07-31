import { NotImplementedError } from './crypto-provider'
import type { Argon2Params, CryptoProvider, KeyPair } from './crypto-provider'

/**
 * Reserved slot for a WebCrypto-backed provider (ECDSA P-256 / SubtleCrypto),
 * the primitive family passkeys need. It implements the full {@link CryptoProvider}
 * contract so call sites type-check today, but every operation throws
 * {@link NotImplementedError} until passkey support lands.
 *
 * Do NOT wire this into `getCryptoProvider()` — it exists to lock in the
 * contract, not to run.
 */
export class WebCryptoProvider implements CryptoProvider {
  readonly id = 'webcrypto'

  ready(): Promise<void> {
    return Promise.reject(new NotImplementedError(this.id, 'ready'))
  }

  randomBytes(_length: number): Uint8Array {
    throw new NotImplementedError(this.id, 'randomBytes')
  }

  secretboxKeyBytes(): number {
    throw new NotImplementedError(this.id, 'secretboxKeyBytes')
  }

  secretboxNonceBytes(): number {
    throw new NotImplementedError(this.id, 'secretboxNonceBytes')
  }

  secretboxEasy(_message: Uint8Array, _nonce: Uint8Array, _key: Uint8Array): Uint8Array {
    throw new NotImplementedError(this.id, 'secretboxEasy')
  }

  secretboxOpenEasy(_ciphertext: Uint8Array, _nonce: Uint8Array, _key: Uint8Array): Uint8Array {
    throw new NotImplementedError(this.id, 'secretboxOpenEasy')
  }

  boxKeypair(): KeyPair {
    throw new NotImplementedError(this.id, 'boxKeypair')
  }

  boxSeal(_message: Uint8Array, _recipientPublicKey: Uint8Array): Uint8Array {
    throw new NotImplementedError(this.id, 'boxSeal')
  }

  boxSealOpen(_ciphertext: Uint8Array, _publicKey: Uint8Array, _privateKey: Uint8Array): Uint8Array {
    throw new NotImplementedError(this.id, 'boxSealOpen')
  }

  scalarMultBase(_privateKey: Uint8Array): Uint8Array {
    throw new NotImplementedError(this.id, 'scalarMultBase')
  }

  deriveKey(_password: string, _salt: Uint8Array, _params: Argon2Params): Promise<Uint8Array> {
    return Promise.reject(new NotImplementedError(this.id, 'deriveKey'))
  }

  wipe(_arr: Uint8Array): void {
    throw new NotImplementedError(this.id, 'wipe')
  }
}
