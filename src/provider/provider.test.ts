import { describe, expect, it } from 'vitest'
import { getCryptoProvider } from './active-provider'
import { LibsodiumProvider } from './libsodium-provider'
import { WebCryptoProvider } from './webcrypto-provider'
import { NotImplementedError } from './crypto-provider'

describe('active provider', () => {
  it('defaults to the libsodium provider', () => {
    expect(getCryptoProvider().id).toBe('libsodium')
  })
})

describe('LibsodiumProvider', () => {
  it('performs a secretbox encrypt/decrypt round-trip', async () => {
    const p = new LibsodiumProvider()
    await p.ready()

    const key = p.randomBytes(p.secretboxKeyBytes())
    const nonce = p.randomBytes(p.secretboxNonceBytes())
    const message = new Uint8Array([1, 2, 3, 4, 5])

    const cipher = p.secretboxEasy(message, nonce, key)
    const recovered = p.secretboxOpenEasy(cipher, nonce, key)

    expect(recovered).toEqual(message)
  })

  it('performs a sealed-box round-trip to a derived public key', async () => {
    const p = new LibsodiumProvider()
    await p.ready()

    const kp = p.boxKeypair()
    const derivedPk = p.scalarMultBase(kp.privateKey)
    expect(derivedPk).toEqual(kp.publicKey)

    const message = new Uint8Array([9, 8, 7])
    const sealed = p.boxSeal(message, kp.publicKey)
    const opened = p.boxSealOpen(sealed, kp.publicKey, kp.privateKey)

    expect(opened).toEqual(message)
  })

  it('throws if used before ready()', () => {
    const p = new LibsodiumProvider()
    expect(() => p.randomBytes(1)).toThrow()
  })
})

describe('WebCryptoProvider (reserved slot)', () => {
  const p = new WebCryptoProvider()

  it('has the expected id', () => {
    expect(p.id).toBe('webcrypto')
  })

  it('rejects ready() with NotImplementedError', async () => {
    await expect(p.ready()).rejects.toBeInstanceOf(NotImplementedError)
  })

  it('rejects deriveKey() with NotImplementedError', async () => {
    await expect(
      p.deriveKey('pw', new Uint8Array(16), {
        memorySize: 19456,
        iterations: 2,
        parallelism: 1,
        hashLength: 32,
      }),
    ).rejects.toBeInstanceOf(NotImplementedError)
  })

  it('throws NotImplementedError from every synchronous primitive', () => {
    const bytes = new Uint8Array(0)
    expect(() => p.randomBytes(1)).toThrow(NotImplementedError)
    expect(() => p.secretboxKeyBytes()).toThrow(NotImplementedError)
    expect(() => p.secretboxNonceBytes()).toThrow(NotImplementedError)
    expect(() => p.secretboxEasy(bytes, bytes, bytes)).toThrow(NotImplementedError)
    expect(() => p.secretboxOpenEasy(bytes, bytes, bytes)).toThrow(NotImplementedError)
    expect(() => p.boxKeypair()).toThrow(NotImplementedError)
    expect(() => p.boxSeal(bytes, bytes)).toThrow(NotImplementedError)
    expect(() => p.boxSealOpen(bytes, bytes, bytes)).toThrow(NotImplementedError)
    expect(() => p.scalarMultBase(bytes)).toThrow(NotImplementedError)
    expect(() => p.wipe(bytes)).toThrow(NotImplementedError)
  })
})
