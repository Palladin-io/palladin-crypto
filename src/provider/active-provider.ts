import type { CryptoProvider } from './crypto-provider'
import { LibsodiumProvider } from './libsodium-provider'

/**
 * The active provider every high-level crypto function routes through.
 * Defaults to {@link LibsodiumProvider}. `setCryptoProvider` exists for future
 * provider swaps and for tests — production code never calls it.
 */
let active: CryptoProvider = new LibsodiumProvider()

export function getCryptoProvider(): CryptoProvider {
  return active
}

export function setCryptoProvider(provider: CryptoProvider): void {
  active = provider
}
