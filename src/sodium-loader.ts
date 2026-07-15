import sodium from 'libsodium-wrappers'

let readyPromise: Promise<typeof sodium> | null = null

/**
 * libsodium ships as WASM and must be awaited before use. We lazy-load it
 * on the first call and cache the promise so subsequent callers reuse the
 * same initialisation. The WASM is embedded (base64) in the JS bundle — it is
 * never fetched as remote code.
 */
export function loadSodium(): Promise<typeof sodium> {
  if (!readyPromise) {
    readyPromise = sodium.ready.then(() => sodium)
  }
  return readyPromise
}
