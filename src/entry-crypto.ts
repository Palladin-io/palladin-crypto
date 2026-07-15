import { toBase64, fromBase64 } from './encoding'
import { getCryptoProvider } from './provider/active-provider'
import type { EntryContent, EntryPlaintext } from './payload-types'

/**
 * Encrypt a typed entry payload with the caller's Vault Key.
 *
 * Every entry is stored as a JSON object — a discriminated union on
 * `type` that carries either a single secret value (KEY) or the
 * username/password/url tuple (CREDENTIAL). Persisting the `type`
 * inside the blob means decrypt round-trips back to the exact same
 * object shape without depending on out-of-band metadata.
 *
 * Output is the {@link EntryContent} expected by `POST /vaults/{id}/entries`
 * — a flat `(encryptedBlob, nonce)` pair. The plaintext type lives on the
 * outer entry `type` field; the client uses it to pick the right schema
 * when decrypting.
 *
 * The libsodium primitives stay in a single audited module (the crypto
 * provider). Feature code imports this helper rather than reaching for
 * `crypto_secretbox` directly.
 */
export async function encryptEntry(
  payload: EntryPlaintext,
  vaultKey: Uint8Array,
): Promise<EntryContent> {
  const provider = getCryptoProvider()
  await provider.ready()
  const nonce = provider.randomBytes(provider.secretboxNonceBytes())
  // Wrap the encoded plaintext in a fresh Uint8Array so libsodium's
  // strict instanceof check passes regardless of the runtime
  // (Node's TextEncoder returns a Buffer in some test environments,
  // which fails the check even though the byte payload is identical).
  const plaintext = new Uint8Array(new TextEncoder().encode(JSON.stringify(payload)))
  const cipher = provider.secretboxEasy(plaintext, nonce, vaultKey)
  return {
    encryptedBlob: toBase64(cipher),
    nonce: toBase64(nonce),
  }
}

/**
 * Decrypt the {@link EntryContent} produced by {@link encryptEntry} or by
 * the mobile/agent client — same wire format. Throws if the MAC fails;
 * callers should translate into a typed UI error.
 *
 * The decoded plaintext bytes are JSON-parsed and then the byte buffer
 * is wiped so the only surviving artefact is the structured object the
 * caller needs. Strings inside that object retain plaintext secrets —
 * the caller is responsible for keeping them off persistent storage.
 */
export async function decryptEntry(
  content: EntryContent,
  vaultKey: Uint8Array,
): Promise<EntryPlaintext> {
  const provider = getCryptoProvider()
  await provider.ready()
  const cipher = fromBase64(content.encryptedBlob)
  const nonceBytes = fromBase64(content.nonce)
  const plaintext = provider.secretboxOpenEasy(cipher, nonceBytes, vaultKey)
  try {
    return JSON.parse(new TextDecoder().decode(plaintext)) as EntryPlaintext
  } finally {
    // Wipe the decoded plaintext buffer — the parsed object keeps the
    // secret strings (managed by the caller), but the raw byte buffer
    // should not linger.
    provider.wipe(plaintext)
  }
}
