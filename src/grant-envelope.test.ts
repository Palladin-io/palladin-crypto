import { describe, expect, it } from 'vitest'
import { fromBase64, toBase64 } from './encoding'
import { produceGrantEntryEnvelope } from './grant-envelope'
import { loadSodium } from './sodium-loader'

/**
 * Wrap TextEncoder output in a fresh Uint8Array — in some runtimes it can be a
 * Buffer, which fails libsodium's strict `instanceof Uint8Array` check (same
 * workaround documented in entry-crypto.ts). Production never hits this: it
 * feeds libsodium bytes from `fromBase64`, which already returns a plain
 * Uint8Array.
 */
function encode(text: string): Uint8Array {
  return new Uint8Array(new TextEncoder().encode(text))
}

/**
 * Round-trip test: the web client (producer) builds a grant envelope, and we
 * decrypt it exactly as the MCP agent (consumer) would. This is the byte-compat
 * guarantee — if the producer ever drifts from the agent's `crypto_box_seal_open`
 * + `crypto_secretbox_open_easy` expectations, this test fails.
 */
describe('produceGrantEntryEnvelope', () => {
  it('produces an envelope the agent can decrypt back to the original plaintext', async () => {
    const sodium = await loadSodium()

    // --- Setup: a Vault Key, an entry sealed under it, and an agent keypair ---
    const vaultKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
    const plaintext = encode(
      JSON.stringify({ type: 0, value: 'super-secret-token', notes: 'prod' }),
    )
    const vkNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const sealedBlob = sodium.crypto_secretbox_easy(plaintext, vkNonce, vaultKey)
    const entryContent = {
      encryptedBlob: toBase64(sealedBlob),
      nonce: toBase64(vkNonce),
    }

    const agentKeypair = sodium.crypto_box_keypair()
    const agentPublicKey = toBase64(agentKeypair.publicKey)

    // --- Producer (web client) ---
    const envelope = await produceGrantEntryEnvelope({
      entryContent,
      vaultKey,
      agentPublicKey,
    })

    // --- Consumer (MCP agent) ---
    const dek = sodium.crypto_box_seal_open(
      fromBase64(envelope.agentWrappedDek),
      agentKeypair.publicKey,
      agentKeypair.privateKey,
    )
    const recovered = sodium.crypto_secretbox_open_easy(
      fromBase64(envelope.reEncryptedBlob),
      fromBase64(envelope.nonce),
      dek,
    )

    expect(new TextDecoder().decode(recovered)).toBe(
      new TextDecoder().decode(plaintext),
    )
  })

  it('uses a fresh DEK + nonce per call (no reuse)', async () => {
    const sodium = await loadSodium()
    const vaultKey = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
    const plaintext = encode('same-input')
    const vkNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const entryContent = {
      encryptedBlob: toBase64(sodium.crypto_secretbox_easy(plaintext, vkNonce, vaultKey)),
      nonce: toBase64(vkNonce),
    }
    const agentPublicKey = toBase64(sodium.crypto_box_keypair().publicKey)

    const a = await produceGrantEntryEnvelope({ entryContent, vaultKey, agentPublicKey })
    const b = await produceGrantEntryEnvelope({ entryContent, vaultKey, agentPublicKey })

    // Different nonce and different ciphertext/wrapped DEK each time.
    expect(a.nonce).not.toBe(b.nonce)
    expect(a.reEncryptedBlob).not.toBe(b.reEncryptedBlob)
    expect(a.agentWrappedDek).not.toBe(b.agentWrappedDek)
  })

  it('throws when the entry content cannot be decrypted with the given VK', async () => {
    const sodium = await loadSodium()
    const realVk = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
    const wrongVk = sodium.randombytes_buf(sodium.crypto_secretbox_KEYBYTES)
    const vkNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const entryContent = {
      encryptedBlob: toBase64(
        sodium.crypto_secretbox_easy(encode('x'), vkNonce, realVk),
      ),
      nonce: toBase64(vkNonce),
    }
    const agentPublicKey = toBase64(sodium.crypto_box_keypair().publicKey)

    await expect(
      produceGrantEntryEnvelope({ entryContent, vaultKey: wrongVk, agentPublicKey }),
    ).rejects.toBeDefined()
  })
})
