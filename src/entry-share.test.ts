import { describe, expect, it } from 'vitest'
import { fromBase64, toBase64 } from './encoding'
import { entryShareAad, openEntryShare, prepareEntryShare, type EntryShareScope, type EntryShareSnapshot } from './entry-share'
import { loadSodium } from './sodium-loader'
import { wipe } from './sodium'
import { decodeHex, encodeHex } from './vault-v2-bytes'
import vector from './fixtures/entry-share-v1.json'

const scope: EntryShareScope = {
  shareId: '00112233-4455-4677-8899-aabbccddeeff',
  organizationId: '11112233-4455-4677-8899-aabbccddeeff',
  vaultId: '22222233-4455-4677-8899-aabbccddeeff',
  entryId: '33332233-4455-4677-8899-aabbccddeeff',
  sourceRevision: '9007199254740993',
  expiresAt: '2026-09-21T12:00:00.123456789Z',
}
const snapshot: EntryShareSnapshot = {
  schema: 'palladin.entry-share.v1', title: 'Test credential', entryType: 'credential',
  fields: [{ id: 'credential.password', label: 'Password', type: 'concealed', value: '  e\u0301\u0000🔑  ' }],
}

describe('Entry sharing encryption', () => {
  it('matches independently generated Python/native-libsodium AAD and ciphertext', async () => {
    expect(encodeHex(entryShareAad(vector.scope))).toBe(vector.aadHex)
    expect(await openEntryShare(vector, vector.scope, vector.scope.shareId, decodeHex(vector.keyHex)))
      .toEqual(vector.snapshot)
  })

  it('preserves selected values byte-for-byte without normalizing or trimming', async () => {
    const packet = await prepareEntryShare(scope, snapshot)
    try {
      expect(await openEntryShare(packet, scope, scope.shareId, packet.key)).toEqual(snapshot)
      expect(packet.key).toHaveLength(32)
      expect(packet.accessToken).toHaveLength(32)
      expect(fromBase64(packet.nonce)).toHaveLength(24)
      expect(packet.accessToken).not.toEqual(packet.key)
    } finally { wipe(packet.key); wipe(packet.accessToken) }
  })

  it('generates independent keys, access bearers and nonces for each snapshot', async () => {
    const first = await prepareEntryShare(scope, snapshot)
    const second = await prepareEntryShare(scope, snapshot)
    try {
      expect(first.key).not.toEqual(second.key)
      expect(first.accessToken).not.toEqual(second.accessToken)
      expect(first.nonce).not.toBe(second.nonce)
      expect(first.ciphertext).not.toBe(second.ciphertext)
    } finally {
      for (const packet of [first, second]) { wipe(packet.key); wipe(packet.accessToken) }
    }
  })

  it.each(['shareId', 'organizationId', 'vaultId', 'entryId', 'sourceRevision', 'expiresAt'] as const)(
    'rejects substituted %s authority', async (field) => {
      const packet = await prepareEntryShare(scope, snapshot)
      const changed = { ...scope, [field]: field === 'sourceRevision' ? '9007199254740994'
        : field === 'expiresAt' ? '2026-09-21T12:00:00.123456788Z'
          : '44442233-4455-4677-8899-aabbccddeeff' }
      try {
        await expect(openEntryShare(packet, changed, changed.shareId, packet.key)).rejects.toThrow('Invalid Entry sharing snapshot')
      } finally { wipe(packet.key); wipe(packet.accessToken) }
    },
  )

  it('rejects a self-consistent packet for a different requested link', async () => {
    const packet = await prepareEntryShare(scope, snapshot)
    try {
      await expect(openEntryShare(packet, scope, scope.vaultId, packet.key)).rejects.toThrow()
    } finally { wipe(packet.key); wipe(packet.accessToken) }
  })

  it.each(['key', 'nonce', 'ciphertext'] as const)('rejects a changed %s', async (field) => {
    const packet = await prepareEntryShare(scope, snapshot)
    try {
      const bytes = field === 'key' ? packet.key : fromBase64(packet[field])
      bytes[0] ^= 1
      if (field !== 'key') packet[field] = toBase64(bytes)
      await expect(openEntryShare(packet, scope, scope.shareId, packet.key)).rejects.toThrow()
    } finally { wipe(packet.key); wipe(packet.accessToken) }
  })

  it('does not treat the access bearer as a decryption key', async () => {
    const packet = await prepareEntryShare(scope, snapshot)
    try {
      await expect(openEntryShare(packet, scope, scope.shareId, packet.accessToken)).rejects.toThrow()
    } finally { wipe(packet.key); wipe(packet.accessToken) }
  })

  it('encodes equivalent UTC Instant representations identically, retaining nanoseconds', () => {
    expect(entryShareAad({ ...scope, expiresAt: '2026-09-21T12:00:00Z' }))
      .toEqual(entryShareAad({ ...scope, expiresAt: '2026-09-21T12:00:00.000000000Z' }))
    expect(encodeHex(entryShareAad(scope)).endsWith('075bcd15')).toBe(true)
    expect(encodeHex(entryShareAad(scope))).toContain('0020000000000001')
  })

  it.each(['2026-02-30T12:00:00Z', '2026-09-21T12:00:00+00:00', 'bad',
    '2026-09-21T12:00:00.1234567891Z'])('rejects ambiguous or invalid expiry %s', (expiresAt) => {
    expect(() => entryShareAad({ ...scope, expiresAt })).toThrow()
  })

  it.each(['01', '-1', '1.5', '18446744073709551616'])('rejects invalid revision %s', (sourceRevision) => {
    expect(() => entryShareAad({ ...scope, sourceRevision })).toThrow()
  })

  it('refuses oversize plaintext before encrypting', async () => {
    await expect(prepareEntryShare(scope, { ...snapshot, fields: [{ ...snapshot.fields[0], value: 'x'.repeat(262_144) }] }))
      .rejects.toThrow('Invalid Entry sharing snapshot')
  })

  it.each([
    { ...snapshot, agentFieldAccess: { password: 'discovery' } },
    { ...snapshot, fields: [snapshot.fields[0], snapshot.fields[0]] },
    { ...snapshot, fields: [] },
    { ...snapshot, fields: [{ ...snapshot.fields[0], grantId: scope.entryId }] },
    { ...snapshot, fields: [{ ...snapshot.fields[0], type: 'text' }] },
    { ...snapshot, fields: [{ ...snapshot.fields[0], id: 'key.value' }] },
    { ...snapshot, fields: [{ ...snapshot.fields[0], id: 'agentFieldAccess' }] },
  ])('rejects invalid decrypted plaintext without exposing validation input', async (value) => {
    const s = await loadSodium()
    const key = new Uint8Array(32).fill(2)
    const nonce = new Uint8Array(24).fill(3)
    const plaintext = Uint8Array.from(new TextEncoder().encode(JSON.stringify(value)))
    const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, entryShareAad(scope), null, nonce, key)
    try {
      await expect(openEntryShare({ nonce: toBase64(nonce), ciphertext: toBase64(ciphertext) }, scope, scope.shareId, key))
        .rejects.toEqual(new Error('Invalid Entry sharing snapshot'))
    } finally { wipe(plaintext); wipe(key) }
  })

  it.each([
    { nonce: toBase64(new Uint8Array(23)), ciphertext: toBase64(new Uint8Array(16)) },
    { nonce: toBase64(new Uint8Array(24)), ciphertext: toBase64(new Uint8Array(15)) },
    { nonce: toBase64(new Uint8Array(24)), ciphertext: 'A'.repeat(400_000) },
    { nonce: 'not base64', ciphertext: 'AAAA' },
  ])('bounds and decodes the encrypted packet before key use', async (packet) => {
    await expect(openEntryShare(packet, scope, scope.shareId, new Uint8Array(32))).rejects.toThrow()
  })
})
