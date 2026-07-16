# @palladin/crypto

Palladin shared zero-knowledge crypto package (libsodium WASM) — the single
source of client-side crypto for the web panel and the browser extension.

All encryption and decryption in Palladin happens on the client. This package
holds every primitive so that the web panel, the browser extension, and (by wire
compatibility) the mobile and MCP-agent clients all speak the exact same crypto.

## What's inside

- **Key derivation** — Argon2id (`deriveKey`, `ARGON2_PARAMS`).
- **Entry encryption** — `encryptEntry` / `decryptEntry` (XSalsa20-Poly1305).
- **Vault-key sealing** — `sealVaultKey` / `unsealVaultKey` (X25519 sealed box).
- **Grant envelopes** — `produceGrantEntryEnvelope` (per-grant DEK, sealed to the
  agent's public key).
- **TOTP** — RFC 6238 (`generateTotp`, `parseOtpauthUri`, `totpParamsFromSecret`).
- **Password generator** — CSPRNG with rejection sampling (`generatePassword`).
- **Provider abstraction** — `CryptoProvider` with a live `LibsodiumProvider` and
  a reserved `WebCryptoProvider` slot for future passkeys (ECDSA P-256).

## Install

```bash
npm install @palladin/crypto
```

## Usage

```ts
import { deriveKey, encryptEntry, decryptEntry, ENTRY_TYPE_KEY } from '@palladin/crypto'

const mk = await deriveKey(password, saltBytes)
const content = await encryptEntry({ type: ENTRY_TYPE_KEY, value: 'secret' }, vaultKey)
const plaintext = await decryptEntry(content, vaultKey)
```

## Develop

```bash
npm install      # runs prepare -> build
npm test         # Vitest (RFC 6238 vectors + round-trip tests)
npm run build    # tsup -> dist/ (ESM + CJS + d.ts)
npm run typecheck
npm pack --dry-run
```

## Security

Never change the behaviour of an existing operation (KDF params, wire formats) —
it breaks already-stored data and other clients. See [`AGENTS.md`](./AGENTS.md)
for the full rules and [`SECURITY.md`](./SECURITY.md) for responsible disclosure.

Licensed under [GPL-3.0-or-later](./LICENSE).
