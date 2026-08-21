# @palladin/crypto

Candidate shared zero-knowledge crypto package for Palladin clients, implemented
with libsodium WASM.

The package is published to npm with signed provenance. The browser extension
uses the reviewed registry release; remaining consumer cutovers must continue to
verify byte compatibility against the protocol contracts before switching.

All encryption and decryption in Palladin happens on the client. This repository
is intended to centralize compatible primitives once each consumer's migration
is implemented, reviewed, and released. Until then, existing consumer code and
protocol contracts remain authoritative for production behavior.

## What's inside

- **Key derivation** — legacy Argon2id plus the frozen Identity password KDF v1
  (`deriveIdentityV1`, `assertIdentityKdfProfile`). Identity derives one
  Argon2id account root and domain-separates AuthCredential from the client-only
  master key with HKDF-SHA-256.
- **Entry encryption** — `encryptEntry` / `decryptEntry` (XSalsa20-Poly1305).
- **Vault-key sealing** — `sealVaultKey` / `unsealVaultKey` (X25519 sealed box).
- **Grant envelopes** — `produceGrantEntryEnvelope` (per-grant DEK, sealed to the
  agent's public key).
- **TOTP** — RFC 6238 (`generateTotp`, `parseOtpauthUri`, `totpParamsFromSecret`).
- **Password generator** — CSPRNG with rejection sampling (`generatePassword`).
- **Provider abstraction** — `CryptoProvider` with a live `LibsodiumProvider` and
  a reserved `WebCryptoProvider` slot for future passkeys (ECDSA P-256).
- **Canonical Vault protocol 2** — versioned XChaCha20-Poly1305 envelopes,
  HKDF-SHA-256 subkeys, X25519 sealed-key wrappers, canonical AAD/JSON, and the
  MemberVaultMetadata, MemberIndex, MemberSecret, and AgentDiscovery projections.

Protocol 2 is additive in `0.2.x`. The legacy `0.1.x` operations keep their
original byte format and remain available only for callers that have not yet
completed the coordinated non-production cutover. Protocol 2 consumers must
reject unknown suite/version discriminators; there is no algorithm fallback.

## Install

Install the exact reviewed release used by the consuming application:

```bash
npm install --save-exact @palladin/crypto@0.4.0
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
npm test         # Vitest (RFC 6238 + cross-client Protocol 2 vectors/negative tests)
npm run build    # tsup -> dist/ (ESM + CJS + d.ts)
npm run typecheck
npm pack --dry-run
```

## Security

Never change the behaviour of an existing operation (KDF params, wire formats) —
it breaks already-stored data and other clients. See [`AGENTS.md`](./AGENTS.md)
for the full rules and [`SECURITY.md`](./SECURITY.md) for responsible disclosure.

Licensed under [Apache-2.0](./LICENSE). See [NOTICE](./NOTICE),
[third-party notices](./THIRD_PARTY_NOTICES.md), and the
[trademark policy](./TRADEMARKS.md).
