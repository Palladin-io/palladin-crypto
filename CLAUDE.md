# @palladin/crypto

Single source of Palladin's client-side, zero-knowledge crypto. Consumed by the
React web panel and the browser extension (MV3), both of which must produce
byte-identical ciphertext so the mobile and MCP-agent clients can decrypt it.

## Hard rules

- **This is the only place client-side crypto lives.** Web panel and extension
  import from here — they never inline `libsodium`/`hash-wasm` calls.
- **Never change the behaviour of an existing operation.** KDF parameters
  (`ARGON2_PARAMS`), the `crypto_secretbox` / `crypto_box_seal` wire formats, and
  the base64 encoding are the contract shared with already-stored data and other
  clients. A parameter or format change silently breaks unlock/decrypt for
  existing users. Any such change requires a versioned migration, not an edit.
- **Semver.** Behaviour-preserving refactors → patch. Additive API → minor.
  Anything that could change produced bytes → treat as a breaking change and
  coordinate a migration before publishing.
- **No secrets, ever.** Nothing here logs, throws, or returns key material,
  passwords, mnemonics, or generated codes. This repo is public.
- **No remote code.** `libsodium-wrappers` and `hash-wasm` embed their WASM as
  in-JS base64 and are kept as external runtime deps so the consumer bundles
  them — required by the extension's MV3 CSP (no remote script).

## Provider abstraction

The public API routes through a swappable `CryptoProvider`:

- `LibsodiumProvider` — the only live implementation (XSalsa20-Poly1305 secretbox,
  X25519 `crypto_box_seal`, Argon2id via `hash-wasm`).
- `WebCryptoProvider` — reserved, empty slot for the passkeys work (ECDSA P-256).
  Implements the contract but every method throws `NotImplementedError`. Do not
  wire it into `getCryptoProvider()`.

TOTP (RFC 6238) and the password generator are standalone standard utilities —
they are deterministic and unrelated to the swappable asymmetric scheme, so they
do not route through the provider.

## Layout

```
src/
  index.ts                 # public barrel
  provider/                # CryptoProvider contract + implementations
  sodium-loader.ts         # lazy libsodium WASM init
  argon2.ts                # KDF params + deriveKey
  sodium.ts                # keypair + symmetric helpers (via provider)
  encoding.ts              # base64 <-> bytes
  entry-crypto.ts          # encrypt/decrypt entry payloads
  vault-key.ts             # seal/unseal VK
  grant-envelope.ts        # GRANULAR grant re-encryption
  password-generator.ts    # CSPRNG password generator
  totp.ts                  # RFC 6238 TOTP + otpauth parsing
  payload-types.ts         # crypto payload types
```

## Build & test

- `npm run build` / `npm run prepare` — tsup, emits ESM + CJS + `.d.ts` to `dist/`.
  `prepare` lets the package work as a git dependency (npm builds it on install).
- `npm test` — Vitest (node env). Includes RFC 6238 TOTP vectors and
  producer→consumer round-trips (derive→wrap→unwrap, seal→unseal, grant envelope
  decrypted as the agent would).
- `npm run typecheck` — `tsc --noEmit`.

`AGENTS.md` and `CLAUDE.md` are kept byte-for-byte identical.
