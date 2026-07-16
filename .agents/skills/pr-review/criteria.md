# PR Review Criteria - @palladin/crypto

Load `AGENTS.md` in full before reviewing. This package is the byte-level crypto
contract shared by Palladin clients. Security and backward compatibility issues
are Critical and blocking.

## Cryptographic compatibility

- Reject changes to Argon2id parameters, salt handling, nonce sizes, base64
  encoding, `crypto_secretbox`, `crypto_box_seal`, or payload shapes unless the
  PR includes an explicitly versioned migration for existing data.
- Existing operations must continue producing and consuming compatible bytes
  across web, extension, mobile, and agent clients.
- New algorithms go behind the provider abstraction. Do not bypass
  `CryptoProvider` or wire the placeholder `WebCryptoProvider` into production.
- Randomness must come from a CSPRNG. Reject `Math.random`, predictable nonces,
  nonce reuse, or implicit deterministic key generation.

## Secret handling

- Reject logging, analytics, error messages, fixtures, snapshots, or persistent
  storage containing passwords, keys, TOTP seeds, plaintext payloads, or codes.
- Temporary key copies are wiped in `finally` paths where practical. No early
  return may bypass cleanup.
- Public errors are value-free and do not expose cryptographic material.

## Supply chain and public repository

- Remote code is forbidden. WASM and JavaScript used at runtime are bundled by
  consumers and compatible with MV3 CSP.
- New dependencies require a concrete need, maintained provenance, lockfile
  updates, and no high-severity audit finding.
- No credentials, internal infrastructure secrets, signing keys, or unpublished
  endpoints may enter this public repository.
- PR workflows must not execute untrusted fork code with repository secrets.

## API and provider design

- Public API changes are additive and semver-correct unless accompanied by a
  coordinated breaking migration.
- Keep TOTP and password generation outside the asymmetric provider unless the
  contract genuinely changes.
- Strict TypeScript, no `any`, unsafe assertions, or duplicated crypto logic.
- Keep one implementation of each primitive and export it through `src/index.ts`.

## Tests

- Preserve RFC 6238 vectors and producer-consumer round trips.
- Byte-affecting changes require fixed compatibility vectors for old and new
  code paths.
- `npm run typecheck`, `npm run build`, `npm test`, `npm audit --audit-level=high`,
  and `git diff --check` pass.
- `AGENTS.md` and `CLAUDE.md` remain byte-for-byte identical.

## Review output

Report only concrete findings with file and line references. Treat secret
exposure, cryptographic regression, compatibility breakage, weak randomness,
or unversioned wire-format changes as Critical.
