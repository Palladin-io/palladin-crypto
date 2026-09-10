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
- **Script execution package** — canonical Script metadata, typed parameters,
  direct/FULL authorization bindings and fail-closed whole-package verification
  layered over the existing authenticated Vault and grant envelopes.

Protocol 2 is additive in `0.2.x`. The legacy `0.1.x` operations keep their
original byte format and remain available only for callers that have not yet
completed the coordinated non-production cutover. Protocol 2 consumers must
reject unknown suite/version discriminators; there is no algorithm fallback.

## Install

The CVT-573 branch prepares `0.6.0`; it is not a published release yet. Its new
Credential write APIs share the default web Agent policy and build GRANULAR
replacement envelopes for the canonical API. FULL uses a Vault-key grant and
does not require per-entry replacement envelopes. ScriptExecution packages
remain a separate atomic write input.

`buildCanonicalGrantEnvelope` uses `encodeDeliveryBoundGrantAad`, matching the
deployed backend's `EnvelopeDescriptorCodecTests` vector including DeliveryPolicy.
The existing `encodeCanonicalEnvelopeAad` and `projectGrantPayload` exports retain
their original byte format. The new `projectCanonicalGrantPayload` adapter uses
production namespaced notes and derived TOTP codes, never TOTP seeds. Do not use
the older generic projection for this new write path.

`sealCanonicalCredentialEntry` and `projectCanonicalCredentialDiscovery` produce
the current web Credential discovery contract (Get/Exec/Inject, null/undefined
values omitted, explicit empty strings preserved). The original generic Entry/discovery APIs retain their existing
behavior. `defaultCredentialAgentFieldAccess` also owns custom-field defaults.

`currentVaultPlaintext` exposes the current web plaintext contract separately
from the byte-stable generic exports. `openCurrentMemberSecret` accepts current
Key URL metadata. `buildCanonicalScriptExecutionManifest` preserves the web's
legacy-description fallback, and `sealCanonicalScriptExecutionPackage` projects
exact approved references, including Discovery values and derived TOTP codes.
`refreshCanonicalScriptExecutionPackage` retains that projection when incrementing
the package revision. The generic Script package producer/refresher retain their
original projection behavior. Current Script references also accept the registered
`key.url` field. TOTP generation clears its owned decoded-key and digest buffers;
immutable JavaScript strings and internal hash-wasm allocations are GC-managed.

Readable legacy custom-field UUIDs may contain uppercase, but canonical grant
field IDs require lowercase. Grant choices exclude noncanonical IDs rather than
silently rewriting identity or weakening the receiver's field-set commitment.

Known existing contract limitation: current web TOTP projection stores a code
and relative `expiresIn` at package construction time, not a durable source for
future derivation. This extraction preserves that behavior; it does not make a
stored TOTP code fresh at delayed delivery/execution. Changing delivery timing or
adding authenticated absolute expiry requires a coordinated producer/consumer
contract change outside CVT-573. Generic legacy exports are not a fallback for
the current no-seed payload contract.

Local consumer acceptance covers atomic Entry replacement inputs with GRANULAR
envelopes and complete dependent ScriptExecution packages. Publication still
requires security review and the signed-tag release workflow; local tarball
validation is not evidence of a released registry dependency.

Consumer adoption and registry installation must follow the reviewed, signed
`0.6.0` release; a feature-branch dependency is not a supported installation.

After the reviewed `0.6.0` release is published, install its exact registry version:

```bash
npm install --save-exact @palladin/crypto@0.6.0
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

## Candidate browser shared unlock transport (0.7.0)

`createSharedUnlockParticipant` provides one ephemeral, in-memory MK transfer
using X25519, HKDF-SHA-256 and XChaCha20-Poly1305. The source and recipient use
independently authorized `SharedUnlockContext` values and peer public keys from
the verified browser channel. Both transfer directions bind the full context,
use distinct key derivation domains, and expire within 30 seconds. A participant
allows one attempt and is disposed on success, failure or explicit cancellation.

This API is a crypto primitive, **not a browser authenticator or Identity login
API**. Callers must implement `assertCurrent`, recheck current authority after
awaiting `open` and before installing the returned MK, and wipe a cancelled
result. It must reject lock/logout/off/revoke, changed account, environment,
document/generation, authorization or expired inherited limits. Persistent
markers, copied tokens and possession of an MK cannot authorize a new session.

The candidate contract and generated synthetic vectors are owned by
[palladin-protocol](https://github.com/Palladin-io/palladin-protocol/tree/feat/cvt-583-shared-unlock/contracts/shared-unlock).
The fixture copy in `src/fixtures/shared-unlock-v1/` is test-only and excluded
from the package. The contract remains candidate pending the complete Identity
bootstrap/lifecycle contract, browser integration and release verification;
release tag and fixture digest must be pinned before consumer cutover. Existing
Vault, Identity KDF and Agent Inject operations are unchanged.

`createSharedUnlockIdentityProofSigner` generates the separate, RAM-only Ed25519
receiver proof key before source authorization. It signs consume once and then
commit once for the same Identity operation, binding the full MK transcript hash,
challenge and lifetime. `assertCurrent` remains mandatory. This local ordering
complements the required server-side atomic consume; it does not replace it.
Independent Node-generated proof vectors are also consumed by the .NET verifier.
