# Entry sharing and signed grant reasons

The additive 0.13.0 API moves the current web client's Entry-sharing v1 producer,
receiver, link codec and complete-Entry projection into the shared SDK. It also
exports verification and decryption of the signed Protocol 2 grant-request reason.
Existing encrypted formats and existing exports are unchanged.

Source: `Palladin-io/palladin-react-web-panel`, current `src/shared/crypto/entry-share*`
and `reason-protocol.ts`. The sharing fixture preserves that client's independently
generated Python/native-libsodium AAD and ciphertext vector. Tests cover recipient
coordinates, nanosecond expiry, revisions above JavaScript's safe integer range,
field types, complete card/CVV/TOTP copies, ciphertext tampering and signature tampering.
TOTP issuer/account metadata with surrounding whitespace is rejected instead of
being silently trimmed by the existing URI parser; null and colon-bearing metadata
round-trip without inventing or changing an account.

Consumers must supply authenticated/request-bound scope coordinates, never derive
expected coordinates from the envelope being opened. A grant reason additionally
requires the authoritative Agent signing identity and the requested-method and
Vault message-key-version checks at the consumer boundary.

Share keys and access tokens are transient client material. The decryption key
belongs only in the link fragment, never in the create API payload. `clearEntryShareLink`
wipes byte buffers; the consumer must also discard its in-memory link and retry state
on close, lock or account change. No sharing material belongs in durable storage.

Release remains through the repository's reviewed PR and signed-tag trusted-publishing
workflow. This branch does not publish a package.
