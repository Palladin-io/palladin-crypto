# Operation-time TOTP grant migration

`buildCanonicalGrantEnvelopeV2` is an explicit opt-in API for encrypted
`palladin.grant-payload.v2`. The existing `buildCanonicalGrantEnvelope`, v1
projection/parser and Script reference APIs retain their original behavior.
The additive API requires a reviewed minor release and consumers pinned to that
exact registry version before rollout.

V2 projects only explicitly approved fields allowed by Member policy. Primary
and custom TOTP values contain a strict source object for native-runtime-only
RFC 6238 derivation. No code is generated at grant construction time. Issuer and
account metadata are omitted. Field-set commitment, scopes, key/revision binding,
methods and delivery policy use the existing authenticated Vault envelope.
The encrypted source never reaches the backend as plaintext. The source is
sensitive: callers must not log or serialize it outside that encrypted envelope.

The native consumer must support the schema before any Member producer switches.
Get field returns code/expiry, full Get redacts sources, Exec materializes a code
in the environment, and Inject sends only a code. Member/runtime source memory
must not be persisted. See the public `palladin-protocol` GrantPayload v2 registry
for exact source encoding and supported algorithms/limits.

Roll out compatible native consumers, release this package, then explicitly
migrate web, extension and mobile producers and refresh grants through an
unlocked authorized Member. Existing selected-field restrictions remain intact.
Old producers must not downgrade a refreshed v2 grant: coordinate rollout or
apply an explicit version gate. The Script reference producer is a separate
cutover and is not changed by this additive API. No client cutover or production
AWS acceptance is claimed by these library tests.

## Conformance fixtures

`src/fixtures/grant-payload-v2/vectors.json` is copied byte-for-byte from
`Palladin-io/palladin-protocol/contracts/grant-payload/v2/vectors.json`, at commit `331d94e6c5ba4b5adaba07fda286a3a20633b78f`, generated
by its committed `scripts/generate-v2.mjs`. Seeds are public RFC 6238 Appendix B
material. Regenerate upstream and copy the result; never edit fixture outputs.
Tests verify canonical parsing/encoding and source rejection. Existing envelope
round-trip tests exercise both versions and authenticated-data corruption.
