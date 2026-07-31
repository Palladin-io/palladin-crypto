# Contributing to @palladin/crypto

This package implements security-critical cryptographic operations. Start with a
public issue describing the problem, threat model, byte-compatibility impact,
and proposed tests before opening a substantial pull request. Report
vulnerabilities privately according to `SECURITY.md`.

## Cryptographic compatibility

Never change existing KDF parameters, encoded wire formats, nonce handling, or
operation output bytes in place. Such a change requires an explicit protocol
version, coordinated consumer migration, and positive and negative compatibility
tests. Never include real passwords, keys, tokens, mnemonics, or vault data in
issues, fixtures, logs, screenshots, or pull requests.

Consumer cutover to this package and Protocol 2 integration are still pending.
Coordinate any public API change with those migration plans; do not describe a
consumer as migrated until its released code imports the package.

Run `npm run typecheck`, `npm run build`, `npm test`, `npm run oss:check`, and
`npm pack --dry-run` before requesting review.

## Legal terms

By contributing, you agree that your contribution is licensed under the license
applicable to the files you modify.

Every commit must include a Developer Certificate of Origin sign-off:

    Signed-off-by: Your Name <your.email@example.com>

Add it with `git commit -s`. Do not submit code copied from another project
unless its source, copyright, and license are identified and compatible.

Submitting a contribution does not grant rights to Palladin trademarks.
