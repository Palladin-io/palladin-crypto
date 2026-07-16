# Security Policy

`@palladin/crypto` implements the client-side, zero-knowledge cryptography for
Palladin — a password manager. We take vulnerabilities in this package very
seriously.

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Email **security@palladin.io** with:

- a description of the issue and its impact,
- steps to reproduce or a proof of concept,
- affected version(s) or commit,
- any suggested remediation.

We aim to acknowledge reports within 3 business days and to keep you updated as
we investigate and remediate. We support coordinated disclosure and will credit
reporters who wish to be named once a fix is released.

## Scope

In scope:

- flaws in the cryptographic construction (KDF usage, AEAD/sealed-box handling,
  nonce management, randomness),
- key material leaking through the API, errors, or return values,
- provider-abstraction bypasses that weaken the guarantees above.

Out of scope:

- vulnerabilities in third-party dependencies without a demonstrated impact on
  this package (report those upstream),
- issues requiring a compromised local host / malware already running as the
  user (outside the threat model, consistent with the product Security Model).

## Handling of secrets

This package never logs, throws, or returns key material, passwords, mnemonics,
recovery keys, or generated one-time codes. Reports of any such leak are treated
as high severity.
