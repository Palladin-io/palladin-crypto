# Security Policy

Palladin is a password manager. Do not report security vulnerabilities through
public GitHub issues, discussions, or pull requests.

## Reporting a vulnerability

Email **patryk.roguszewski@palladin.io** with `Security` in the subject, or
follow the instructions at
[palladin.io/.well-known/security.txt](https://palladin.io/.well-known/security.txt).

Include the affected package version or commit, impact, and minimal safe
reproduction steps. Do not send acquired secrets or personal data; an
anonymized proof is sufficient.

## Scope

Security-sensitive areas include cryptographic construction and wire
compatibility, KDF use, sealed-box and secretbox handling, randomness, key
material exposure, and bypasses of the provider abstraction. A dependency-only
report should demonstrate a concrete impact on this package.

## Safe harbor and testing boundaries

Good-faith research limited to the minimum necessary test on data you own, or
in an environment you are expressly authorized to test, will not be treated as
a violation of Palladin's vulnerability-testing restrictions.

The complete process and safe-harbor conditions are defined in Palladin's
[Vulnerability Disclosure Policy](https://palladin.io/vulnerability-disclosure).

Do not access another person's data, perform social engineering, disrupt
availability, destroy data, retain or disclose secrets, or publicly disclose a
vulnerability before Palladin has had a reasonable opportunity to remediate it.
