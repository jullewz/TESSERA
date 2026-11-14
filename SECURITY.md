# Security Policy

Tessera is a security tool, so its own security matters a lot.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's
[private vulnerability reporting](https://github.com/jullewz/tessera/security/advisories/new).

Include:

- the affected version and platform
- a description of the issue and its impact
- steps or a proof of concept to reproduce it

You will receive an acknowledgement within 7 days. Fixes for confirmed issues are released as soon as practical, and
reporters are credited in the advisory unless they prefer otherwise.

## Scope

In scope:

- ways to alter a sealed baseline without `tessera verify` or `tessera check` detecting it
- forged manifests or inclusion proofs that verify as valid
- command injection through hooks, configuration or file names
- crashes or hangs triggered by crafted file names or directory structures

Out of scope:

- an attacker who holds the sealing key (see the threat model in
  [docs/security-model.md](docs/security-model.md))
- changes made between two scans and reverted before the next one (a property of any polling monitor)
