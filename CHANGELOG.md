# Changelog

All notable changes to Tessera are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-14

First public release.

### Added
- Parallel filesystem scanner with streaming SHA-256, SHA-512, BLAKE2b and SHA3-256 hashing.
- Policy engine with `**` and `{a,b}` globs, last-match-wins rules, seven built-in profiles and custom profiles.
- Diff engine detecting added, removed, modified, metadata, type-changed, moved and unreadable entries.
- Risk heuristics: setuid/setgid, world-writable, root ownership changes, persistence locations, new system
  executables, Windows hidden/system attributes, timestomping, symlink retargeting and log truncation.
- RFC 6962 Merkle roots, HMAC-SHA256 baseline seals, signed manifests and per-file inclusion proofs.
- Transactional SQLite baseline store with history, diffing and pruning.
- Reporters: terminal, JSON, Markdown, self-contained HTML and SARIF 2.1.0.
- Watch mode with de-duplicated alerts, command hooks and webhooks.
- CLI commands: `init`, `keygen`, `snapshot`, `check`, `diff`, `watch`, `baselines`, `show`, `verify`,
  `export`, `prove`, `verify-proof`, `explain`, `config`, `prune`.
- Starter configurations for Linux, macOS and Windows 10+.

[Unreleased]: https://github.com/jullewz/tessera/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jullewz/tessera/releases/tag/v0.1.0
