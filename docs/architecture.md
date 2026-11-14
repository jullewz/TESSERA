# Architecture

Tessera is a layered, dependency-free Python package. Each layer has one job and depends only on layers below it.

```
cli.py                       argument parsing, rendering, exit codes
  │
engine.py · watch.py         snapshot / check / verify orchestration, polling loop
  │
scanner · diff · risk        walking + hashing · comparison · severity heuristics
policy · matcher             rule resolution, glob compilation
sealing · merkle · store     tamper evidence, persistence
  │
models · util · osinfo       data model, helpers, platform detection
```

## Data flow of `tessera check`

1. **Load configuration** (`config.py`). TOML is validated strictly. Every section rejects unknown keys and suggests the
   closest valid key. Paths are expanded (`~`, `$VAR`, `%VAR%`) and made absolute.
2. **Load the baseline** (`store.py`) and **verify it** (`sealing.py`). Records are re-hashed into a Merkle root,
   compared with the stored root and, when a key is available, with the HMAC seal.
3. **Scan** (`scanner.py`). An explicit stack walks each root. Each entry is resolved against the policy first, so
   ignored subtrees are never entered. Metadata comes from `lstat`. Files whose profile tracks `digest` are queued
   on a thread pool for hashing.
4. **Diff** (`diff.py`). Paths are matched between baseline and scan. For each pair, only the attributes of the
   resolved profile are compared. Unmatched paths become additions and removals. Removals and additions with the
   same content hash and size are paired up as **moves**.
5. **Assess risk** (`risk.py`). Heuristics inspect each change and raise its severity to a floor when they fire.
6. **Report** (`reporters/`), **run hooks** (`hooks.py`) and return an exit code.

## Key design decisions

### Polling over filesystem events

Watch mode re-scans on an interval. Event APIs (inotify, FSEvents, ReadDirectoryChangesW) differ per platform, drop
events under load and miss everything that happens while the monitor is down. A full re-scan compared with a sealed
baseline has none of those gaps. Native event backends are on the roadmap as an optional low-latency layer, not a
replacement.

### Last matching rule wins

Rules work like `.gitignore`: put broad rules first and specific overrides after. `tessera explain PATH` shows which
rule applies and why. An `ignore` rule on a directory prunes the walk, so files below it cannot be re-included.

### Records are canonical

`FileRecord` is a frozen dataclass. Its canonical JSON form (sorted keys, no whitespace, UTF-8) is the Merkle leaf
input, so the same filesystem state always produces the same root, on every platform and Python version.

Undecodable POSIX file names (arbitrary bytes) are mapped deterministically to backslash escapes by
`util.safe_path`, so they can be stored in SQLite and JSON and still compare equal across scans.

### Errors never abort a scan

A locked file on Windows, a permission error or a file vanishing mid-scan is recorded in the entry's `error` field.
The diff engine reports it as `unreadable`, so an attacker cannot hide a file by making it unreadable.

### Severity is a floor, not a sum

Rules set a base severity. Heuristics only raise it to their floor (`setuid` is always critical). Three or more
independent signals on one change raise it one more level. Content-free changes (only `mtime`, `inode`, `nlink`) are
capped at `low` to keep noise down.

### Directory mtime is noise

A directory's modification time changes whenever an entry inside it changes, and those entries are reported
themselves. Directory `mtime` is therefore only compared under the `paranoid` profile.

## Storage schema

```sql
baselines(id, created_at, label, host, platform, algorithm, file_count,
          merkle_root, seal, config_digest, roots, scan_seconds, error_count)
files(baseline_id, path, kind, size, mode, uid, gid, mtime_ns, inode, nlink,
      digest, link_target, attributes, error)         -- WITHOUT ROWID
meta(key, value)                                      -- schema_version
```

Each baseline is written in one transaction. The store refuses databases written by a newer schema version.

## Extending Tessera

- New heuristic: see `CONTRIBUTING.md` and [risk-heuristics.md](risk-heuristics.md).
- New report format: add a module to `reporters/` exposing `render(report, style) -> str`.
- New profile attribute: add it to `ALL_ATTRIBUTES` in `models.py`, capture it in `scanner.record_from_stat`, bump the
  store schema version and add a migration.
