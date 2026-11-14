# Configuration reference

Tessera reads one TOML file. Create a commented starter with `tessera init`, validate it with `tessera config -v`.

**Lookup order:** `--config PATH`, `$TESSERA_CONFIG`, `./tessera.toml`, then the per-user config directory:

| Platform | Config directory | Data directory (baseline store) |
|---|---|---|
| Linux | `$XDG_CONFIG_HOME/tessera` or `~/.config/tessera` | `$XDG_DATA_HOME/tessera` or `~/.local/share/tessera` |
| macOS | `~/Library/Application Support/tessera` | same |
| Windows | `%APPDATA%\tessera` | `%LOCALAPPDATA%\tessera` |

Paths in the file expand `~` and environment variables (`$HOME`, `${HOME}`, and `%USERPROFILE%` on Windows). Use
forward slashes on Windows (`C:/Windows/System32`) to avoid TOML escape rules.

## `[general]`

| Key | Default | Description |
|---|---|---|
| `store` | data dir `/tessera.db` | SQLite baseline database |
| `key_file` | config dir `/seal.key` | HMAC sealing key. Missing key means unsealed baselines |
| `algorithm` | `"sha256"` | `sha256`, `sha512`, `blake2b` or `sha3_256` |
| `workers` | `min(8, cpu count)` | Hashing threads, 1 to 64 |
| `max_file_size` | `"512MiB"` | Larger files are tracked by metadata only. Accepts `B`, `KB`, `KiB`, `MB`, `MiB`, `GB`, `GiB` |
| `chunk_size` | `"1MiB"` | Read buffer size, at least `4KiB` |
| `follow_symlinks` | `false` | Follow symlinks during the walk (loops are detected) |
| `one_filesystem` | `true` | Do not descend into other mounts or volumes |
| `case_sensitive` | `"auto"` | Pattern matching case. `auto` is `false` on Windows and macOS, `true` on Linux |
| `default_profile` | `"full"` | Profile for paths no rule matches |
| `default_severity` | `"medium"` | Severity for paths no rule matches, or rules without one |

## `[[watch]]`

One table per root to scan. A root can be a directory or a single file.

```toml
[[watch]]
path = "/etc"
exclude = ["**/*.swp", "/etc/mtab"]
```

`exclude` patterns skip entries entirely (they are never recorded). Use `ignore` rules for the same effect across
all roots.

## `[[rule]]`

```toml
[[rule]]
pattern = "/etc/{passwd,shadow}"
profile = "full"
severity = "critical"    # optional
```

Rules are evaluated in order and **the last match wins**.

### Pattern syntax

| Syntax | Matches |
|---|---|
| `*` | anything except `/` |
| `?` | one character except `/` |
| `[abc]`, `[!abc]` | character class, negated class |
| `{a,b}` | alternatives, nesting allowed |
| `**` | any number of directories, including none |
| no `/` in pattern | the file name anywhere: `*.log` equals `**/*.log` |
| trailing `/**` | the directory itself and everything below |

Backslashes count as path separators, so `C:\Windows\**` and `C:/Windows/**` are the same pattern.

### Profiles

| Profile | Tracks | Use for |
|---|---|---|
| `full` | kind, size, mode, uid, gid, mtime, content hash, link target, platform attributes | default for system files |
| `paranoid` | everything in `full` plus inode, link count and directory mtime | high-value paths |
| `content` | kind, size, content hash, link target | files whose permissions churn legitimately |
| `permissions` | kind, mode, uid, gid, platform attributes | files whose content churns, like `/etc/resolv.conf` |
| `append` | ownership and permissions. Size may grow, shrinking is a high-severity change | logs |
| `existence` | kind only (added, removed, type changes) | caches, spool directories |
| `ignore` | nothing, the subtree is not walked | temp files, editor swap files |

Define your own:

```toml
[profiles.hash-only]
attributes = ["kind", "digest"]

[[rule]]
pattern = "/opt/models/**"
profile = "hash-only"
```

Available attributes: `kind`, `size`, `mode`, `uid`, `gid`, `mtime_ns`, `inode`, `nlink`, `digest`, `link_target`,
`attributes`.

### Severities

`info` < `low` < `medium` < `high` < `critical`. Risk heuristics can raise a severity, never lower it. See
[risk-heuristics.md](risk-heuristics.md).

## `[[hook]]`

Hooks run after `check` and on every watch cycle with new changes, when the highest severity reaches `min_severity`.
The payload is the JSON report (see `-f json`), filtered to changes at or above `min_severity`, plus a `hook` field.

### Command hooks

```toml
[[hook]]
name = "notify"
command = ["python3", "/opt/tessera/notify.py"]   # list form, no shell
min_severity = "high"
timeout = 15                                      # seconds, 0 < timeout <= 300
```

The report arrives on standard input. A non-zero exit code is logged as a hook failure. The program is resolved on
`PATH` (with `PATHEXT` on Windows) and run with `shell=False`, so nothing in the report is ever interpreted as shell
syntax.

### Webhooks

```toml
[[hook]]
name = "siem"
url = "https://siem.example.internal/ingest/tessera"
headers = { Authorization = "Bearer ${TESSERA_TOKEN}" }
min_severity = "critical"
```

Only `http://` and `https://` URLs are accepted. Put secrets in environment variables, not in the file.

## `[report]`

| Key | Default | Description |
|---|---|---|
| `format` | `"terminal"` | `terminal`, `json`, `markdown`, `html`, `sarif` |
| `min_severity` | `"info"` | Hide changes below this level |
| `fail_on` | `"low"` | Exit code `1` when a change at or above this level exists |

Command-line flags (`--format`, `--min-severity`, `--fail-on`) override these.

## Policy drift

Each baseline stores a digest of the settings that affect a scan (roots, excludes, algorithm, policy). When the
current configuration differs, `check` adds a note, because changes may come from the new policy rather than the
filesystem. Take a fresh `snapshot` after changing the policy on purpose.
