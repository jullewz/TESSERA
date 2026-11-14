# Security model

This document states what Tessera protects against, how, and where its guarantees end.

## Goal

Detect unauthorised changes to monitored files, and detect attempts to hide those changes by tampering with Tessera's
own records.

## Mechanisms

### 1. Content and metadata baselines

Each monitored entry is recorded with its content hash (SHA-256 by default) and metadata. Changing a file's content
without changing its hash requires a second-preimage attack on the hash function.

### 2. Merkle root

Records are sorted by path, serialised canonically and hashed into an RFC 6962 Merkle tree:

```
leaf = SHA-256(0x00 || canonical_json(record))
node = SHA-256(0x01 || left || right)
```

The `0x00` / `0x01` prefixes give domain separation, so an internal node can never be passed off as a leaf. Any
changed, added or removed record changes the root.

### 3. HMAC seal

The root and the baseline metadata (host, platform, time, algorithm, record count, config digest) are sealed:

```
seal = HMAC-SHA256(key, "tessera-seal-v1\n" || canonical_json(header))
```

An attacker who edits the SQLite store must recompute the root (easy) and forge the seal (requires the key). Seals are
compared in constant time.

### 4. Inclusion proofs

`tessera prove` produces the audit path for one record. A verifier with the sealed header can confirm that the record
belonged to the baseline using `log2(n)` hashes, without seeing any other record. The record count is bound by the
sealed header, which prevents proofs against a tree of a different size.

## Threat model

| Attacker can | Tessera detects it | Notes |
|---|---|---|
| Modify, add, remove or rename monitored files | Yes | Reported with severity on the next scan |
| Restore the old `mtime` after editing (timestomping) | Yes | Content hash differs, flagged critical |
| Make a file unreadable to hide it | Yes | Reported as `unreadable` |
| Edit the baseline database | Yes, with a key | `verify` and `check` exit `3` |
| Delete the baseline database | Yes, indirectly | `check` fails with no baseline. Keep exported manifests offsite |
| Read the sealing key | **No** | They can forge seals. Protect the key (below) |
| Replace the `tessera` program itself | **No** | Run Tessera from read-only or verified media for high assurance |
| Change a file and revert it between two scans | **No** | Inherent to polling. Shorten the interval |
| Hook the kernel (rootkit) to lie to `stat`/`read` | **No** | No userland tool can detect this reliably |

## Protecting the key

The seal is only as strong as the key's secrecy. In order of increasing assurance:

1. **Default:** key file readable only by its owner (`0600` on POSIX). Tessera warns when group or others can read
   it. Protects against non-root attackers.
2. **Offline key:** keep the key on removable or read-only media and mount it only for `snapshot` and `verify`.
   Run `check` without the key: it still detects changes, and reports the seal as `not checked`.
3. **Separate verifier:** `tessera export` the manifest on the monitored host, copy it to a trusted machine and run
   `tessera verify --manifest` there with the key. The monitored host never holds the key after the snapshot.

On Windows, POSIX modes do not apply. Restrict the key file with NTFS permissions:

```powershell
icacls "$env:APPDATA\tessera\seal.key" /inheritance:r /grant:r "$($env:USERNAME):(R,W)"
```

## Safe handling of untrusted input

- File names are never passed to a shell. Hooks run with `shell=False` and receive data on standard input.
- All HTML output is escaped. The HTML report loads no external resources.
- SQL uses bound parameters only.
- Configuration rejects unknown keys and validates types and ranges.
- Manifests and proofs are parsed defensively. Malformed input produces an integrity error, not a crash.
