# Risk heuristics

After the diff engine finds a change, `risk.py` looks for patterns intruders leave behind. Each heuristic sets a
**severity floor**. The final severity is the highest of the rule's severity and every floor. When three or more
heuristics fire on the same change, it is raised one more level. Heuristics never lower a severity.

| Heuristic | Floor | Fires when |
|---|---|---|
| setuid / setgid gained | critical | A file gains the setuid or setgid bit |
| Timestomping | critical | Content hash changed while `mtime` stayed identical |
| World-writable | high | A file or non-sticky directory becomes writable by everyone |
| Root ownership change | high | Owner changes to or from uid 0 |
| Security-sensitive file | high | The file name is one of `passwd`, `shadow`, `sudoers`, `authorized_keys`, `hosts`, `crontab`, `ld.so.preload`, `sshd_config`, shell profiles and similar |
| Persistence location | high | An entry is added, modified or moved into cron, systemd units, `init.d`, `sudoers.d`, `profile.d`, `pam.d`, macOS `LaunchAgents`/`LaunchDaemons`, the Windows Startup folder, Windows scheduled tasks or `.ssh` |
| New or modified system executable | high | An executable (by name or execute bit) changes in `bin`, `sbin`, `lib`, `lib64`, `libexec`, `System32`, `SysWOW64` or a macOS bundle's `MacOS` folder |
| Append-only file shrank | high | A file under the `append` profile became smaller (applied by the diff engine) |
| Execute permission added | medium | A file gains an execute bit |
| New executable or script | medium | A file with an executable extension (`.exe`, `.dll`, `.ps1`, `.sh`, `.so`, `.dylib` and others) appears anywhere |
| Hidden or system attribute | medium | On Windows, a file gains the hidden or system attribute |
| Symlink retargeted | medium | A symbolic link now points somewhere else |

Reasons appear in every report format, so you see *why* a change was rated the way it was.

## Example

Adding `svc:x:0:0::/tmp:/bin/sh` to `/etc/passwd` produces a `modified` change. The rule in the starter config rates
`/etc/passwd` critical. If the rule said `medium`, the sensitive-file heuristic would still raise it to `high`.

## Writing your own

See [CONTRIBUTING.md](../CONTRIBUTING.md#adding-a-risk-heuristic). A heuristic is a plain function:

```python
def _my_check(change: Change, old: FileRecord | None, new: FileRecord | None) -> Finding | None:
    if new and new.size > 10 * 1024**3:
        return Severity.MEDIUM, "file is larger than 10 GiB"
    return None
```
