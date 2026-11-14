# Platform notes

Tessera runs on Linux, macOS and Windows 10 or newer with Python 3.11+. The same configuration format and the same
CLI work everywhere. `tessera init` writes a starter config tuned for the current platform (override with
`--platform`).

## Linux

- **Permissions.** Reading `/etc/shadow`, `/root` or other users' home directories requires root:
  `sudo tessera check`. Keep the store and key in root-owned locations when running as root, for example
  `store = "/var/lib/tessera/tessera.db"` and `key_file = "/etc/tessera/seal.key"`.
- **Tracked metadata.** mode (including setuid, setgid and sticky bits), uid, gid, mtime, inode, link count and
  symlink targets.
- **Mounts.** `one_filesystem = true` keeps scans from wandering into `/proc`, network shares or bind mounts below a
  root.
- **Scheduling.** A systemd timer or cron entry works well:

```ini
# /etc/systemd/system/tessera.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/tessera check -c /etc/tessera/tessera.toml -q -f json -o /var/log/tessera/last.json

# /etc/systemd/system/tessera.timer
[Timer]
OnCalendar=hourly
Persistent=true
[Install]
WantedBy=timers.target
```

## macOS

- **Full Disk Access.** macOS privacy protection (TCC) hides some locations, even from root. Grant Full Disk Access
  to your terminal (System Settings → Privacy & Security → Full Disk Access) when monitoring protected folders.
  Unreadable entries are reported, never silently skipped.
- **Case.** APFS is case-insensitive by default, so `case_sensitive = "auto"` matches patterns case-insensitively.
- **File flags.** BSD file flags (`chflags`, such as `uchg` and `hidden`) are recorded in the `attributes` field.
- **Persistence.** The starter config watches `LaunchAgents` and `LaunchDaemons`, the most common persistence
  locations on macOS.
- **Scheduling.** Use a `launchd` plist with `StartInterval`.

## Windows 10 and 11

- **Installing.** Install Python from python.org or the Microsoft Store, then `py -m pip install .` in the clone.
  Run the tool as `tessera` or `py -m tessera`.
- **Paths.** Write paths with forward slashes in TOML: `"C:/Windows/System32/drivers/etc"`. Environment variables in
  `%VAR%` form are expanded: `"%APPDATA%/Microsoft/Windows/Start Menu/Programs/Startup"`.
- **Case.** NTFS is case-insensitive, so patterns match case-insensitively by default.
- **Administrator rights.** Many files under `C:\Windows` and `C:\ProgramData` need an elevated PowerShell. Files
  locked by other processes (such as registry hives or `pagefile.sys`) are reported as `unreadable`. Exclude them
  when that is expected.
- **Tracked metadata.** Windows has no POSIX owners, so `uid` and `gid` are not recorded. `mode` reflects the
  read-only flag. File attributes (hidden, system, read-only, archive, reparse point) are recorded in `attributes`,
  and gaining the hidden or system attribute raises severity.
- **Junctions and symlinks.** Directory junctions and symlinks are recorded but not followed unless
  `follow_symlinks = true`.
- **Colours.** ANSI colours are enabled through the console API on Windows 10+ (Windows Terminal, PowerShell,
  cmd). Set `NO_COLOR=1` to disable them. Box-drawing characters fall back to ASCII when the console encoding cannot
  display them.
- **Key protection.** POSIX permissions do not apply. Use `icacls`, see [security-model.md](security-model.md).
- **Scheduling.** Use Task Scheduler:

```powershell
$action  = New-ScheduledTaskAction -Execute "py" -Argument "-m tessera check -q -f json -o C:\ProgramData\tessera\last.json"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName "Tessera integrity check" -Action $action -Trigger $trigger -RunLevel Highest
```

## Moving baselines between machines

Baselines are tied to absolute paths, so compare a baseline only on the machine that produced it. To verify a
baseline elsewhere, `tessera export` it and run `tessera verify --manifest` on the other machine.
