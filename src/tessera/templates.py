"""Starter configurations written by ``tessera init``, one per platform."""

from __future__ import annotations

from tessera.osinfo import PlatformName, config_dir, data_dir

_COMMON_FOOTER = """
[report]
format = "terminal"      # terminal | json | markdown | html | sarif
min_severity = "info"    # hide changes below this level
fail_on = "low"          # exit code 1 when a change at or above this level exists

# Run a command when a check finds serious changes. The JSON report is
# written to the command's standard input. No shell is involved.
# [[hook]]
# name = "log-to-file"
# command = ["python3", "examples/hooks/notify.py"]
# min_severity = "high"
# timeout = 15

# Or POST the JSON report to a webhook you control.
# [[hook]]
# name = "webhook"
# url = "https://hooks.example.internal/tessera"
# headers = { Authorization = "Bearer ${TESSERA_WEBHOOK_TOKEN}" }
# min_severity = "critical"
"""

_LINUX = """
[[watch]]
path = "/etc"
exclude = ["/etc/mtab", "**/*.swp", "/etc/ld.so.cache"]

[[watch]]
path = "/usr/bin"

[[watch]]
path = "/usr/sbin"

[[watch]]
path = "/usr/local/bin"

[[watch]]
path = "/root/.ssh"

# Rules: the LAST matching rule wins.
[[rule]]
pattern = "/etc/**"
profile = "full"
severity = "medium"

[[rule]]
pattern = "/usr/**"
profile = "full"
severity = "high"

[[rule]]
pattern = "/etc/{passwd,shadow}"
profile = "full"
severity = "critical"

[[rule]]
pattern = "/etc/sudoers*"
profile = "full"
severity = "critical"

[[rule]]
pattern = "**/.ssh/**"
profile = "full"
severity = "critical"

[[rule]]
pattern = "/etc/resolv.conf"
profile = "permissions"
severity = "low"

[[rule]]
pattern = "**/*.log"
profile = "append"
"""

_MACOS = """
[[watch]]
path = "/etc"
exclude = ["**/*.swp"]

[[watch]]
path = "/usr/local/bin"

[[watch]]
path = "/Library/LaunchDaemons"

[[watch]]
path = "/Library/LaunchAgents"

[[watch]]
path = "~/Library/LaunchAgents"

[[watch]]
path = "~/.ssh"

# Rules: the LAST matching rule wins.
[[rule]]
pattern = "**/Launch{Agents,Daemons}/**"
profile = "full"
severity = "high"

[[rule]]
pattern = "/etc/sudoers*"
profile = "full"
severity = "critical"

[[rule]]
pattern = "**/.ssh/**"
profile = "full"
severity = "critical"

[[rule]]
pattern = "**/.DS_Store"
profile = "ignore"
"""

_WINDOWS = """
# Paths use forward slashes. Environment variables like %USERPROFILE% and
# ~ are expanded. Matching is case-insensitive on Windows.

[[watch]]
path = "C:/Windows/System32/drivers/etc"

[[watch]]
path = "C:/Windows/System32/Tasks"

[[watch]]
path = "C:/ProgramData/Microsoft/Windows/Start Menu/Programs/Startup"

[[watch]]
path = "%APPDATA%/Microsoft/Windows/Start Menu/Programs/Startup"

[[watch]]
path = "~/.ssh"

# Rules: the LAST matching rule wins.
[[rule]]
pattern = "**/Start Menu/Programs/Startup/**"
profile = "full"
severity = "high"

[[rule]]
pattern = "C:/Windows/System32/Tasks/**"
profile = "content"
severity = "high"

[[rule]]
pattern = "**/drivers/etc/hosts"
profile = "content"
severity = "critical"

[[rule]]
pattern = "**/.ssh/**"
profile = "content"
severity = "critical"

[[rule]]
pattern = "**/desktop.ini"
profile = "ignore"
"""


def starter_config(platform: PlatformName) -> str:
    """Return a commented starter ``tessera.toml`` for ``platform``."""
    store = (data_dir(platform) / "tessera.db").as_posix()
    key = (config_dir(platform) / "seal.key").as_posix()
    body = {"linux": _LINUX, "macos": _MACOS, "windows": _WINDOWS}[platform]
    header = f"""# Tessera configuration ({platform})
# Reference: https://github.com/jullewz/tessera/blob/main/docs/configuration.md

[general]
store = '{store}'
key_file = '{key}'
algorithm = "sha256"          # sha256 | sha512 | blake2b | sha3_256
workers = 4                   # parallel hashing threads
max_file_size = "512MiB"      # larger files are tracked by metadata only
follow_symlinks = false
one_filesystem = true         # do not cross into other mounts or volumes
case_sensitive = "auto"       # auto: false on Windows and macOS, true on Linux
default_profile = "full"
default_severity = "medium"
"""
    return header + body + _COMMON_FOOTER
