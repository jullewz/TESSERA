"""Configuration loading and validation (TOML).

Lookup order for the configuration file:

1. ``--config PATH`` on the command line
2. the ``TESSERA_CONFIG`` environment variable
3. ``./tessera.toml`` in the current directory
4. the per-user config directory (see :func:`tessera.osinfo.config_dir`)
"""

from __future__ import annotations

import difflib
import hashlib
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tessera.errors import ConfigError
from tessera.hashing import validate_algorithm
from tessera.models import Severity
from tessera.osinfo import PlatformName, config_dir, current_platform, data_dir, default_case_sensitive
from tessera.policy import Policy, Rule
from tessera.reporters import FORMATS
from tessera.scanner import ScanRoot, ScanSettings
from tessera.util import canonical_json, expand_path, parse_size

CONFIG_FILENAME = "tessera.toml"


@dataclass(slots=True)
class HookConfig:
    name: str
    command: list[str] | None = None
    url: str | None = None
    min_severity: Severity = Severity.HIGH
    timeout: float = 15.0
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ReportConfig:
    format: str = "terminal"
    min_severity: Severity = Severity.INFO
    fail_on: Severity = Severity.LOW


@dataclass(slots=True)
class Config:
    store: Path
    key_file: Path
    scan: ScanSettings
    roots: list[ScanRoot]
    policy: Policy
    hooks: list[HookConfig]
    report: ReportConfig
    source: Path | None = None

    def digest(self) -> str:
        """Fingerprint of everything that affects what a scan records."""
        material = {
            "roots": [[r.path, sorted(r.exclude)] for r in self.roots],
            "algorithm": self.scan.algorithm,
            "follow_symlinks": self.scan.follow_symlinks,
            "one_filesystem": self.scan.one_filesystem,
            "max_file_size": self.scan.max_file_size,
            "policy": self.policy.digest_material(),
        }
        return hashlib.sha256(canonical_json(material)).hexdigest()[:16]


# ---------------------------------------------------------------- validation
_ALLOWED: dict[str, set[str]] = {
    "": {"general", "watch", "rule", "profiles", "hook", "report"},
    "general": {
        "store",
        "key_file",
        "algorithm",
        "workers",
        "max_file_size",
        "follow_symlinks",
        "one_filesystem",
        "case_sensitive",
        "chunk_size",
        "default_profile",
        "default_severity",
    },
    "watch": {"path", "exclude"},
    "rule": {"pattern", "profile", "severity"},
    "hook": {"name", "command", "url", "min_severity", "timeout", "headers"},
    "report": {"format", "min_severity", "fail_on"},
}


def _check_keys(table: dict[str, Any], section: str, where: str) -> None:
    allowed = _ALLOWED[section]
    for key in table:
        if key not in allowed:
            close = difflib.get_close_matches(key, allowed, n=1)
            hint = f"did you mean {close[0]!r}?" if close else f"allowed keys: {', '.join(sorted(allowed))}"
            raise ConfigError(f"unknown key {key!r} in {where}", hint=hint)


def _expect(value: Any, kind: type | tuple[type, ...], where: str) -> Any:
    if isinstance(value, bool) and kind in (int, float, (int, float)):
        raise ConfigError(f"{where} must be a number, not a boolean")
    if not isinstance(value, kind):
        names = kind.__name__ if isinstance(kind, type) else " or ".join(k.__name__ for k in kind)
        raise ConfigError(f"{where} must be of type {names}, got {type(value).__name__}")
    return value


def _str_list(value: Any, where: str) -> list[str]:
    _expect(value, list, where)
    for i, item in enumerate(value):
        _expect(item, str, f"{where}[{i}]")
    return list(value)


def _severity(value: Any, where: str) -> Severity:
    _expect(value, str, where)
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from None


def parse_config(data: dict[str, Any], *, source: Path | None = None,
                 platform: PlatformName | None = None) -> Config:  # fmt: skip
    """Validate a decoded TOML document and build a :class:`Config`."""
    plat = platform or current_platform()
    _check_keys(data, "", "the top level")

    general = _expect(data.get("general", {}), dict, "[general]")
    _check_keys(general, "general", "[general]")

    try:
        algorithm = validate_algorithm(_expect(general.get("algorithm", "sha256"), str, "general.algorithm"))
        max_size = parse_size(general.get("max_file_size", "512MiB"))
        chunk = parse_size(general.get("chunk_size", "1MiB"))
    except ValueError as exc:
        raise ConfigError(f"[general]: {exc}") from None
    if chunk < 4096:
        raise ConfigError("general.chunk_size must be at least 4KiB")

    workers = _expect(general.get("workers", min(8, os.cpu_count() or 2)), int, "general.workers")
    if not 1 <= workers <= 64:
        raise ConfigError("general.workers must be between 1 and 64")

    case_value = general.get("case_sensitive", "auto")
    if case_value == "auto":
        case_sensitive = default_case_sensitive(plat)
    else:
        case_sensitive = _expect(case_value, bool, "general.case_sensitive")

    scan = ScanSettings(
        algorithm=algorithm,
        workers=workers,
        max_file_size=max_size,
        follow_symlinks=_expect(general.get("follow_symlinks", False), bool, "general.follow_symlinks"),
        one_filesystem=_expect(general.get("one_filesystem", True), bool, "general.one_filesystem"),
        chunk_size=chunk,
        case_sensitive=case_sensitive,
    )

    store = Path(expand_path(_expect(general.get("store", str(data_dir(plat) / "tessera.db")),
                                     str, "general.store")))  # fmt: skip
    key_file = Path(expand_path(_expect(general.get("key_file", str(config_dir(plat) / "seal.key")),
                                        str, "general.key_file")))  # fmt: skip

    # watches
    watches_raw = _expect(data.get("watch", []), list, "[[watch]]")
    if not watches_raw:
        raise ConfigError("no [[watch]] entries configured",
                          hint="add at least one [[watch]] table with a 'path'")  # fmt: skip
    roots: list[ScanRoot] = []
    for i, entry in enumerate(watches_raw):
        where = f"[[watch]] #{i + 1}"
        _expect(entry, dict, where)
        _check_keys(entry, "watch", where)
        if "path" not in entry:
            raise ConfigError(f"{where} is missing 'path'")
        path = expand_path(_expect(entry["path"], str, f"{where}.path"))
        roots.append(ScanRoot(path, _str_list(entry.get("exclude", []), f"{where}.exclude")))

    # profiles
    profiles_raw = _expect(data.get("profiles", {}), dict, "[profiles]")
    profiles: dict[str, list[str]] = {}
    for name, body in profiles_raw.items():
        where = f"[profiles.{name}]"
        _expect(body, dict, where)
        extra = set(body) - {"attributes"}
        if extra:
            raise ConfigError(f"unknown key {sorted(extra)[0]!r} in {where}", hint="only 'attributes' is allowed")
        profiles[name] = _str_list(body.get("attributes", []), f"{where}.attributes")

    # rules
    rules: list[Rule] = []
    for i, entry in enumerate(_expect(data.get("rule", []), list, "[[rule]]")):
        where = f"[[rule]] #{i + 1}"
        _expect(entry, dict, where)
        _check_keys(entry, "rule", where)
        if "pattern" not in entry or "profile" not in entry:
            raise ConfigError(f"{where} needs both 'pattern' and 'profile'")
        severity = _severity(entry["severity"], f"{where}.severity") if "severity" in entry else None
        rules.append(Rule(_expect(entry["pattern"], str, f"{where}.pattern"),
                          _expect(entry["profile"], str, f"{where}.profile"), severity))  # fmt: skip

    try:
        policy = Policy(
            rules,
            profiles=profiles,
            default_profile=_expect(general.get("default_profile", "full"), str, "general.default_profile"),
            default_severity=_severity(general.get("default_severity", "medium"), "general.default_severity"),
            case_sensitive=case_sensitive,
        )
    except ValueError as exc:
        raise ConfigError(str(exc)) from None

    # hooks
    hooks: list[HookConfig] = []
    for i, entry in enumerate(_expect(data.get("hook", []), list, "[[hook]]")):
        where = f"[[hook]] #{i + 1}"
        _expect(entry, dict, where)
        _check_keys(entry, "hook", where)
        command = _str_list(entry["command"], f"{where}.command") if "command" in entry else None
        url = _expect(entry["url"], str, f"{where}.url") if "url" in entry else None
        if (command is None) == (url is None):
            raise ConfigError(f"{where} needs exactly one of 'command' or 'url'")
        if command is not None and not command:
            raise ConfigError(f"{where}.command must not be empty")
        if url is not None and not url.startswith(("https://", "http://")):
            raise ConfigError(f"{where}.url must start with https:// or http://")
        headers = _expect(entry.get("headers", {}), dict, f"{where}.headers")
        for key, value in headers.items():
            _expect(value, str, f"{where}.headers.{key}")
        timeout = float(_expect(entry.get("timeout", 15), (int, float), f"{where}.timeout"))
        if not 0 < timeout <= 300:
            raise ConfigError(f"{where}.timeout must be between 0 and 300 seconds")
        hooks.append(HookConfig(
            name=_expect(entry.get("name", f"hook-{i + 1}"), str, f"{where}.name"),
            command=command,
            url=url,
            min_severity=_severity(entry.get("min_severity", "high"), f"{where}.min_severity"),
            timeout=timeout,
            headers={str(k): os.path.expandvars(v) for k, v in headers.items()},
        ))  # fmt: skip

    report_raw = _expect(data.get("report", {}), dict, "[report]")
    _check_keys(report_raw, "report", "[report]")
    fmt = _expect(report_raw.get("format", "terminal"), str, "report.format")
    if fmt not in FORMATS:
        raise ConfigError(f"report.format {fmt!r} is not supported", hint=f"use one of: {', '.join(FORMATS)}")
    report = ReportConfig(
        format=fmt,
        min_severity=_severity(report_raw.get("min_severity", "info"), "report.min_severity"),
        fail_on=_severity(report_raw.get("fail_on", "low"), "report.fail_on"),
    )

    return Config(store=store, key_file=key_file, scan=scan, roots=roots, policy=policy,
                  hooks=hooks, report=report, source=source)  # fmt: skip


def find_config(explicit: str | None = None) -> Path:
    if explicit:
        return Path(expand_path(explicit))
    env = os.environ.get("TESSERA_CONFIG")
    if env:
        return Path(expand_path(env))
    local = Path.cwd() / CONFIG_FILENAME
    if local.is_file():
        return local
    return config_dir() / CONFIG_FILENAME


def load_config(explicit: str | None = None) -> Config:
    path = find_config(explicit)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ConfigError(f"configuration file not found: {path}",
                          hint="create one with `tessera init`") from None  # fmt: skip
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from None
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{path} is not valid UTF-8") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from None
    return parse_config(data, source=path)
