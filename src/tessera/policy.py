"""Policy engine: which attributes to track, and how serious changes are.

Rules are evaluated in order and the **last** matching rule wins, the same
way ``.gitignore`` works. Paths not matched by any rule use the default
profile and severity.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from tessera.matcher import compile_glob
from tessera.models import ALL_ATTRIBUTES, Severity
from tessera.util import match_path

# Built-in profiles. "append" is special-cased by the diff engine: the file
# may grow, but shrinking or rewriting it is a change.
BUILTIN_PROFILES: dict[str, frozenset[str]] = {
    "full": frozenset({"kind", "size", "mode", "uid", "gid", "mtime_ns", "digest", "link_target", "attributes"}),
    "paranoid": frozenset(ALL_ATTRIBUTES),
    "content": frozenset({"kind", "size", "digest", "link_target"}),
    "permissions": frozenset({"kind", "mode", "uid", "gid", "attributes"}),
    "append": frozenset({"kind", "mode", "uid", "gid", "attributes"}),
    "existence": frozenset({"kind"}),
    "ignore": frozenset(),
}

HASHING_ATTRIBUTE = "digest"


@dataclass(frozen=True, slots=True)
class Rule:
    pattern: str
    profile: str
    severity: Severity | None = None

    def describe(self) -> str:
        sev = f", severity={self.severity.label}" if self.severity is not None else ""
        return f"{self.pattern} -> {self.profile}{sev}"


@dataclass(frozen=True, slots=True)
class Resolution:
    """The outcome of evaluating the policy for one path."""

    profile: str
    attributes: frozenset[str]
    severity: Severity
    rule: Rule | None
    rule_index: int | None

    @property
    def ignored(self) -> bool:
        return self.profile == "ignore"

    @property
    def wants_hash(self) -> bool:
        return HASHING_ATTRIBUTE in self.attributes

    @property
    def label(self) -> str | None:
        return self.rule.pattern if self.rule else None


class Policy:
    def __init__(
        self,
        rules: Iterable[Rule] = (),
        *,
        profiles: Mapping[str, Iterable[str]] | None = None,
        default_profile: str = "full",
        default_severity: Severity = Severity.MEDIUM,
        case_sensitive: bool = True,
    ) -> None:
        self.profiles: dict[str, frozenset[str]] = dict(BUILTIN_PROFILES)
        for name, attrs in (profiles or {}).items():
            if name in BUILTIN_PROFILES:
                raise ValueError(f"profile {name!r} is built in and cannot be redefined")
            attr_set = frozenset(attrs)
            unknown = attr_set - set(ALL_ATTRIBUTES)
            if unknown:
                raise ValueError(f"profile {name!r} has unknown attributes: {', '.join(sorted(unknown))}")
            self.profiles[name] = attr_set
        self.rules = list(rules)
        for rule in self.rules:
            if rule.profile not in self.profiles:
                raise ValueError(f"rule {rule.pattern!r} uses unknown profile {rule.profile!r}")
        if default_profile not in self.profiles:
            raise ValueError(f"unknown default profile {default_profile!r}")
        self.default_profile = default_profile
        self.default_severity = default_severity
        self.case_sensitive = case_sensitive
        self._compiled = [compile_glob(r.pattern, case_sensitive) for r in self.rules]
        self._cache: dict[str, Resolution] = {}

    def resolve(self, path: str) -> Resolution:
        cached = self._cache.get(path)
        if cached is not None:
            return cached
        target = match_path(path)
        index: int | None = None
        for i in range(len(self._compiled) - 1, -1, -1):
            if self._compiled[i].fullmatch(target):
                index = i
                break
        if index is None:
            result = Resolution(
                self.default_profile,
                self.profiles[self.default_profile],
                self.default_severity,
                None,
                None,
            )
        else:
            rule = self.rules[index]
            result = Resolution(
                rule.profile,
                self.profiles[rule.profile],
                rule.severity if rule.severity is not None else self.default_severity,
                rule,
                index,
            )
        if len(self._cache) < 200_000:
            self._cache[path] = result
        return result

    def digest_material(self) -> dict[str, object]:
        """Data identifying this policy, used to detect policy drift."""
        return {
            "rules": [[r.pattern, r.profile, r.severity.label if r.severity else None] for r in self.rules],
            "profiles": {k: sorted(v) for k, v in sorted(self.profiles.items())},
            "default_profile": self.default_profile,
            "default_severity": self.default_severity.label,
            "case_sensitive": self.case_sensitive,
        }
