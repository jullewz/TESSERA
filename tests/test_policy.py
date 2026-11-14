from __future__ import annotations

import pytest

from tessera.models import Severity
from tessera.policy import Policy, Rule


def test_last_matching_rule_wins() -> None:
    policy = Policy([
        Rule("/etc/**", "full", Severity.MEDIUM),
        Rule("/etc/*.log", "append"),
        Rule("/etc/secret", "full", Severity.CRITICAL),
    ])  # fmt: skip
    assert policy.resolve("/etc/hosts").profile == "full"
    assert policy.resolve("/etc/hosts").severity is Severity.MEDIUM
    assert policy.resolve("/etc/x.log").profile == "append"
    assert policy.resolve("/etc/x.log").rule_index == 1
    secret = policy.resolve("/etc/secret")
    assert secret.severity is Severity.CRITICAL and secret.label == "/etc/secret"


def test_defaults_when_nothing_matches() -> None:
    policy = Policy([Rule("/etc/**", "content")], default_profile="permissions",
                    default_severity=Severity.LOW)  # fmt: skip
    res = policy.resolve("/opt/app")
    assert res.rule is None
    assert res.profile == "permissions"
    assert res.severity is Severity.LOW
    assert not res.wants_hash


def test_ignore_and_custom_profiles() -> None:
    policy = Policy([Rule("**/*.tmp", "ignore"), Rule("/data/**", "hashonly")],
                    profiles={"hashonly": ["kind", "digest"]})  # fmt: skip
    assert policy.resolve("/x/a.tmp").ignored
    data = policy.resolve("/data/a")
    assert data.wants_hash and data.attributes == frozenset({"kind", "digest"})


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"rules": [Rule("/x", "nope")]}, "unknown profile"),
        ({"profiles": {"full": ["kind"]}}, "built in"),
        ({"profiles": {"mine": ["colour"]}}, "unknown attributes"),
        ({"default_profile": "zzz"}, "unknown default profile"),
    ],
)
def test_invalid_policies(kwargs: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Policy(**kwargs)  # type: ignore[arg-type]


def test_case_insensitive_policy() -> None:
    policy = Policy([Rule("C:/Windows/**", "content", Severity.HIGH)], case_sensitive=False)
    assert policy.resolve(r"c:\WINDOWS\explorer.exe").severity is Severity.HIGH


def test_digest_material_changes_with_rules() -> None:
    a = Policy([Rule("/a", "full")]).digest_material()
    b = Policy([Rule("/a", "content")]).digest_material()
    assert a != b
