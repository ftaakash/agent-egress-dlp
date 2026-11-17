"""Policy file (`.egressguard.yml`): action per rule, passthrough hosts, allowlist."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

POLICY_FILENAME = ".egressguard.yml"

# Order matters: more specific rules first, so a git email is reported as git_email, not email.
RULES: tuple[str, ...] = (
    "private_key",
    "aws_access_key",
    "github_token",
    "anthropic_key",
    "openai_key",
    "stripe_key",
    "registered_secret",
    "git_email",
    "email",
    "os_username",
)
ACTIONS: tuple[str, ...] = ("block", "redact", "log")

DEFAULT_ACTIONS: dict[str, str] = {
    "private_key": "block",
    "aws_access_key": "block",
    "github_token": "block",
    "anthropic_key": "block",
    "openai_key": "block",
    "stripe_key": "block",
    "registered_secret": "block",
    "git_email": "redact",
    "email": "redact",
    "os_username": "redact",
}

# Model-provider API hosts: tunnelled without decryption, never scanned.
DEFAULT_PASSTHROUGH: tuple[str, ...] = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
)

_TOP_KEYS = {"rules", "passthrough_hosts", "allow", "secrets"}
_HOST_RE = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")


class PolicyError(ValueError):
    """The policy file is missing, malformed or names something unknown."""


def _host_pattern(host: str) -> str:
    """Regex (no anchors) for a host or a one-label wildcard like `*.example.com`."""
    if host.startswith("*."):
        return r"[^.:]+\." + re.escape(host[2:])
    return re.escape(host)


def _host_matches(pattern: str, host: str) -> bool:
    return re.fullmatch(_host_pattern(pattern), host.lower().rstrip(".")) is not None


@dataclass(frozen=True)
class AllowEntry:
    host: str
    rules: frozenset[str]


@dataclass(frozen=True)
class Policy:
    actions: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    passthrough_hosts: tuple[str, ...] = DEFAULT_PASSTHROUGH
    allow: tuple[AllowEntry, ...] = ()
    env_files: tuple[str, ...] = (".env",)
    scan_environment: bool = True
    source: str | None = field(default=None, compare=False)

    @classmethod
    def default(cls) -> Policy:
        return cls()

    def is_passthrough(self, host: str) -> bool:
        return any(_host_matches(p, host) for p in self.passthrough_hosts)

    def allowed(self, host: str, rule: str) -> bool:
        return any(rule in e.rules and _host_matches(e.host, host) for e in self.allow)

    def weakened(self) -> list[str]:
        """Ways this policy is looser than the defaults. Shown at start, because a policy file can come
        with a cloned repository the user did not write."""
        rank = {"log": 0, "redact": 1, "block": 2}
        out = [
            f"{rule}: {self.actions[rule]} (default {DEFAULT_ACTIONS[rule]})"
            for rule in RULES
            if rank[self.actions[rule]] < rank[DEFAULT_ACTIONS[rule]]
        ]
        out += [f"allow {e.host}: {', '.join(sorted(e.rules))}" for e in self.allow]
        out += [f"passthrough {h}" for h in self.passthrough_hosts if h not in DEFAULT_PASSTHROUGH]
        if not self.scan_environment:
            out.append("secrets.environment: false")
        return out

    def ignore_hosts_regex(self) -> str:
        """mitmproxy `ignore_hosts` pattern; it is matched against `host:port`."""
        alts = "|".join(_host_pattern(h) for h in self.passthrough_hosts)
        return rf"^(?:{alts}):\d+$"


def _str_list(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}: expected a list of strings")
    return list(value)


def _check_host(host: str, where: str) -> str:
    h = host.strip().lower()
    if not _HOST_RE.match(h):
        raise PolicyError(f"{where}: {host!r} is not a host name (use 'example.com' or '*.example.com')")
    return h


def parse_policy(data: Any, source: str | None = None) -> Policy:
    if data is None:
        return Policy(source=source)
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping of keys (rules, passthrough_hosts, allow, secrets)")
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise PolicyError(f"unknown key(s): {', '.join(sorted(map(str, unknown)))}")

    actions = dict(DEFAULT_ACTIONS)
    rules = data.get("rules") or {}
    if not isinstance(rules, dict):
        raise PolicyError("rules: expected a mapping of rule name to action")
    for rule, action in rules.items():
        if rule not in DEFAULT_ACTIONS:
            raise PolicyError(f"rules: unknown rule {rule!r} (known: {', '.join(RULES)})")
        if action not in ACTIONS:
            raise PolicyError(f"rules.{rule}: unknown action {action!r} (use block, redact or log)")
        actions[rule] = action

    passthrough = DEFAULT_PASSTHROUGH
    if "passthrough_hosts" in data:
        passthrough = tuple(
            _check_host(h, "passthrough_hosts")
            for h in _str_list(data["passthrough_hosts"], "passthrough_hosts")
        )

    allow: list[AllowEntry] = []
    raw_allow = data.get("allow") or []
    if not isinstance(raw_allow, list):
        raise PolicyError("allow: expected a list of {host, rules}")
    for i, entry in enumerate(raw_allow):
        if not isinstance(entry, dict) or "host" not in entry or not isinstance(entry["host"], str):
            raise PolicyError(f"allow[{i}]: each entry needs a 'host' and a 'rules' list")
        names = _str_list(entry.get("rules"), f"allow[{i}].rules")
        for r in names:
            if r not in DEFAULT_ACTIONS:
                raise PolicyError(f"allow[{i}].rules: unknown rule {r!r}")
        allow.append(AllowEntry(_check_host(entry["host"], f"allow[{i}].host"), frozenset(names)))

    env_files: tuple[str, ...] = (".env",)
    scan_env = True
    secrets = data.get("secrets") or {}
    if not isinstance(secrets, dict) or set(secrets) - {"env_files", "environment"}:
        raise PolicyError("secrets: expected a mapping with env_files (list) and environment (true/false)")
    if "env_files" in secrets:
        env_files = tuple(_str_list(secrets["env_files"], "secrets.env_files"))
    if "environment" in secrets:
        if not isinstance(secrets["environment"], bool):
            raise PolicyError("secrets.environment: expected true or false")
        scan_env = secrets["environment"]

    return Policy(actions, passthrough, tuple(allow), env_files, scan_env, source)


def load_policy(path: Path) -> Policy:
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    if not path.is_file():
        raise PolicyError(f"policy file not found: {path}")
    try:
        data = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except YAMLError as e:
        raise PolicyError(f"{path}: invalid YAML: {e}") from e
    try:
        return parse_policy(data, str(path))
    except PolicyError as e:
        raise PolicyError(f"{path}: {e}") from e


def find_policy(directory: Path) -> Path | None:
    p = directory / POLICY_FILENAME
    return p if p.is_file() else None
