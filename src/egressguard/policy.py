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
    # Keys the file actually set ("rules.email", "passthrough_hosts", "secrets.environment"), as opposed
    # to defaults filled in. A repository policy is merged on these only.
    explicit: frozenset[str] = field(default=frozenset(), compare=False)

    @classmethod
    def default(cls) -> Policy:
        return cls()

    def is_passthrough(self, host: str) -> bool:
        return any(_host_matches(p, host) for p in self.passthrough_hosts)

    def allowed(self, host: str, rule: str) -> bool:
        return any(rule in e.rules and _host_matches(e.host, host) for e in self.allow)

    def to_data(self) -> dict[str, Any]:
        """A mapping `parse_policy` accepts, so a merged policy can be handed to the proxy process."""
        return {
            "rules": dict(self.actions),
            "passthrough_hosts": list(self.passthrough_hosts),
            "allow": [{"host": e.host, "rules": sorted(e.rules)} for e in self.allow],
            "secrets": {"env_files": list(self.env_files), "environment": self.scan_environment},
        }

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

    explicit = {f"rules.{r}" for r in rules}
    explicit |= {k for k in ("passthrough_hosts",) if k in data}
    explicit |= {f"secrets.{k}" for k in secrets}
    return Policy(actions, passthrough, tuple(allow), env_files, scan_env, source, frozenset(explicit))


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


USER_CONFIG_FILENAME = "config.yml"
_RANK = {"log": 0, "redact": 1, "block": 2}


def user_config_path() -> Path:
    from .eventlog import egressguard_home

    return egressguard_home() / USER_CONFIG_FILENAME


def merge_repo_policy(base: Policy, repo: Policy, project_dir: Path) -> tuple[Policy, list[str]]:
    """Apply a repository's policy on top of a trusted one, keeping only what makes it stricter.

    A policy file can arrive with a cloned repository, so it must not be able to loosen protection.
    Returns the merged policy and a description of every setting that was ignored.
    """
    ignored: list[str] = []
    actions = dict(base.actions)
    for rule, action in repo.actions.items():
        if f"rules.{rule}" not in repo.explicit:
            continue
        if _RANK[action] > _RANK[actions[rule]]:
            actions[rule] = action
        elif _RANK[action] < _RANK[actions[rule]]:
            ignored.append(f"{rule}: {action} (keeps {actions[rule]})")

    ignored += [f"allow {e.host}: {', '.join(sorted(e.rules))}" for e in repo.allow]

    # Passthrough hosts are not inspected: the repository may remove hosts, never add them.
    passthrough = base.passthrough_hosts
    if "passthrough_hosts" in repo.explicit:
        passthrough = tuple(h for h in base.passthrough_hosts if h in repo.passthrough_hosts)
        ignored += [f"passthrough {h}" for h in repo.passthrough_hosts if h not in base.passthrough_hosts]

    # Extra .env files only add registered secrets, but only files inside the project are read.
    env_files = list(base.env_files)
    root = project_dir.resolve()
    for name in repo.env_files:
        p = Path(name)
        full = (p if p.is_absolute() else root / p).resolve()
        if not full.is_relative_to(root):
            ignored.append(f"secrets.env_files {name} (outside the project)")
        elif name not in env_files and str(full) not in env_files:
            env_files.append(str(full))

    scan_env = base.scan_environment
    if "secrets.environment" in repo.explicit and repo.scan_environment:
        scan_env = True
    if "secrets.environment" in repo.explicit and base.scan_environment and not repo.scan_environment:
        ignored.append("secrets.environment: false")

    merged = Policy(actions, passthrough, base.allow, tuple(env_files), scan_env, base.source)
    return merged, ignored


@dataclass(frozen=True)
class EffectivePolicy:
    policy: Policy
    sources: list[str]
    ignored: list[str] = field(default_factory=list)
    skipped_repo_file: Path | None = None


def effective_policy(cwd: Path, explicit: Path | None) -> EffectivePolicy:
    """The policy `egressguard run` uses.

    Trusted, may loosen: the file given with --policy; otherwise ~/.egressguard/config.yml; otherwise
    the built-in defaults. Not trusted, may only tighten: ./.egressguard.yml, unless --policy was given.
    """
    repo_file = find_policy(cwd)
    if explicit is not None:
        skipped = repo_file if repo_file and repo_file.resolve() != explicit.resolve() else None
        return EffectivePolicy(load_policy(explicit), [str(explicit)], skipped_repo_file=skipped)
    user = user_config_path()
    if user.is_file():
        base, sources = load_policy(user), [str(user)]
    else:
        base, sources = Policy.default(), ["built-in defaults"]
    if repo_file is None:
        return EffectivePolicy(base, sources)
    merged, ignored = merge_repo_policy(base, load_policy(repo_file), cwd)
    return EffectivePolicy(merged, [*sources, f"{repo_file} (may only tighten)"], ignored)
