"""Content rules: a pure scanner over text. No mitmproxy import, so it is easy to test.

Rules are tried in priority order (see `policy.RULES`); on overlap the higher-priority rule wins.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from .policy import RULES

MIN_SECRET_LEN = 8
MIN_USERNAME_LEN = 4
# Account names that identify nobody; matching them would only produce noise.
GENERIC_USERNAMES = frozenset(
    {
        "root", "admin", "administrator", "user", "users", "runner", "runneradmin", "ubuntu",
        "vagrant", "guest", "default", "owner", "developer", "test", "system",
    }
)  # fmt: skip

_FORMATS: dict[str, re.Pattern[str]] = {
    "private_key": re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:.*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----)?",
        re.DOTALL,
    ),
    "aws_access_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    "github_token": re.compile(
        r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})(?![A-Za-z0-9_])"
    ),
    "anthropic_key": re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}"),
    "openai_key": re.compile(r"(?<![A-Za-z0-9])sk-(?!ant-)[A-Za-z0-9_\-]{20,}"),
    "stripe_key": re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    "email": re.compile(
        r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._+-]+(?:@|%40)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    ),
}


@dataclass(frozen=True)
class Finding:
    rule: str
    where: str
    start: int
    end: int
    value: str


def _literal_variants(value: str) -> set[str]:
    return {value, quote(value, safe=""), quote_plus(value, safe="")}


def _alternation(values: Iterable[str]) -> str:
    return "|".join(re.escape(v) for v in sorted(set(values), key=len, reverse=True))


class Scanner:
    def __init__(
        self,
        registered: Iterable[str] = (),
        git_email: str | None = None,
        os_username: str | None = None,
    ) -> None:
        self._patterns: list[tuple[str, re.Pattern[str]]] = []
        extra: dict[str, re.Pattern[str]] = {}
        values = {v for v in registered if len(v) >= MIN_SECRET_LEN}
        if values:
            variants: set[str] = set()
            for v in values:
                variants |= _literal_variants(v)
            extra["registered_secret"] = re.compile(_alternation(variants))
        if git_email and "@" in git_email:
            extra["git_email"] = re.compile(_alternation(_literal_variants(git_email)), re.IGNORECASE)
        if (
            os_username
            and len(os_username) >= MIN_USERNAME_LEN
            and os_username.lower() not in GENERIC_USERNAMES
        ):
            extra["os_username"] = re.compile(
                rf"(?<![A-Za-z0-9_]){re.escape(os_username)}(?![A-Za-z0-9_])", re.IGNORECASE
            )
        for rule in RULES:
            pat = _FORMATS.get(rule) or extra.get(rule)
            if pat is not None:
                self._patterns.append((rule, pat))

    def scan(self, text: str, where: str) -> list[Finding]:
        if not text:
            return []
        taken: list[Finding] = []
        for rule, pat in self._patterns:  # priority order
            for m in pat.finditer(text):
                if m.end() == m.start():
                    continue
                if any(m.start() < f.end and f.start < m.end() for f in taken):
                    continue
                taken.append(Finding(rule, where, m.start(), m.end(), m.group()))
        return sorted(taken, key=lambda f: f.start)

    def scan_request(self, url: str, headers: Sequence[tuple[str, str]], body: str) -> list[Finding]:
        found = self.scan(url, "url")
        for name, value in headers:
            found += self.scan(value, f"header:{name}")
        found += self.scan(body, "body")
        return found


def redact(text: str, findings: Iterable[Finding]) -> str:
    """Replace each finding's span with `[REDACTED:<rule>]`. Findings must come from scanning `text`."""
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        text = text[: f.start] + f"[REDACTED:{f.rule}]" + text[f.end :]
    return text
