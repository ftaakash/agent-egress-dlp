"""Values the proxy treats as the developer's: registered secrets and identity.

Read by the proxy process itself from its own environment and the `.env` files, so the values are never
written to disk by egressguard.
"""

from __future__ import annotations

import getpass
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path

from .rules import MIN_SECRET_LEN

_SECRET_NAME = re.compile(r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)(?:_|$)")
# Names that point at a secret rather than hold one (SSH_KEY_PATH, GPG_KEY_ID, TOKEN_FILE).
_NOT_A_SECRET = re.compile(r"_(?:PATH|FILE|DIR|SOCK|ID|NAME)$")
_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def _parse_value(raw: str) -> str:
    raw = raw.strip()
    if raw[:1] in ("'", '"'):
        end = raw.find(raw[0], 1)
        return raw[1:end] if end > 0 else raw[1:]
    return re.split(r"\s+#", raw, maxsplit=1)[0].strip()


def env_file_values(path: Path) -> list[str]:
    """Values from a dotenv file, in file order, skipping ones too short to match safely."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_LINE.match(line)
        if not m:
            continue
        value = _parse_value(m.group(2))
        if len(value) >= MIN_SECRET_LEN:
            out.append(value)
    return out


def environment_values(env: Mapping[str, str]) -> list[str]:
    """Values of environment variables whose names look like secrets (TOKEN, SECRET, API_KEY, ...)."""
    return [
        v
        for k, v in env.items()
        if not k.upper().startswith("EGRESSGUARD_")
        and _SECRET_NAME.search(k.upper())
        and not _NOT_A_SECRET.search(k.upper())
        and len(v) >= MIN_SECRET_LEN
    ]


def git_email(cwd: Path | None = None) -> str | None:
    try:
        p = subprocess.run(
            ["git", "config", "--get", "user.email"],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    email = p.stdout.strip()
    return email or None


def os_username() -> str | None:
    try:
        return getpass.getuser() or None
    except (OSError, KeyError):
        return None
