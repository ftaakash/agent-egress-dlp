"""Local JSONL event log. Matched values are stored only as a keyed hash."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any


def egressguard_home() -> Path:
    env = os.environ.get("EGRESSGUARD_HOME")
    return Path(env) if env else Path.home() / ".egressguard"


def default_log_path() -> Path:
    return egressguard_home() / "egress.jsonl"


KEY_LEN = 32
KEY_WAIT = 2.0


def _hmac_key() -> bytes:
    """Per-install random key, so low-entropy values (emails, usernames) cannot be found by guessing."""
    home = egressguard_home()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "hmac.key"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process may have created the file and not written the key yet.
        deadline = time.monotonic() + KEY_WAIT
        while True:
            key = path.read_bytes()
            if len(key) == KEY_LEN:
                return key
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"{path} is not a {KEY_LEN}-byte key; delete it to make a new one"
                ) from None
            time.sleep(0.05)
    key = secrets.token_bytes(KEY_LEN)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


class EventLog:
    def __init__(self, path: Path, session: str) -> None:
        self.path = path
        self.session = session
        self._key = _hmac_key()
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def hash_value(self, value: str) -> str:
        return "hmac:" + hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def write(self, event: str, **fields: Any) -> None:
        rec = {"t": round(time.time(), 3), "session": self.session, "event": event, **fields}
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line)


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out
