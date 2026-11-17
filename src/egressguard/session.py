"""Session configuration handed from `egressguard run` to the proxy process (no secrets in it)."""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class SessionConfig:
    session_id: str
    session_dir: str
    cwd: str
    log_path: str
    policy_path: str | None = None
    resolve: dict[str, tuple[str, int]] = field(default_factory=dict)
    extra_ca: list[str] = field(default_factory=list)

    @classmethod
    def new(
        cls,
        *,
        cwd: Path,
        log_path: Path,
        session_dir: Path,
        policy_path: Path | None = None,
        resolve: dict[str, tuple[str, int]] | None = None,
        extra_ca: list[Path] | None = None,
    ) -> SessionConfig:
        return cls(
            session_id=secrets.token_hex(4),
            session_dir=str(session_dir),
            cwd=str(cwd),
            log_path=str(log_path),
            policy_path=str(policy_path) if policy_path else None,
            resolve=dict(resolve or {}),
            extra_ca=[str(p) for p in extra_ca or []],
        )

    @property
    def ready_file(self) -> Path:
        return Path(self.session_dir) / "ready.json"

    @property
    def config_file(self) -> Path:
        return Path(self.session_dir) / "session.json"

    def save(self) -> Path:
        Path(self.session_dir).mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        return self.config_file

    @classmethod
    def load(cls, path: Path) -> SessionConfig:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["resolve"] = {k: (str(v[0]), int(v[1])) for k, v in data.get("resolve", {}).items()}
        return cls(**data)
