"""Shared fixtures: a throwaway CA, local fake HTTPS upstreams and a helper that starts the real proxy."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from egressguard.fakes import FakeUpstream, make_fake_pki
from egressguard.runner import ProxyProcess, start_proxy
from egressguard.session import SessionConfig

TOOLS = "tools.example.test"
OTHER = "other.example.test"
MODEL = "api.model.test"
HOSTS = (TOOLS, OTHER, MODEL)


@pytest.fixture(scope="session")
def pki(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("pki")
    make_fake_pki(d, HOSTS)
    return d


@pytest.fixture
def upstream(pki: Path) -> Iterator[FakeUpstream]:
    with FakeUpstream(pki, HOSTS) as up:
        yield up


@pytest.fixture
def eg_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "eghome"
    monkeypatch.setenv("EGRESSGUARD_HOME", str(home))
    return home


@dataclass
class Proxy:
    proc: ProxyProcess
    cfg: SessionConfig
    trust: Path  # proxy CA + fake upstream CA

    def events(self) -> list[dict[str, object]]:
        p = Path(self.cfg.log_path)
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]


StartProxy = Callable[..., Proxy]


@pytest.fixture
def proxy(tmp_path: Path, pki: Path, upstream: FakeUpstream, eg_home: Path) -> Iterator[StartProxy]:
    started: list[ProxyProcess] = []

    def _start(policy_text: str | None = None, env: dict[str, str] | None = None) -> Proxy:
        work = tmp_path / "work"
        work.mkdir(exist_ok=True)
        policy_path = None
        if policy_text is not None:
            policy_path = work / ".egressguard.yml"
            policy_path.write_text(policy_text, encoding="utf-8")
        cfg = SessionConfig.new(
            cwd=work,
            policy_path=policy_path,
            log_path=tmp_path / "egress.jsonl",
            resolve=upstream.resolve_map(),
            extra_ca=[pki / "upstream-ca.pem"],
            session_dir=tmp_path / "session",
        )
        proc = start_proxy(cfg, extra_env=env)
        started.append(proc)
        trust = tmp_path / "trust.pem"
        trust.write_text(proc.ca_cert.read_text() + (pki / "upstream-ca.pem").read_text(), encoding="utf-8")
        return Proxy(proc, cfg, trust)

    yield _start
    for p in started:
        p.stop()
    for p in started:
        assert not p.is_listening(), "proxy port still open after stop"


def send(
    url: str,
    *,
    proxy_port: int | None,
    trust: Path,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, str]:
    """One HTTPS request with Python urllib through the proxy; returns (status, body)."""
    status, _, body = send_full(url, proxy_port=proxy_port, trust=trust, data=data, headers=headers)
    return status, body


def send_full(
    url: str,
    *,
    proxy_port: int | None,
    trust: Path,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], str]:
    """Like `send`, but also returns the response headers."""
    ctx = ssl.create_default_context(cafile=str(trust))
    handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPSHandler(context=ctx)]
    if proxy_port is not None:
        p = f"http://127.0.0.1:{proxy_port}"
        handlers.append(urllib.request.ProxyHandler({"https": p, "http": p}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, dict(r.headers.items()), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        with e:
            return e.code, dict(e.headers.items()), e.read().decode("utf-8", "replace")
