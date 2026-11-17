"""F3 unit edges: the addon fails closed when inspection raises."""

from __future__ import annotations

from pathlib import Path

import pytest
from mitmproxy.test import tflow

from egressguard.addon import EgressGuard
from egressguard.eventlog import EventLog
from egressguard.policy import Policy
from egressguard.rules import Scanner


class Boom(Scanner):
    def scan_request(self, *a: object, **k: object) -> list:  # type: ignore[override,type-arg]
        raise RuntimeError("scanner exploded")


def test_addon_error_blocks_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    log = EventLog(tmp_path / "log.jsonl", session="t")
    addon = EgressGuard(Policy.default(), Boom(), log, resolve={})
    f = tflow.tflow()
    addon.request(f)
    assert f.response is not None
    assert f.response.status_code == 403
    assert b"internal error" in (f.response.content or b"")
    events = (tmp_path / "log.jsonl").read_text()
    assert "addon_error" in events
    assert "scanner exploded" not in events  # exception text could carry request data


def test_addon_redacts_header_in_unit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    log = EventLog(tmp_path / "log.jsonl", session="t")
    addon = EgressGuard(Policy.default(), Scanner(), log, resolve={})
    f = tflow.tflow()
    f.request.headers["X-Who"] = "a@example.org"
    f.request.headers.add("X-Who", "b@example.org")
    addon.request(f)
    assert f.response is None
    assert f.request.headers.get_all("X-Who") == ["[REDACTED:email]", "[REDACTED:email]"]
