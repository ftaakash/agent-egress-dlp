"""F4: hashed JSONL log and `egressguard report`."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from conftest import MODEL, TOOLS, StartProxy, send

from egressguard.cli import main
from egressguard.eventlog import EventLog
from egressguard.fakes import FakeUpstream

AWS = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "someone.else@example.org"


def test_acceptance_log_has_no_raw_values_and_report_summarises(
    proxy: StartProxy, upstream: FakeUpstream, pki: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    px = proxy(f"passthrough_hosts: [{MODEL}]\n")
    port = px.proc.port
    assert send(f"https://{TOOLS}/up", proxy_port=port, trust=px.trust, data=f"k={AWS}".encode())[0] == 403
    status, _ = send(
        f"https://{TOOLS}/q?mail={EMAIL}", proxy_port=port, trust=px.trust, headers={"X-From": EMAIL}
    )
    assert status == 200
    assert send(f"https://{MODEL}/v1", proxy_port=port, trust=pki / "upstream-ca.pem", data=b"hi")[0] == 200
    px.proc.stop()

    raw = Path(px.cfg.log_path).read_text(encoding="utf-8")
    assert AWS not in raw
    assert EMAIL not in raw
    assert "someone.else" not in raw
    assert "hmac:" in raw

    assert main(["report", "--log", px.cfg.log_path]) == 0
    out = capsys.readouterr().out
    assert re.search(rf"{re.escape(TOOLS)}\s+2\b", out), out  # two requests inspected
    assert re.search(r"aws_access_key\s+block\s+1\b", out), out
    assert re.search(r"email\s+redact\s+2\b", out), out  # once in the query, once in the header
    assert re.search(rf"{re.escape(MODEL)}\s+1\b", out), out  # passthrough connection


def test_hash_is_keyed_and_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib

    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path / "a"))
    a1 = EventLog(tmp_path / "l.jsonl", "s").hash_value("dev.user@example.com")
    a2 = EventLog(tmp_path / "l.jsonl", "s").hash_value("dev.user@example.com")
    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path / "b"))
    b = EventLog(tmp_path / "l.jsonl", "s").hash_value("dev.user@example.com")
    assert a1 == a2  # same install key, same value -> same hash (lets you count repeats)
    assert a1 != b  # different install key
    plain = hashlib.sha256(b"dev.user@example.com").hexdigest()[:16]
    assert plain not in a1


def test_report_empty_log(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["report", "--log", str(tmp_path / "none.jsonl")]) == 0
    assert "no events" in capsys.readouterr().out


def test_report_last_session_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = tmp_path / "l.jsonl"
    rows = [
        {"session": "s1", "event": "request", "host": "old.test", "outcome": "forwarded"},
        {"session": "s2", "event": "request", "host": "new.test", "outcome": "forwarded"},
        "this line is not json",
    ]
    log.write_text("\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows), encoding="utf-8")
    assert main(["report", "--log", str(log), "--last"]) == 0
    out = capsys.readouterr().out
    assert "new.test" in out
    assert "old.test" not in out
