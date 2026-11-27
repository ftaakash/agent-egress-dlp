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


def test_empty_hmac_key_file_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from egressguard import eventlog

    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    monkeypatch.setattr(eventlog, "KEY_WAIT", 0.2)
    (tmp_path / "hmac.key").write_bytes(b"")  # another process created it and has not written yet
    with pytest.raises(RuntimeError, match="hmac.key"):
        EventLog(tmp_path / "l.jsonl", "s")


def test_notice_lines_name_rule_and_place_never_value() -> None:
    from egressguard.runner import notice_line

    ev = {
        "event": "finding",
        "rule": "email",
        "action": "redact",
        "where": "body",
        "host": "x.test",
        "value": "hmac:ab",
    }
    assert notice_line(ev) == "egressguard: redacted email in body (x.test)"
    assert notice_line({**ev, "action": "block"}) == "egressguard: blocked email in body (x.test)"
    for quiet in ("log", "allow", "dropped"):
        assert notice_line({**ev, "action": quiet}) is None
    assert notice_line({"event": "request", "host": "x.test"}) is None
    assert "x.test" in (notice_line({"event": "tcp_blocked", "host": "x.test"}) or "")


def test_live_notices_handle_partial_lines_and_other_sessions(tmp_path: Path) -> None:
    import io

    from egressguard.runner import LiveNotices

    log = tmp_path / "l.jsonl"
    log.write_text(
        json.dumps({"session": "old", "event": "finding", "action": "block"}) + "\n", encoding="utf-8"
    )
    out = io.StringIO()
    w = LiveNotices(log, "s1", out)  # starts after what is already in the log
    line = json.dumps({"session": "s1", "event": "finding", "rule": "aws_access_key", "action": "block",
                       "where": "body", "host": "t.test"})  # fmt: skip
    other = json.dumps({"session": "s2", "event": "finding", "rule": "email", "action": "redact",
                        "where": "url", "host": "t.test"})  # fmt: skip
    with log.open("a", encoding="utf-8") as f:
        f.write(other + "\n" + line[:20])  # the second line is only half written
    w._poll()
    assert out.getvalue() == ""
    with log.open("a", encoding="utf-8") as f:
        f.write(line[20:] + "\n")
    w.stop()
    assert out.getvalue() == "egressguard: blocked aws_access_key in body (t.test)\n"


# ---- v0.4: session digest ------------------------------------------------------------------------------


def _digest_session(proxy: StartProxy, pki: Path) -> str:
    """One proxy session: a clean request, an email in a header, the AWS key in a body, one passthrough."""
    px = proxy(f"passthrough_hosts: [{MODEL}]\n")
    port = px.proc.port
    assert send(f"https://{TOOLS}/ok", proxy_port=port, trust=px.trust)[0] == 200
    assert (
        send(f"https://{TOOLS}/fetch", proxy_port=port, trust=px.trust, headers={"X-From": EMAIL})[0] == 200
    )
    assert send(f"https://{TOOLS}/up", proxy_port=port, trust=px.trust, data=f"k={AWS}".encode())[0] == 403
    assert send(f"https://{MODEL}/v1", proxy_port=port, trust=pki / "upstream-ca.pem", data=b"hi")[0] == 200
    px.proc.stop()
    return px.cfg.log_path


def test_acceptance_session_digest_markdown(
    proxy: StartProxy, upstream: FakeUpstream, pki: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = _digest_session(proxy, pki)
    assert main(["report", "--log", log, "--last", "--format", "markdown"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# egressguard session "), out
    assert "## What left the machine" in out
    assert re.search(rf"^\| {re.escape(TOOLS)} \| 1 \| 1 \| 1 \| ", out, re.M), out
    assert "/ok" in out and "/fetch" in out and "/up" in out
    assert "## Blocked and redacted, by rule" in out
    assert re.search(rf"^\| aws_access_key \| block \| body \| {re.escape(TOOLS)} \| 1 \|$", out, re.M), out
    assert re.search(rf"^\| email \| redact \| header:X-From \| {re.escape(TOOLS)} \| 1 \|$", out, re.M), out
    assert re.search(rf"^\| {re.escape(MODEL)} \| 1 \|$", out, re.M), out
    assert AWS not in out and EMAIL not in out and "someone.else" not in out


def test_acceptance_session_digest_text(
    proxy: StartProxy, upstream: FakeUpstream, pki: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    log = _digest_session(proxy, pki)
    assert main(["report", "--log", log, "--last"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("egressguard session "), out
    assert re.search(rf"{re.escape(TOOLS)}\s+1\s+1\s+1\b", out), out
    assert re.search(rf"aws_access_key\s+block\s+body\s+{re.escape(TOOLS)}\s+1\b", out), out
    assert re.search(rf"email\s+redact\s+header:X-From\s+{re.escape(TOOLS)}\s+1\b", out), out
    assert re.search(rf"{re.escape(MODEL)}\s+1\b", out), out
    assert AWS not in out and EMAIL not in out
    assert "no matched values" in out


def _two_session_log(tmp_path: Path) -> Path:
    rows = [
        {"t": 1000.0, "session": "aaaa1111", "event": "proxy_start", "port": 1},
        {"t": 1001.0, "session": "aaaa1111", "event": "request", "host": "old.test", "outcome": "blocked"},
        {"t": 2000.0, "session": "bbbb2222", "event": "proxy_start", "port": 2},
        {"t": 2001.0, "session": "bbbb2222", "event": "request", "host": "new.test", "outcome": "redacted"},
        {"t": 2002.0, "session": "bbbb2222", "event": "request", "host": "new.test", "outcome": "forwarded"},
        {"t": 2003.0, "session": "bbbb2222", "event": "passthrough", "host": "api.model.test", "port": 443},
    ]
    log = tmp_path / "l.jsonl"
    log.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return log


def test_report_lists_sessions_newest_first(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = _two_session_log(tmp_path)
    assert main(["report", "--log", str(log)]) == 0
    out = capsys.readouterr().out
    assert "Sessions (newest first)" in out
    new, old = out.index("bbbb2222"), out.index("aaaa1111")
    assert new < old
    assert re.search(r"bbbb2222\s+\S+ \S+\s+\S+\s+2\s+0\s+1\s+1\b", out), (
        out
    )  # inspected, blocked, redacted, pt
    assert "sessions: 2" in out  # the totals are still printed


def test_report_session_by_id_and_unknown_id(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = _two_session_log(tmp_path)
    assert main(["report", "--log", str(log), "--session", "aaaa1111"]) == 0
    out = capsys.readouterr().out
    assert "old.test" in out and "new.test" not in out
    assert main(["report", "--log", str(log), "--session", "nope"]) == 1
    assert "no session nope" in capsys.readouterr().out


def test_markdown_escapes_table_cells(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rows = [
        {"t": 1.0, "session": "s", "event": "request", "host": "h.test", "method": "GET",
         "path": "/a|b", "outcome": "forwarded"},
    ]  # fmt: skip
    log = tmp_path / "l.jsonl"
    log.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    assert main(["report", "--log", str(log), "--last", "--format", "markdown"]) == 0
    assert r"/a\|b" in capsys.readouterr().out
