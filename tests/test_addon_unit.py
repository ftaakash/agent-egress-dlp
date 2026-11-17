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


def _addon(tmp_path: Path, policy: Policy | None = None) -> EgressGuard:
    return EgressGuard(policy or Policy.default(), Scanner(), EventLog(tmp_path / "l.jsonl", "t"), resolve={})


def test_websocket_client_message_blocked_or_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mitmproxy.websocket import WebSocketMessage
    from wsproto.frame_protocol import Opcode

    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    addon = _addon(tmp_path)
    f = tflow.twebsocketflow()
    assert f.websocket is not None
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, b"key AKIAIOSFODNN7EXAMPLE"))
    addon.websocket_message(f)
    assert f.websocket.messages[-1].dropped
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, b"mail a@example.org"))
    addon.websocket_message(f)
    assert not f.websocket.messages[-1].dropped
    assert f.websocket.messages[-1].content == b"mail [REDACTED:email]"
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, False, b"server says a@example.org"))
    addon.websocket_message(f)
    assert f.websocket.messages[-1].content == b"server says a@example.org"  # only outbound is checked


def test_tcp_client_message_with_finding_kills_flow(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mitmproxy import tcp

    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    addon = _addon(tmp_path)
    f = tflow.ttcpflow()
    addon.tcp_message(f)  # the default messages are clean
    assert f.error is None
    f.messages.append(tcp.TCPMessage(True, b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))
    addon.tcp_message(f)
    assert f.error is not None  # killed: raw TCP cannot be redacted in place, so any finding blocks
    assert "tcp_blocked" in (tmp_path / "l.jsonl").read_text()


def test_tcp_to_passthrough_host_is_not_scanned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from mitmproxy import tcp

    from egressguard.policy import parse_policy

    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    addon = _addon(tmp_path, parse_policy({"passthrough_hosts": ["address"]}))
    f = tflow.ttcpflow()
    f.messages.append(tcp.TCPMessage(True, b"AKIAIOSFODNN7EXAMPLE"))
    addon.tcp_message(f)
    assert f.error is None


def test_host_is_the_connection_target_not_host_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from egressguard.policy import parse_policy

    monkeypatch.setenv("EGRESSGUARD_HOME", str(tmp_path))
    pol = parse_policy({"allow": [{"host": "trusted.test", "rules": ["email"]}], "rules": {"email": "block"}})
    addon = _addon(tmp_path, pol)
    f = tflow.tflow()
    f.server_conn.address = ("evil.test", 443)
    f.request.headers["Host"] = "trusted.test"
    f.request.headers["X-Who"] = "a@example.org"
    addon.request(f)
    assert f.response is not None and f.response.status_code == 403
