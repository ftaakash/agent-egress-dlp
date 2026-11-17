"""F3: block / redact / log actions in the proxy, allowlist, fail closed."""

from __future__ import annotations

import gzip

from conftest import MODEL, OTHER, TOOLS, StartProxy, send

from egressguard.fakes import FakeUpstream

AWS = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "dev.user@example.com"


def test_acceptance_block(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy()
    status, body = send(
        f"https://{TOOLS}/upload",
        proxy_port=px.proc.port,
        trust=px.trust,
        data=f"AWS_ACCESS_KEY_ID={AWS}".encode(),
    )
    assert status == 403
    assert "egressguard: blocked" in body
    assert "aws_access_key" in body
    assert AWS not in body
    assert upstream.requests_to(TOOLS) == []
    assert upstream.connections[TOOLS] == 0  # lazy connection strategy: not even a TLS handshake


def test_acceptance_redact(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy()
    status, _ = send(
        f"https://{TOOLS}/fetch?q=docs",
        proxy_port=px.proc.port,
        trust=px.trust,
        headers={"User-Agent": f"agent/1.0 ({EMAIL})"},
    )
    assert status == 200
    (got,) = upstream.requests_to(TOOLS)
    assert got["headers"]["User-Agent"] in (
        "agent/1.0 ([REDACTED:email])",
        "agent/1.0 ([REDACTED:git_email])",
    )


def test_acceptance_log_action_passes_value(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy("rules:\n  email: log\n  git_email: log\n")
    status, _ = send(
        f"https://{TOOLS}/comment", proxy_port=px.proc.port, trust=px.trust, data=f"from {EMAIL}".encode()
    )
    assert status == 200
    (got,) = upstream.requests_to(TOOLS)
    assert got["body"] == f"from {EMAIL}"
    assert any(e["event"] == "finding" and e["action"] == "log" for e in px.events())


def test_acceptance_allowlist(proxy: StartProxy, upstream: FakeUpstream) -> None:
    secret = "allowlisted-secret-12345"
    px = proxy(
        f"allow:\n  - host: {TOOLS}\n    rules: [registered_secret]\n",
        env={"INTERNAL_API_TOKEN": secret},
    )
    status, _ = send(
        f"https://{TOOLS}/api", proxy_port=px.proc.port, trust=px.trust, data=f"token={secret}".encode()
    )
    assert status == 200
    assert upstream.requests_to(TOOLS)[0]["body"] == f"token={secret}"
    status, body = send(
        f"https://{OTHER}/api", proxy_port=px.proc.port, trust=px.trust, data=f"token={secret}".encode()
    )
    assert status == 403
    assert "registered_secret" in body
    assert upstream.requests_to(OTHER) == []


def test_redact_in_query_and_body(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy()
    status, _ = send(
        f"https://{TOOLS}/s?who=someone%40example.org",
        proxy_port=px.proc.port,
        trust=px.trust,
        data=b'{"note": "mail jane@example.org please"}',
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    (got,) = upstream.requests_to(TOOLS)
    assert got["path"] == "/s?who=[REDACTED:email]"
    assert got["body"] == '{"note": "mail [REDACTED:email] please"}'


def test_redaction_in_undecodable_body_is_blocked(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy()
    status, body = send(
        f"https://{TOOLS}/up",
        proxy_port=px.proc.port,
        trust=px.trust,
        data=b"not really gzip " + EMAIL.encode(),
        headers={"Content-Encoding": "gzip"},
    )
    assert status == 403
    assert "not text" in body
    assert upstream.requests_to(TOOLS) == []


def test_gzip_body_is_scanned(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy()
    status, _ = send(
        f"https://{TOOLS}/up",
        proxy_port=px.proc.port,
        trust=px.trust,
        data=gzip.compress(f"key {AWS}".encode()),
        headers={"Content-Encoding": "gzip"},
    )
    assert status == 403
    assert upstream.requests_to(TOOLS) == []


def test_clean_request_untouched(proxy: StartProxy, upstream: FakeUpstream) -> None:
    px = proxy()
    status, body = send(
        f"https://{TOOLS}/docs?q=json", proxy_port=px.proc.port, trust=px.trust, data=b"hello"
    )
    assert status == 200
    assert TOOLS in body
    (got,) = upstream.requests_to(TOOLS)
    assert got["body"] == "hello"


def test_passthrough_is_not_decrypted(proxy: StartProxy, upstream: FakeUpstream, pki: object) -> None:
    from pathlib import Path

    assert isinstance(pki, Path)
    px = proxy(f"passthrough_hosts: [{MODEL}]\n")
    # The client trusts ONLY the fake upstream CA: a 200 means the proxy did not present its own certificate.
    status, _ = send(
        f"https://{MODEL}/v1/messages",
        proxy_port=px.proc.port,
        trust=pki / "upstream-ca.pem",
        data=f"prompt with {AWS} and {EMAIL}".encode(),
    )
    assert status == 200
    assert upstream.requests_to(MODEL)[0]["body"] == f"prompt with {AWS} and {EMAIL}"
    # ...and an intercepted host fails for that same client: it is the proxy's certificate there.
    try:
        send(f"https://{TOOLS}/x", proxy_port=px.proc.port, trust=pki / "upstream-ca.pem")
        raise AssertionError("expected a certificate error")
    except OSError as e:
        assert "CERTIFICATE_VERIFY_FAILED" in str(e)
    assert any(e["event"] == "passthrough" and e["host"] == MODEL for e in px.events())
