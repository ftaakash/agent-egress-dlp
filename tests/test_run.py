"""F5: `egressguard run -- <cmd>` with real clients (Python urllib, curl, Node fetch, git)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import MODEL, TOOLS

import egressguard
from egressguard.fakes import FakeUpstream, port_is_listening
from egressguard.runner import child_env

AGENT_PY = [sys.executable, "-m", "egressguard.demo_agent"]
AGENT_MJS = str(Path(egressguard.__file__).with_name("demo_agent.mjs"))
AWS = "AKIAIOSFODNN7EXAMPLE"


def eg_run(
    upstream: FakeUpstream,
    pki: Path,
    work: Path,
    cmd: list[str],
    *,
    policy: str = f"passthrough_hosts: [{MODEL}]\n",
    via: str = "flag",
    repo_policy: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """`policy` is trusted: passed with --policy (via="flag") or as the user config (via="user").
    `repo_policy` is written to the project's .egressguard.yml, which may only tighten."""
    args = [sys.executable, "-m", "egressguard.cli", "run", "--extra-ca", str(pki / "upstream-ca.pem")]
    if via == "flag":
        trusted = work.parent / "trusted-policy.yml"
        trusted.write_text(policy, encoding="utf-8")
        args += ["--policy", str(trusted)]
    else:
        home = Path(os.environ["EGRESSGUARD_HOME"])
        home.mkdir(parents=True, exist_ok=True)
        (home / "config.yml").write_text(policy, encoding="utf-8")
    if repo_policy is not None:
        (work / ".egressguard.yml").write_text(repo_policy, encoding="utf-8")
    for host, (ip, port) in upstream.resolve_map().items():
        args += ["--resolve", f"{host}={ip}:{port}"]
    return subprocess.run(
        [*args, "--", *cmd], cwd=work, capture_output=True, text=True, timeout=120, env=dict(os.environ)
    )


def proxy_port(stderr: str) -> int:
    m = re.search(r"proxy on 127\.0\.0\.1:(\d+)", stderr)
    assert m, stderr
    return int(m.group(1))


@pytest.fixture
def work(tmp_path: Path, eg_home: Path) -> Path:
    d = tmp_path / "proj"
    d.mkdir()
    return d


def test_acceptance_python_client(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    agent = AGENT_PY
    # (a) tools host is inspected: AWS key blocked
    r = eg_run(upstream, pki, work, [*agent, "block"])
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("403 egressguard: blocked"), r.stdout
    assert not port_is_listening(proxy_port(r.stderr))  # (d) no listener left
    # (b) model host passes through: the client trusts ONLY the upstream CA and still gets 200
    r = eg_run(upstream, pki, work, [*agent, "model", str(pki / "upstream-ca.pem")])
    assert r.stdout.startswith("200"), r.stdout + r.stderr
    assert AWS in upstream.requests_to(MODEL)[0]["body"]  # untouched
    assert upstream.requests_to(TOOLS) == []
    # (d) exit code propagates
    assert eg_run(upstream, pki, work, [*agent, "exit:7"]).returncode == 7


def test_acceptance_child_environment(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(upstream, pki, work, [*AGENT_PY, "env"])
    env = json.loads(r.stdout)
    port = proxy_port(r.stderr)
    assert env["HTTPS_PROXY"] == f"http://127.0.0.1:{port}"
    assert env["NODE_USE_ENV_PROXY"] == "1"
    assert env["NO_PROXY"] is None
    assert env["EGRESSGUARD_ACTIVE"] == "1"
    assert env["CURL_HOME"]
    # the session directory (bundles, curl config) is removed when the run ends
    assert not Path(env["CURL_HOME"]).exists()


def test_child_env_contents(tmp_path: Path) -> None:
    import certifi

    ca = tmp_path / "proxy-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nPROXYCA\n-----END CERTIFICATE-----\n", encoding="utf-8")
    base = {"PATH": "x", "NO_PROXY": "*", "no_proxy": "corp", "GIT_CONFIG_COUNT": "1", "HOME": "h"}
    env = child_env(base, "http://127.0.0.1:1234", tmp_path / "s", ca, extra_ca=[])
    bundle = Path(env["SSL_CERT_FILE"]).read_text(encoding="utf-8")
    assert "PROXYCA" in bundle
    assert bundle.count("BEGIN CERTIFICATE") > 50  # public roots are included, not replaced
    assert Path(certifi.where()).read_text(encoding="utf-8").strip()[-200:] in bundle
    assert env["REQUESTS_CA_BUNDLE"] == env["CURL_CA_BUNDLE"] == env["SSL_CERT_FILE"]
    assert env["GIT_SSL_CAINFO"] == env["SSL_CERT_FILE"]
    node_ca = Path(env["NODE_EXTRA_CA_CERTS"]).read_text(encoding="utf-8")
    assert "PROXYCA" in node_ca and node_ca.count("BEGIN CERTIFICATE") == 1  # additive for Node
    assert "NO_PROXY" not in env and "no_proxy" not in env
    assert env["HTTPS_PROXY"] == env["https_proxy"] == "http://127.0.0.1:1234"
    curlrc = (Path(env["CURL_HOME"]) / ".curlrc").read_text(encoding="utf-8")
    assert "cacert" in curlrc
    assert (Path(env["CURL_HOME"]) / "_curlrc").read_text(encoding="utf-8") == curlrc
    assert ("ssl-revoke-best-effort" in curlrc) == (os.name == "nt")
    # git config entries are appended after the user's own
    assert env["GIT_CONFIG_COUNT"] == "3"
    assert env["GIT_CONFIG_KEY_1"] == "http.sslCAInfo"
    assert base["NO_PROXY"] == "*"  # the caller's mapping is not modified


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
def test_acceptance_curl(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    curl = shutil.which("curl")
    assert curl
    ua = ["-A", "demo-agent/1.0 (dev.user@example.com)"]
    r = eg_run(upstream, pki, work, [curl, "-sS", *ua, "--data-binary", f"k={AWS}", f"https://{TOOLS}/up"])
    assert "egressguard: blocked" in r.stdout, r.stdout + r.stderr
    r = eg_run(upstream, pki, work, [curl, "-sS", *ua, f"https://{TOOLS}/fetch"])
    assert '"ok": true' in r.stdout, r.stdout + r.stderr
    # passthrough: curl trusting only the upstream CA still connects
    cmd = [curl, "-sS", "--cacert", str(pki / "upstream-ca.pem"), "-d", "hi", f"https://{MODEL}/v1"]
    r = eg_run(upstream, pki, work, cmd)
    assert '"server": "api.model.test"' in r.stdout, r.stdout + r.stderr
    (got,) = upstream.requests_to(TOOLS)
    assert "dev.user@example.com" not in got["headers"]["User-Agent"]
    assert "[REDACTED:" in got["headers"]["User-Agent"]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_acceptance_node_fetch(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    node = shutil.which("node")
    assert node
    r = eg_run(upstream, pki, work, [node, AGENT_MJS, "block"])
    assert r.stdout.startswith("403 egressguard: blocked"), r.stdout + r.stderr
    r = eg_run(upstream, pki, work, [node, AGENT_MJS, "redact"])
    assert r.stdout.startswith("200"), r.stdout + r.stderr
    (got,) = upstream.requests_to(TOOLS)
    assert "[REDACTED:" in got["headers"]["User-Agent"]


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_https_goes_through_proxy(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    git = shutil.which("git")
    assert git
    r = eg_run(upstream, pki, work, [git, "ls-remote", f"https://{TOOLS}/repo.git"])
    # The fake server is not a git server, so git fails after the HTTP exchange; what matters is that the
    # request got through the proxy's TLS (no certificate error) and reached the upstream.
    assert "certificate" not in r.stderr.lower() and "ssl" not in r.stderr.lower(), r.stderr
    assert any(q["path"].startswith("/repo.git/info/refs") for q in upstream.requests_to(TOOLS))


def test_bad_policy_exits_2_without_starting(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(
        upstream,
        pki,
        work,
        [sys.executable, "-c", "print('child ran')"],
        policy="rules:\n  credit_card: block\n",
    )
    assert r.returncode == 2
    assert "credit_card" in r.stderr
    assert "proxy on" not in r.stderr
    assert "child ran" not in r.stdout


def test_command_not_found(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(upstream, pki, work, ["definitely-not-a-command-xyz"])
    assert r.returncode == 127
    assert "not found" in r.stderr


def test_user_config_can_loosen_and_is_announced(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(
        upstream, pki, work, [*AGENT_PY, "block"], policy="rules:\n  aws_access_key: log\n", via="user"
    )
    assert r.stdout.startswith("200"), r.stdout + r.stderr  # the user's own config is trusted
    assert "weakens the defaults: aws_access_key: log (default block)" in r.stderr


def test_acceptance_repo_policy_cannot_loosen(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    repo = (
        "rules:\n  aws_access_key: log\n"
        f"allow:\n  - host: {TOOLS}\n    rules: [aws_access_key]\n"
        "passthrough_hosts: [api.model.test, tools.example.test]\n"
    )
    r = eg_run(upstream, pki, work, [*AGENT_PY, "block"], via="user", repo_policy=repo)
    assert r.stdout.startswith("403 egressguard: blocked"), r.stdout + r.stderr
    assert upstream.requests_to(TOOLS) == []
    assert "ignored" in r.stderr
    assert "aws_access_key: log" in r.stderr
    assert f"allow {TOOLS}" in r.stderr
    assert f"passthrough {TOOLS}" in r.stderr


def test_repo_policy_can_tighten(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(upstream, pki, work, [*AGENT_PY, "redact"], via="user", repo_policy="rules:\n  email: block\n")
    assert r.stdout.startswith("403 egressguard: blocked"), r.stdout + r.stderr
    assert "email in header:User-Agent" in r.stdout


def test_explicit_policy_flag_skips_repo_file(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(upstream, pki, work, [*AGENT_PY, "redact"], repo_policy="rules:\n  email: block\n")
    assert r.stdout.startswith("200"), r.stdout + r.stderr
    assert "not used because --policy was given" in r.stderr


def test_bad_repo_policy_exits_2(upstream: FakeUpstream, pki: Path, work: Path) -> None:
    r = eg_run(upstream, pki, work, [*AGENT_PY, "exit:0"], via="user", repo_policy="rules:\n  nope: block\n")
    assert r.returncode == 2
    assert "nope" in r.stderr


def test_invalid_git_config_count_is_tolerated(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n", encoding="utf-8")
    env = child_env({"GIT_CONFIG_COUNT": "abc"}, "http://127.0.0.1:1", tmp_path / "s", ca, extra_ca=[])
    assert env["GIT_CONFIG_COUNT"] == "2"
    assert env["GIT_CONFIG_KEY_0"] == "http.sslCAInfo"


def test_ctrl_c_during_startup_kills_the_proxy(
    tmp_path: Path, eg_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from egressguard import runner
    from egressguard.session import SessionConfig

    started: list[subprocess.Popen[bytes]] = []
    real_popen = subprocess.Popen

    def spy(*a: object, **k: object) -> subprocess.Popen[bytes]:
        p = real_popen(*a, **k)  # type: ignore[call-overload]
        started.append(p)
        return p  # type: ignore[no-any-return]

    def interrupt(_s: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(runner.subprocess, "Popen", spy)
    monkeypatch.setattr(runner, "_sleep", interrupt)
    cfg = SessionConfig.new(cwd=tmp_path, log_path=tmp_path / "l.jsonl", session_dir=tmp_path / "s")
    with pytest.raises(KeyboardInterrupt):
        runner.start_proxy(cfg)
    assert started and started[0].poll() is not None  # the proxy process was stopped
    # ...and so was the real interpreter behind a Windows venv launcher: a survivor would write the ready
    # file within about a second of starting.
    import time

    time.sleep(4)
    assert not cfg.ready_file.exists()
