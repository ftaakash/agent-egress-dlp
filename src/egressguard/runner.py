"""`egressguard run`: start the proxy, run the agent with per-process proxy and trust, clean up."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .fakes import port_is_listening
from .policy import Policy
from .proxy import ca_dir
from .session import SessionConfig

START_TIMEOUT = 60.0
_sleep = time.sleep  # module attribute so a test can interrupt only the startup wait


class Writer(Protocol):
    def write(self, s: str, /) -> int: ...
    def flush(self) -> None: ...


class ProxyStartError(RuntimeError):
    pass


def kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        # The venv python.exe is a launcher with the real interpreter as its child: kill the whole tree.
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


@dataclass
class ProxyProcess:
    popen: subprocess.Popen[bytes]
    port: int
    ca_cert: Path
    log_file: Path

    def stop(self) -> None:
        kill_tree(self.popen)

    def is_listening(self) -> bool:
        return port_is_listening(self.port)


def start_proxy(cfg: SessionConfig, extra_env: dict[str, str] | None = None) -> ProxyProcess:
    path = cfg.save()
    cfg.ready_file.unlink(missing_ok=True)
    log_file = Path(cfg.session_dir) / "proxy.log"
    env = dict(os.environ)
    env.update(extra_env or {})
    out = log_file.open("wb")
    popen = subprocess.Popen(
        [sys.executable, "-m", "egressguard.proxy", str(path)],
        stdout=out,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=env,
    )
    out.close()
    deadline = time.monotonic() + START_TIMEOUT
    try:
        while time.monotonic() < deadline:
            if cfg.ready_file.exists():
                port = int(json.loads(cfg.ready_file.read_text(encoding="utf-8"))["port"])
                return ProxyProcess(popen, port, ca_dir() / "mitmproxy-ca-cert.pem", log_file)
            if popen.poll() is not None:
                break
            _sleep(0.05)
    except BaseException:  # Ctrl+C or any error while waiting: do not leave the proxy running
        kill_tree(popen)
        raise
    kill_tree(popen)
    tail = log_file.read_text(encoding="utf-8", errors="replace")[-2000:]
    raise ProxyStartError(f"proxy did not start (log {log_file}):\n{tail}")


# Variables that would let traffic skip the proxy or point it at another trust store.
_STRIP = {
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY", "CURL_HOME",
    "GIT_SSL_CAINFO", "GIT_SSL_CAPATH",
}  # fmt: skip


def _read_pems(paths: list[Path]) -> str:
    return "".join(p.read_text(encoding="utf-8").strip() + "\n" for p in paths)


def child_env(
    base: Mapping[str, str],
    proxy_url: str,
    session_dir: Path,
    proxy_ca: Path,
    extra_ca: list[Path],
) -> dict[str, str]:
    """Environment for the agent: proxy and trust for this process tree only."""
    import certifi

    session_dir.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in base.items() if k.upper() not in _STRIP}

    # SSL_CERT_FILE / REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE replace the trust store, so the bundle must
    # also hold the public roots or every real HTTPS host would break.
    bundle = session_dir / "ca-bundle.pem"
    bundle.write_text(_read_pems([proxy_ca, Path(certifi.where()), *extra_ca]), encoding="utf-8")
    # NODE_EXTRA_CA_CERTS is added to Node's built-in roots.
    node_ca = session_dir / "node-extra-ca.pem"
    node_ca.write_text(_read_pems([proxy_ca, *extra_ca]), encoding="utf-8")

    # Schannel curl (both curl.exe builds on Windows) ignores CURL_CA_BUNDLE; a config file via CURL_HOME
    # works for every build. A private CA has no revocation endpoint, so Schannel needs best-effort checks.
    curl_home = session_dir / "curl"
    curl_home.mkdir(exist_ok=True)
    curlrc = f'cacert = "{bundle.as_posix()}"\n'
    if os.name == "nt":
        curlrc += "ssl-revoke-best-effort\n"
    for name in (".curlrc", "_curlrc"):
        (curl_home / name).write_text(curlrc, encoding="utf-8")

    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
        env[k] = proxy_url
    for k in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"):
        env[k] = str(bundle)
    env["NODE_EXTRA_CA_CERTS"] = str(node_ca)
    env["NODE_USE_ENV_PROXY"] = "1"  # Node 24 fetch ignores HTTPS_PROXY without it
    env["CURL_HOME"] = str(curl_home)
    env["EGRESSGUARD_ACTIVE"] = "1"

    # git: per-process config entries, appended after any the user already passes this way.
    raw_count = env.get("GIT_CONFIG_COUNT", "").strip()
    n = int(raw_count) if raw_count.isdigit() else 0
    git_cfg = [
        ("http.sslCAInfo", str(bundle)),
        ("http.schannelUseSSLCAInfo", "true"),  # Git for Windows with the Schannel backend
    ]
    for i, (key, value) in enumerate(git_cfg, start=n):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    env["GIT_CONFIG_COUNT"] = str(n + len(git_cfg))
    return env


def _resolve_command(cmd: list[str]) -> list[str] | None:
    exe = shutil.which(cmd[0])
    if exe is None:
        return None
    return [exe, *cmd[1:]]


def run(
    cmd: list[str],
    *,
    policy: Policy,
    policy_label: str,
    log_path: Path,
    extra_ca: list[Path],
    resolve: dict[str, tuple[str, int]],
    cwd: Path,
    out: Writer = sys.stderr,
    notices: bool = True,
) -> int:
    """Run `cmd` behind the proxy with `policy` (already merged and validated). Returns its exit code.

    With `notices`, every block and redaction is printed to `out` as it happens, so the person running the
    agent sees it even when the agent does not."""
    resolved = _resolve_command(cmd)
    if resolved is None:
        print(f"egressguard: command not found: {cmd[0]}", file=out)
        return 127
    session_dir = Path(tempfile.mkdtemp(prefix="egressguard-"))
    # The proxy gets the merged policy, never a repository's raw file. JSON is valid YAML for load_policy.
    policy_path = session_dir / "policy.json"
    policy_path.write_text(json.dumps(policy.to_data(), indent=2), encoding="utf-8")
    cfg = SessionConfig.new(
        cwd=cwd,
        policy_path=policy_path,
        log_path=log_path,
        session_dir=session_dir,
        resolve=resolve,
        extra_ca=extra_ca,
    )
    proxy: ProxyProcess | None = None
    watcher = LiveNotices(log_path, cfg.session_id, out) if notices else None
    try:
        proxy = start_proxy(cfg)
        url = f"http://127.0.0.1:{proxy.port}"
        env = child_env(os.environ, url, session_dir, proxy.ca_cert, extra_ca)
        print(
            f"egressguard: proxy on 127.0.0.1:{proxy.port}, session {cfg.session_id}, "
            f"policy {policy_label}, log {log_path}",
            file=out,
            flush=True,
        )
        if watcher is not None:
            watcher.start()
        child = subprocess.Popen(resolved, env=env, cwd=cwd)
        while True:
            try:
                code = child.wait()
                break
            except KeyboardInterrupt:  # Ctrl+C also reaches the child; wait for it to exit
                continue
        return code
    finally:
        if proxy is not None:
            proxy.stop()
        if watcher is not None:
            watcher.stop()  # prints anything the proxy logged after the last poll
        shutil.rmtree(session_dir, ignore_errors=True)
        _session_summary(log_path, cfg.session_id, out)


def notice_line(event: dict[str, object]) -> str | None:
    """One terminal line for a log event, or None. Never includes a matched value (the log has none)."""
    kind = event.get("event")
    host = event.get("host")
    if kind == "finding":
        verb = {"block": "blocked", "redact": "redacted"}.get(str(event.get("action")))
        if verb:
            return f"egressguard: {verb} {event.get('rule')} in {event.get('where')} ({host})"
    elif kind == "tcp_blocked":
        return f"egressguard: closed a non-HTTP connection to {host} (a value matched a rule)"
    elif kind == "addon_error":
        return f"egressguard: blocked a request to {host} after an internal error (fail closed)"
    return None


class LiveNotices:
    """Follows this session's lines in the event log and prints a notice for each block or redaction."""

    def __init__(self, log_path: Path, session: str, out: Writer, interval: float = 0.25) -> None:
        self.log_path = log_path
        self.session = session
        self.out = out
        self.interval = interval
        self._offset = log_path.stat().st_size if log_path.exists() else 0
        self._partial = b""
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="egressguard-notices", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        self._poll()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._poll()

    def _poll(self) -> None:
        try:
            with self.log_path.open("rb") as f:
                f.seek(self._offset)
                chunk = f.read()
        except OSError:
            return
        self._offset += len(chunk)
        data = self._partial + chunk
        lines = data.split(b"\n")
        self._partial = lines.pop()  # an unfinished last line is kept for the next poll
        for raw in lines:
            try:
                event = json.loads(raw)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get("session") == self.session:
                line = notice_line(event)
                if line:
                    print(line, file=self.out, flush=True)


def _session_summary(log_path: Path, session: str, out: Writer) -> None:
    from .eventlog import read_events

    ev = [e for e in read_events(log_path) if e.get("session") == session]
    req = [e for e in ev if e.get("event") == "request"]
    if not ev:
        return
    blocked = sum(1 for e in req if e.get("outcome") == "blocked")
    redacted = sum(1 for e in req if e.get("outcome") == "redacted")
    passthrough = sum(1 for e in ev if e.get("event") == "passthrough")
    print(
        f"egressguard: session {session}: {len(req)} requests inspected, {blocked} blocked, "
        f"{redacted} redacted, {passthrough} passthrough connections (egressguard report --last)",
        file=out,
        flush=True,
    )
