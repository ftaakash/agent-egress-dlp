"""Start and stop the proxy process. (`egressguard run` builds on this.)"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .fakes import port_is_listening
from .proxy import ca_dir
from .session import SessionConfig

START_TIMEOUT = 60.0


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
    while time.monotonic() < deadline:
        if cfg.ready_file.exists():
            port = int(json.loads(cfg.ready_file.read_text(encoding="utf-8"))["port"])
            return ProxyProcess(popen, port, ca_dir() / "mitmproxy-ca-cert.pem", log_file)
        if popen.poll() is not None:
            break
        time.sleep(0.05)
    kill_tree(popen)
    tail = log_file.read_text(encoding="utf-8", errors="replace")[-2000:]
    raise ProxyStartError(f"proxy did not start (log {log_file}):\n{tail}")
