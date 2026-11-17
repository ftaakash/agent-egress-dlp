"""Definition of done: `egressguard demo` runs end to end on local fakes and checks its own result."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_demo_passes_and_leaves_nothing(tmp_path: Path) -> None:
    env = dict(os.environ, EGRESSGUARD_HOME=str(tmp_path / "must-not-be-used"))
    r = subprocess.run(
        [sys.executable, "-m", "egressguard.cli", "demo"],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    out = r.stdout
    assert r.returncode == 0, out + r.stderr
    assert "[python] POST tools  body has an AWS key" in out
    assert "403 egressguard: blocked request to tools.example.test: aws_access_key in body" in out
    assert "registered_secret in url" in out
    assert "User-Agent: demo-agent/1.0 ([REDACTED:email])" in out
    assert "Demo passed." in out
    assert not (tmp_path / "must-not-be-used").exists()  # the demo uses its own temporary home
