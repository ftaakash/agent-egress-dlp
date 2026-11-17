"""`egressguard demo`: the whole product on local fakes, with fake values, in one command.

Starts two HTTPS servers on 127.0.0.1 with a throwaway CA, runs a stand-in agent through `egressguard run`,
shows what the servers received and the report. Uses a temporary EGRESSGUARD_HOME and removes it afterwards.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import tempfile
from pathlib import Path

from .fakes import FakeUpstream, make_fake_pki
from .report import report
from .runner import run

TOOLS = "tools.example.test"
MODEL = "api.model.test"
AWS = "AKIAIOSFODNN7EXAMPLE"
DEMO_TOKEN = "demo-token-not-a-real-secret-1234"  # noqa: S105 - fake; registered via the environment


class _MaskTmp(io.TextIOBase):
    """stdout that shows the demo's temporary folder as <tmp> (keeps local paths out of the output)."""

    def __init__(self, tmp: Path) -> None:
        self.names = sorted({str(tmp), str(tmp.resolve())}, key=len, reverse=True)

    def write(self, s: str) -> int:
        for n in self.names:
            s = s.replace(n, "<tmp>")
        sys.stdout.write(s)
        return len(s)

    def flush(self) -> None:
        sys.stdout.flush()


def _say(text: str = "") -> None:
    print(text, flush=True)


def demo() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="egressguard-demo-"))
    saved = {k: os.environ.get(k) for k in ("EGRESSGUARD_HOME", "DEMO_API_TOKEN", "AGENT_UPSTREAM_CA")}
    try:
        pki = tmp / "pki"
        ca = make_fake_pki(pki, [TOOLS, MODEL])
        work = tmp / "project"
        work.mkdir()
        (work / ".egressguard.yml").write_text(
            f"# demo policy: treat the fake model host like a real model API\npassthrough_hosts: [{MODEL}]\n",
            encoding="utf-8",
        )
        log = tmp / "egress.jsonl"
        os.environ["EGRESSGUARD_HOME"] = str(tmp / "home")
        os.environ["DEMO_API_TOKEN"] = DEMO_TOKEN
        os.environ["AGENT_UPSTREAM_CA"] = str(ca)

        with FakeUpstream(pki, [TOOLS, MODEL]) as up:
            _say("egressguard demo: local servers on 127.0.0.1, fake values, nothing leaves this machine.")
            _say(f"  fake third-party site: {TOOLS:<20} -> 127.0.0.1:{up.port(TOOLS)}")
            _say(f"  fake model API:        {MODEL:<20} -> 127.0.0.1:{up.port(MODEL)}  (passthrough)")
            _say()
            _say("== 1. What the agent saw (egressguard run -- python -m egressguard.demo_agent all)")
            code = run(
                [sys.executable, "-m", "egressguard.demo_agent", "all"],
                policy_path=work / ".egressguard.yml",
                log_path=log,
                extra_ca=[ca],
                resolve=up.resolve_map(),
                cwd=work,
                out=_MaskTmp(tmp),
            )
            reqs = list(up.requests)

        _say()
        _say("== 2. What the servers actually received")
        for r in reqs:
            line = f"  {r['server']:<20} {r['method']:<4} {r['path']:<24}"
            if r["server"] == TOOLS:
                line += f" User-Agent: {r['headers'].get('User-Agent')}"
            else:
                line += f" body: {r['body'][:70]}"
            _say(line)

        problems = []
        if code != 0:
            problems.append(f"agent exited with {code}")
        tools = [r for r in reqs if r["server"] == TOOLS]
        model = [r for r in reqs if r["server"] == MODEL]
        if any(AWS in r["body"] or AWS in r["path"] or DEMO_TOKEN in r["path"] for r in tools):
            problems.append("a blocked value reached the tools host")
        if not tools or any("dev.user@example.com" in r["headers"].get("User-Agent", "") for r in tools):
            problems.append("the email was not redacted at the tools host")
        if not model or any(AWS not in r["body"] for r in model):
            problems.append("the model host did not receive the prompt untouched")
        _say(
            f"  -> {len(tools)} requests reached {TOOLS}, none with the AWS key or the token; "
            f"{len(model)} reached {MODEL} unchanged."
            if not problems
            else ""
        )

        _say()
        _say("== 3. egressguard report --last")
        sys.stdout.write(report(log, last_session=True).replace(str(log), "<demo log>"))

        if problems:
            _say("\nDEMO FAILED: " + "; ".join(problems))
            return 1
        _say("\nDemo passed. All servers stopped; temporary files removed.")
        return 0
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)
