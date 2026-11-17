"""A stand-in "agent" for `egressguard demo` and the tests. Uses only what its environment gives it.

usage: python -m egressguard.demo_agent <scenario> [<upstream-ca.pem>]
  block        POST an AWS key to the tools host
  redact       GET the tools host with an email in User-Agent
  token        GET the tools host with $DEMO_API_TOKEN in the query string
  model        POST a prompt to the model host trusting ONLY <upstream-ca.pem> (proves no decryption)
  env          print the proxy/CA environment as JSON
  all          every scenario with Python urllib, then with curl and Node if they are installed
  exit:<n>     exit with code n
All values are fake: the AWS documentation example key and an example.com address.
"""

from __future__ import annotations

import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

TOOLS = os.environ.get("AGENT_TOOLS_HOST", "tools.example.test")
MODEL = os.environ.get("AGENT_MODEL_HOST", "api.model.test")
AWS = "AKIAIOSFODNN7EXAMPLE"
UA = "demo-agent/1.0 (dev.user@example.com)"
PROMPT = f'{{"prompt": "my key is {AWS}, mail dev.user@example.com"}}'
MODEL_LABEL = "POST model  prompt (trusts ONLY the real server's CA)"


def call(url: str, data: bytes | None = None, ctx: ssl.SSLContext | None = None) -> str:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA})  # noqa: S310 - fixed https URLs
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:  # noqa: S310
            return f"{r.status} {r.read().decode()[:80]}"
    except urllib.error.HTTPError as e:
        return f"{e.code} {e.read().decode().strip()[:160]}"
    except OSError as e:
        return f"ERROR {e}"


def scenario(scen: str, upstream_ca: str | None) -> str:
    if scen == "block":
        return call(f"https://{TOOLS}/upload", f"AWS_ACCESS_KEY_ID={AWS}".encode())
    if scen == "redact":
        return call(f"https://{TOOLS}/fetch?q=docs")
    if scen == "token":
        return call(f"https://{TOOLS}/search?token={os.environ.get('DEMO_API_TOKEN', '')}")
    if scen == "model":
        if not upstream_ca:
            raise SystemExit("the model scenario needs the upstream CA path")
        ctx = ssl.create_default_context(cafile=upstream_ca)
        return call(f"https://{MODEL}/v1/messages", PROMPT.encode(), ctx)
    raise SystemExit(f"unknown scenario {scen}")


def _short(text: str) -> str:
    """First sentence of the first line: enough to see the outcome."""
    line = text.strip().splitlines()[0] if text.strip() else "(no output)"
    return line.split(". ", 1)[0][:100]


def _curl_out(stdout: str, stderr: str) -> str:
    # curl is run with -w "\n%{http_code}": the status is the last line
    lines = stdout.strip().splitlines()
    if len(lines) >= 2 and lines[-1].isdigit():
        return f"{lines[-1]} {lines[0]}"
    return stdout or stderr


def run_all(upstream_ca: str) -> None:
    cases = [
        ("block", "POST tools  body has an AWS key"),
        ("redact", "GET  tools  email in User-Agent"),
        ("token", "GET  tools  $DEMO_API_TOKEN in URL"),
        ("model", MODEL_LABEL),
    ]
    for scen, label in cases:
        print(f"  [python] {label:<53} -> {_short(scenario(scen, upstream_ca))}", flush=True)

    curl = shutil.which("curl")
    if curl:
        base = [curl, "-sS", "-A", UA, "--max-time", "15", "-w", "\n%{http_code}"]
        curl_cases = [
            (
                "POST tools  body has an AWS key",
                [*base, "--data-binary", f"k={AWS}", f"https://{TOOLS}/upload"],
            ),
            ("GET  tools  email in User-Agent", [*base, f"https://{TOOLS}/fetch?q=docs"]),
            (
                MODEL_LABEL,
                [*base, "--cacert", upstream_ca, "--data-binary", PROMPT, f"https://{MODEL}/v1/messages"],
            ),
        ]
        for label, cmd in curl_cases:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            print(f"  [curl]   {label:<53} -> {_short(_curl_out(p.stdout, p.stderr))}", flush=True)
    else:
        print("  [curl]   not installed, skipped", flush=True)

    node = shutil.which("node")
    mjs = Path(__file__).with_name("demo_agent.mjs")
    if node:
        for scen, label in [
            ("block", "POST tools  body has an AWS key"),
            ("redact", "GET  tools  email in User-Agent"),
        ]:
            p = subprocess.run([node, str(mjs), scen], capture_output=True, text=True, timeout=30)
            print(f"  [node]   {label:<53} -> {_short(p.stdout or p.stderr)}", flush=True)
    else:
        print("  [node]   not installed, skipped", flush=True)


def main() -> int:
    scen = sys.argv[1]
    upstream_ca = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("AGENT_UPSTREAM_CA")
    if scen == "all":
        if not upstream_ca:
            raise SystemExit("the all scenario needs the upstream CA path")
        run_all(upstream_ca)
    elif scen == "env":
        keys = [
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY", "CURL_HOME", "GIT_SSL_CAINFO", "EGRESSGUARD_ACTIVE",
        ]  # fmt: skip
        print(json.dumps({k: os.environ.get(k) for k in keys}))
    elif scen.startswith("exit:"):
        return int(scen[5:])
    else:
        print(scenario(scen, upstream_ca))
    return 0


if __name__ == "__main__":
    sys.exit(main())
