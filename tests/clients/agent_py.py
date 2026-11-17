"""A stand-in "agent" for tests and the demo. Uses only urllib and whatever proxy/CA settings its env has.

usage: agent_py.py <scenario> [<upstream-ca.pem>]
  block        POST an AWS key to the tools host
  redact       GET the tools host with an email in User-Agent
  model        POST a prompt to the model host trusting ONLY <upstream-ca.pem> (proves no decryption)
  env          print the proxy/CA environment as JSON
  exit:<n>     exit with code n
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.request

TOOLS = os.environ.get("AGENT_TOOLS_HOST", "tools.example.test")
MODEL = os.environ.get("AGENT_MODEL_HOST", "api.model.test")
UA = "demo-agent/1.0 (dev.user@example.com)"


def call(url: str, data: bytes | None = None, ctx: ssl.SSLContext | None = None) -> str:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx) as r:
            return f"{r.status} {r.read().decode()[:80]}"
    except urllib.error.HTTPError as e:
        return f"{e.code} {e.read().decode().strip()[:160]}"


def main() -> int:
    scen = sys.argv[1]
    if scen == "block":
        print(call(f"https://{TOOLS}/upload", b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))
    elif scen == "redact":
        print(call(f"https://{TOOLS}/fetch?q=docs"))
    elif scen == "model":
        ctx = ssl.create_default_context(cafile=sys.argv[2])
        prompt = b'{"prompt": "my key is AKIAIOSFODNN7EXAMPLE, mail dev.user@example.com"}'
        print(call(f"https://{MODEL}/v1/messages", prompt, ctx))
    elif scen == "env":
        keys = [
            "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS", "NODE_USE_ENV_PROXY", "CURL_HOME", "GIT_SSL_CAINFO", "EGRESSGUARD_ACTIVE",
        ]  # fmt: skip
        print(json.dumps({k: os.environ.get(k) for k in keys}))
    elif scen.startswith("exit:"):
        return int(scen[5:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
