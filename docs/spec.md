# egressguard v0.1 — frozen spec

Frozen on 2026-11-17 (Stage 3). New ideas go to `docs/later.md`, not into v0.1.

## What it is

`egressguard run -- <agent>` starts a local intercepting proxy for one agent process and its children. It inspects the agent's
non-model HTTP(S) traffic (web fetches, `curl`, MCP over HTTP) and redacts, blocks or logs secrets, PII and the developer's
identity before they leave the machine. Model-API hosts are passed through as opaque TLS tunnels and never decrypted.

## Features (v0.1, five)

Each feature has one acceptance test, written before the code, in `tests/`.

| # | Feature | Acceptance test (observable) |
|---|---|---|
| F1 | **Policy file** `.egressguard.yml`: per-rule action, model hosts to pass through, an allowlist of hosts that may receive given rules' values. Built-in defaults when there is no file. | Given a policy that sets `email: block` and allows `registered_secret` to `api.internal.test`, `load_policy` returns those settings with defaults for the rest; a policy naming an unknown rule or action makes `egressguard run` exit with code 2 and a message naming the bad key, without starting anything. |
| F2 | **Content rules**: registered secrets (exact values from `.env` and secret-looking environment variables, raw and URL-encoded), key formats (AWS, GitHub, Anthropic, OpenAI, Stripe, private-key blocks), identity (email addresses, git `user.email`, OS username). Checked in the URL (path and query), headers and body. | Given a request with the AWS documentation key in the body, a GitHub-format token in a header, a `.env` value in the query string, the git email and the OS username, the scanner reports each with its rule name and location (`url`, `header:<name>`, `body`); a request with none of them yields no finding. |
| F3 | **Actions** `block` / `redact` / `log` in a mitmproxy addon. Blocked requests get a 403 whose text names the rule so the agent can recover. Hosts on a rule's allowlist receive the value unchanged. Any addon error blocks the request (fail closed). | Through the real proxy and a local fake upstream: a body with the AWS key gets `403` with `egressguard: blocked` and the rule name, and the upstream records **no request and no connection**; an email in `User-Agent` reaches the upstream as `[REDACTED:email]`; a `log` rule lets the value through unchanged and logs it; an allowlisted host receives the registered secret unchanged. |
| F4 | **Local JSONL log and `egressguard report`**: one event per finding, block, inspected request and passthrough connection. Values are stored only as a keyed hash (HMAC-SHA256, 16 hex chars, per-install key). `report` prints top hosts, findings per rule and action, and passthrough hosts. | After a session that blocked one AWS key and redacted one email, the log file does not contain either raw value anywhere, and `egressguard report` prints the tools host with its request count, `aws_access_key  block  1` and `email  redact  1`. |
| F5 | **`egressguard run -- <cmd>`**: picks a free local port, starts the proxy as a child process with the policy, sets proxy and trust variables **only in the agent's environment**, waits for the agent, stops the proxy and returns the agent's exit code. | `egressguard run -- <client>` against the fake upstream: (a) a request to the tools host is blocked; (b) a request to the passthrough model host succeeds **with the client trusting only the upstream CA**, which proves it was not decrypted; (c) the child sees `HTTPS_PROXY`, `NODE_USE_ENV_PROXY=1`, `CURL_HOME` with a curl config, and an `SSL_CERT_FILE` bundle holding the proxy CA **and** the public roots; (d) the run returns the child's exit code and no listener is left on the proxy port. Checked with Python urllib, curl and Node fetch. |

## Non-goals (v0.1)

- Redacting model-API traffic (crowded; other proxies do it). Model hosts are passed through untouched, not scanned.
- Enforcement. v0.1 is guidance-level and bypassable: anything that ignores `HTTPS_PROXY` or pins certificates goes around it.
  Known bypasses from the spike: Windows PowerShell 5.1 `Invoke-WebRequest`, Node before 24 or libraries with their own agent, `curl -q`.
- Kernel, firewall or network-namespace enforcement; system proxy settings; installing the CA in any trust store.
- Windows service mode, dashboards, SIEM export, IDE agents (Cursor), team policy server.
- ML/NER PII detection: regex and exact match only.
- HTTP/2-specific handling, WebSocket and streaming bodies beyond what mitmproxy does by default (not tested in v0.1).
- Publishing to PyPI (the user can do it later; commands are in `launch.md`).

## Demo scenario (definition of done)

```
egressguard demo
```

No account, no API key, no network. It starts two local fake HTTPS servers with a throwaway CA (`tools.example.test`
standing in for a third-party site, `api.model.test` standing in for the model API), runs a small "agent" through
`egressguard run` that sends: an AWS documentation key in a POST body, the developer's email in a `User-Agent` header,
and a prompt to the model host. Then it prints:

1. per client (Python urllib always; curl and Node if installed): `403 blocked`, `200 redacted`, `200 passthrough`;
2. what the fake servers actually received (the key never arrives, the email arrives as `[REDACTED:email]`, the model
   host gets the body byte for byte);
3. `egressguard report` for the session.

All values are fake (`AKIAIOSFODNN7EXAMPLE`, `dev.user@example.com`). The demo stops every server it starts.

## Design (one page)

```
 agent process tree                     egressguard (parent)
 ┌───────────────┐ HTTPS_PROXY ┌──────────────────────────────┐        ┌────────────────────┐
 │ claude / curl │────────────▶│ mitmdump + egressguard addon │──TLS──▶│ third-party hosts  │
 │ node / python │             │  127.0.0.1:<free port>       │        └────────────────────┘
 └───────────────┘             │  model hosts: ignore_hosts   │──TCP tunnel (no decryption)──▶ model API
                               └──────────────┬───────────────┘
                                              ▼
                                   ~/.egressguard/egress.jsonl (hashed values) ──▶ egressguard report
```

Components (package `egressguard`):

- `policy.py`: defaults, YAML load (`ruamel.yaml`), validation.
- `rules.py`: pure scanner `scan(text) -> list[Finding]` and `redact(text, findings)`; no mitmproxy import.
- `secrets.py`: registered values from `.env` and environment, git email, OS username.
- `addon.py`: mitmproxy addon (`request`, `server_connect`); applies actions, logs, fails closed.
- `eventlog.py`: JSONL writer with HMAC hashing; `report.py` reads it.
- `runner.py`: free port, proxy child process, session directory (CA bundles, curl config), child environment, cleanup.
- `cli.py`: `run`, `report`, `demo` (argparse, stdlib).
- `fakes.py`: throwaway CA, fake TLS upstream that records requests and connections (used by tests and `demo`).

Decisions and the alternative rejected:

| Decision | Rejected alternative | Why |
|---|---|---|
| mitmproxy as the engine (user decision 2026-11-17) | stdlib `ssl` CONNECT proxy | mature TLS interception, HTTP/1 and 2, decoding of compressed bodies; cost: ~40 transitive packages, LGPL-3.0 Windows component, one package with no declared licence (stated in README, open for v0.2) |
| Proxy runs as a child process (`python -m egressguard.proxy`) | mitmproxy `DumpMaster` in-process | crash isolation, simple kill on exit, same code path as `mitmdump` |
| Trust passed per process (env vars + per-session `CURL_HOME`) | installing the CA in the OS store | never changes system state; only the agent's processes trust the CA |
| `SSL_CERT_FILE`/`REQUESTS_CA_BUNDLE`/`CURL_CA_BUNDLE` = proxy CA + certifi roots (+ `--extra-ca`) | proxy CA alone | these variables replace the trust store (spike finding 4); `NODE_EXTRA_CA_CERTS` is additive, so it gets the proxy CA only |
| Per-session `.curlrc`/`_curlrc` with `cacert` (+ `ssl-revoke-best-effort` on Windows) via `CURL_HOME` | `CURL_CA_BUNDLE` alone | Schannel curl ignores `CURL_CA_BUNDLE` and fails revocation checks for a private CA (spike finding 1) |
| `NODE_USE_ENV_PROXY=1` set for the child | none | Node 24 fetch ignores `HTTPS_PROXY` without it (spike finding 2) |
| `NO_PROXY`/`no_proxy` removed from the child env | keep the user's | a `NO_PROXY` entry would silently bypass inspection; stated in README |
| Model hosts via mitmproxy `ignore_hosts`, logged at `server_connect` | decrypt and re-encrypt model traffic | the product promise is that model traffic is never decrypted; ignored hosts only reach `server_connect` (spike finding 5) |
| `connection_strategy=lazy` | default `eager` | with eager, the proxy connects upstream before the request hook, so a blocked request still reaches the destination (spike finding 6) |
| Secrets read by the proxy process from its own environment and the `.env` path | writing them to a session file | registered values never touch disk |
| HMAC-SHA256 with a per-install random key for logged values | plain SHA-256 | emails and usernames are low-entropy; a plain hash is reversible by guessing |
| `--resolve HOST=IP:PORT` (for local fakes in tests and the demo) | editing the hosts file | no system change; documented as a testing aid |

### Threat model (what egressguard must not make worse)

- **Its own logs:** never write a matched value, request body or header value; only rule, location, host, method, path
  (with the query string dropped) and an HMAC of the value. Tested in F4.
- **The CA key:** generated in `~/.egressguard/ca/` (or `EGRESSGUARD_HOME`), never placed in a shared trust store. Anyone who
  can read that folder can impersonate hosts to processes started by `egressguard run`, and to no others.
- **Fail closed:** an exception in the addon blocks the request with a 403; if the proxy dies, the agent's proxied requests
  fail to connect rather than going direct. A body that needs redaction but is not text is blocked, not forwarded.
- **Fail open (stated):** clients that ignore the proxy variables go direct. This is the limit of a guidance-level tool.
- **Least privilege:** no admin rights, listens on 127.0.0.1 only, changes no system setting, no persistent environment
  variable. Upstream TLS is verified against public roots (plus `--extra-ca`); `ssl_insecure` is never set.
- **Passthrough is not inspection:** model hosts are not scanned. A secret in a prompt goes to the model provider as before.

## Dependencies

| Package | Licence | Why |
|---|---|---|
| `mitmproxy` 12.x | MIT | TLS-intercepting proxy engine. Pulls in ~40 packages (~89 MB with test clients, measured in the spike), including `mitmproxy-windows` (LGPL-3.0-or-later, Windows only) and `mitmproxy_rs` (no licence declared in its wheel metadata). Accepted by the user for v0.1. |
| `cryptography` | Apache-2.0 OR BSD-3-Clause | throwaway CA and certificates for `demo` and the tests (already a mitmproxy dependency) |
| `certifi` | MPL-2.0 | public roots added to the per-session CA bundle (already a mitmproxy dependency) |
| `ruamel.yaml` | MIT | policy file (already a mitmproxy dependency) |

Dev only: `pytest`, `ruff`, `mypy`. Python 3.12+ (mitmproxy 12 needs it; built and tested on 3.14 here).
