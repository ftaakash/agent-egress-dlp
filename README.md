# egressguard

[![ci](https://github.com/ftaakash/agent-egress-dlp/actions/workflows/ci.yml/badge.svg)](https://github.com/ftaakash/agent-egress-dlp/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/ftaakash/agent-egress-dlp)](https://github.com/ftaakash/agent-egress-dlp/releases)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

A local proxy for developers who run coding agents (Claude Code, Codex and the like): it redacts or blocks
secrets, PII and your own identity in the agent's **non-model** HTTP traffic (web fetches, `curl`, MCP over HTTP)
before it leaves your machine, and passes model-API traffic through without decrypting it.

```
egressguard run -- claude
```

**Status:** v0.1.0, an early release. It is tested against local fake servers on Windows and Linux, not yet end
to end with a real agent. If you try it in front of one, please [tell me what happened](#feedback-wanted).

## The problem

Model-side redaction proxies only see the prompt. The agent also makes its own requests, and those carry data too:

- Claude Code put the user's email address in the `User-Agent` of its web requests
  ([anthropics/claude-code#107757](https://github.com/anthropics/claude-code/issues/107757)).
- Codex users ask for a local pre-submit DLP layer for secrets
  ([openai/codex#25585](https://github.com/openai/codex/issues/25585)).
- Teams worry about what their agents send without being asked
  ([HN: "OpenAI seems to be silently re-enabling model training on Codex chats"](https://news.ycombinator.com/item?id=50352757)).

## Quickstart

Needs Python 3.12+ and git. No account, no API key, no network access for the demo.

Windows:

```
git clone https://github.com/ftaakash/agent-egress-dlp
cd agent-egress-dlp
py -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\egressguard demo
```

Linux / macOS: the same, with `python3 -m venv .venv`, `.venv/bin/python -m pip install .` and `.venv/bin/egressguard demo`.

Then put your agent behind it:

```
egressguard run -- claude
egressguard report --last
```

## Demo output

`egressguard demo` starts two local HTTPS servers with a throwaway CA (`tools.example.test` as a third-party
site, `api.model.test` as the model API), runs a stand-in agent through `egressguard run` with Python, curl and
Node, then shows what the servers received. Real output from Windows 11 (full run in [docs/demo.txt](docs/demo.txt)):

```
== 1. What the agent saw (egressguard run -- python -m egressguard.demo_agent all)
  [python] POST tools  body has an AWS key                       -> 403 egressguard: blocked request to tools.example.test: aws_access_key in body
  [python] GET  tools  email in User-Agent                       -> 200 {"ok": true, "server": "tools.example.test"}
  [python] GET  tools  $DEMO_API_TOKEN in URL                    -> 403 egressguard: blocked request to tools.example.test: registered_secret in url
  [python] POST model  prompt (trusts ONLY the real server's CA) -> 200 {"ok": true, "server": "api.model.test"}
  [curl]   POST tools  body has an AWS key                       -> 403 egressguard: blocked request to tools.example.test: aws_access_key in body
  [curl]   GET  tools  email in User-Agent                       -> 200 {"ok": true, "server": "tools.example.test"}
  [curl]   POST model  prompt (trusts ONLY the real server's CA) -> 200 {"ok": true, "server": "api.model.test"}
  [node]   POST tools  body has an AWS key                       -> 403 egressguard: blocked request to tools.example.test: aws_access_key in body
  [node]   GET  tools  email in User-Agent                       -> 200 {"ok": true, "server": "tools.example.test"}

== 2. What the servers actually received
  tools.example.test   GET  /fetch?q=docs            User-Agent: demo-agent/1.0 ([REDACTED:email])
  api.model.test       POST /v1/messages             body: {"prompt": "my key is AKIAIOSFODNN7EXAMPLE, mail dev.user@example.com"
  ...
  -> 3 requests reached tools.example.test, none with the AWS key or the token; 2 reached api.model.test unchanged.
```

The model-host lines are the passthrough proof: those clients trust only the fake server's own CA, so a 200
means egressguard did not present its own certificate, so it did not decrypt the connection. All values are
fake (the AWS documentation example key and an `example.com` address).

## How it works

```
 agent process tree                      egressguard
 ┌───────────────┐  HTTPS_PROXY  ┌───────────────────────────────┐        ┌───────────────────┐
 │ claude / curl │──────────────▶│ mitmproxy + egressguard addon │──TLS──▶│ third-party hosts │
 │ node / python │               │ 127.0.0.1:<free port>         │        └───────────────────┘
 └───────────────┘               │ model hosts: tunnelled as-is  │──TCP tunnel, not decrypted──▶ model API
                                 └───────────────┬───────────────┘
                                                 ▼
                                 ~/.egressguard/egress.jsonl (values stored as keyed hashes)
```

`egressguard run` starts the proxy on a free local port and runs your command with proxy and CA settings in
**that process's environment only**:

- `HTTPS_PROXY` / `HTTP_PROXY`;
- a CA bundle with the proxy CA **plus** the public roots in `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and
  `CURL_CA_BUNDLE` (these variables replace the trust store, so the public roots must be in the bundle);
- `NODE_EXTRA_CA_CERTS` and `NODE_USE_ENV_PROXY=1` (Node 24 fetch ignores `HTTPS_PROXY` without it);
- a per-session curl config through `CURL_HOME` (Windows' Schannel curl ignores `CURL_CA_BUNDLE`);
- per-process git settings (`GIT_CONFIG_COUNT`), which also cover Git for Windows with Schannel.

It changes no system proxy, trust store, firewall rule or persistent environment variable. When the command
exits, the proxy is stopped and the session files are deleted. The proxy CA lives in `~/.egressguard/ca/`
(or `$EGRESSGUARD_HOME`) and is trusted only by processes started through `egressguard run`.

For each request to a non-model host, the addon scans the URL, headers and body:

| Rule | Matches | Default action |
|---|---|---|
| `private_key`, `aws_access_key`, `github_token`, `anthropic_key`, `openai_key`, `stripe_key` | known key formats | block |
| `registered_secret` | exact values from `.env` and from environment variables named like `*_TOKEN`, `*_SECRET`, `*_API_KEY`, `*_PASSWORD` (also URL-encoded) | block |
| `git_email` | your `git config user.email` | redact |
| `email` | any email address | redact |
| `os_username` | your OS account name (skipped for generic names such as `admin` or `runner`) | redact |

`block` answers with a 403 whose text names the rule, so the agent can see why and recover. `redact` replaces
the value with `[REDACTED:<rule>]`. `log` lets it through and records it. A blocked request never opens a
connection to the destination (`connection_strategy=lazy`). If inspection itself fails, or a value that should
be redacted sits in a body that is not text, the request is blocked. Hosts for the allowlist and the passthrough
list are taken from the connection target, never from the `Host` header. Outbound WebSocket messages are checked
too (block drops the message, redact rewrites it); other non-HTTP data inside an intercepted connection is
checked, and any block or redact finding closes the connection.

### Policy file

Policies use one format, from three places:

| Where | Trusted? | What it can do |
|---|---|---|
| `--policy FILE` | yes | anything; used alone, a `.egressguard.yml` in the project is then not read |
| `~/.egressguard/config.yml` (your own config) | yes | anything |
| `.egressguard.yml` in the directory you run from | no: it can arrive with a cloned repository | only tighten: stricter actions, removing passthrough hosts, extra `.env` files inside the project |

Without the first two, the built-in defaults are the trusted base. A repository's file cannot set a rule to a
weaker action, add allowlist entries or passthrough hosts, read `.env` files outside the project, or turn off
`secrets.environment`; each ignored setting is named when `egressguard run` starts. The format:

```yaml
rules:                     # change any rule's action: block, redact or log
  email: log
passthrough_hosts:         # model APIs: tunnelled, never decrypted (this list replaces the default)
  - api.anthropic.com
  - api.openai.com
  - generativelanguage.googleapis.com
allow:                     # hosts that may receive values of given rules
  - host: api.mycompany.com
    rules: [registered_secret]
secrets:
  env_files: [.env]        # files whose values are registered secrets
  environment: true        # also register secret-looking environment variables
```

An unknown key, rule or action in any of the files stops `egressguard run` with exit code 2 before anything
starts. When your trusted policy is looser than the defaults, `egressguard run` says how at start.

### Log and report

Events go to `~/.egressguard/egress.jsonl` (or `--log`). A matched value is stored only as an HMAC-SHA256 prefix
with a random per-install key, never in clear; paths are logged without the query string.
`egressguard report [--last]` prints top hosts, findings per rule and action (findings inside a blocked request
show as `dropped`), and passthrough connections.

## What it does not do

- **It is not enforcement.** Anything that ignores `HTTPS_PROXY` goes around it. Known on Windows: PowerShell 5.1
  `Invoke-WebRequest` ignores `HTTPS_PROXY` (it went direct in testing); `curl -q` skips the curl config;
  Node before 24, or libraries that build their own HTTP agent, may ignore the proxy variables. Clients that pin
  certificates fail rather than leak.
- It does not scan model traffic. A secret in a prompt reaches the model provider as before.
- `NO_PROXY` is removed for the agent, so local services the agent calls over HTTP also go through the proxy.
- The per-session curl config replaces your own `~/.curlrc` for that session, and turns Schannel's revocation
  check to best effort (the proxy CA has no revocation endpoint).
- Regex and exact-match detection only: encoded, split or unregistered secrets that do not look like a known
  format are missed.
- Tested against local fake servers only: 70 tests in CI on Ubuntu and Windows with Python 3.12 and 3.14, and
  locally on Windows 11 with Python 3.14, Schannel curl 8.18 and 8.22, Node 24 and Git for Windows 2.53
  (Schannel). Not yet tested: real agents end to end, MCP servers, HTTP/2, streaming, real WebSocket traffic
  (the WebSocket and raw-TCP checks have unit tests only), macOS.

## Dependencies and licences

egressguard is MIT licensed. Its direct dependencies are `mitmproxy` (MIT), `cryptography`
(Apache-2.0 OR BSD-3-Clause), `certifi` (MPL-2.0) and `ruamel.yaml` (MIT). mitmproxy is heavy: it brings about
40 packages, including `mitmproxy-windows` (LGPL-3.0-or-later, Windows only) and `mitmproxy_rs`, whose wheel
metadata declares no licence. These were accepted for v0.1; the licence review is open for v0.2
(see [docs/later.md](docs/later.md)).

## How it differs from nearby tools

| Tool | What its own README says | Difference |
|---|---|---|
| [Ficta](https://github.com/SerovaAI/ficta) | redaction proxy for model traffic; does not catch what the agent sends itself via `curl`, MCP tools or other non-model traffic | that non-model traffic is egressguard's whole scope |
| [Veil (PAIArtCom)](https://github.com/PAIArtCom/Veil) | masks secrets and PII before provider egress and restores them locally; remote MCP egress classification listed as not yet supported | egressguard leaves model traffic alone and inspects the agent's own requests |
| [veil (lemonadesaltbagel)](https://github.com/lemonadesaltbagel/veil) | replaces names, emails and secrets with pseudonyms in what the model sees, and swaps them back locally | model-side and reversible; egressguard works on outbound tool traffic |
| [ExfilGuard](https://github.com/laurikari/exfilguard) | egress proxy with TLS inspection and destination/method rules; forwards bodies without interpreting their content | egressguard decides by content, not destination |

## Roadmap

See [docs/later.md](docs/later.md). Next up:

- tests in front of real agents (Claude Code, Codex) and real MCP servers over HTTP;
- licence review of the mitmproxy dependency tree;
- a CRL endpoint for the proxy CA, and merging your own curl config instead of replacing it;
- macOS.

## Feedback wanted

The most useful report right now: you ran `egressguard run -- <your agent>` and it caught something, missed
something, or broke something. Please [open an issue](https://github.com/ftaakash/agent-egress-dlp/issues/new)
with the agent and its version, your OS, what you expected, and the output of `egressguard report --last`. The
report holds no matched values, only rule names, counts, host names and the log file's path; remove the path and
any host names you would rather not share.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE)
