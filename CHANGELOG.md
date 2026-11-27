# Changelog

## Unreleased

- `egressguard report` is now an after-session digest: `--last` or `--session ID` shows what left the machine
  per host (forwarded, redacted, blocked, methods, paths), what was blocked or redacted per rule and where, and
  the passthrough hosts; without either it lists sessions, newest first, then the totals. `--format markdown`
  gives the same as Markdown tables. No matched values appear in it.
- `docs/spec.md` records the scope of 0.2, 0.3 and this change.

## 0.3.1 - 2026-11-27

Documentation only; no code changes.

- Licence review of all 42 runtime dependencies in `docs/licences.md`, summarised in the README: all
  permissive except four LGPL packages and MPL-2.0 files, none GPL-only. `mitmproxy_rs` and `mitmproxy-linux`,
  whose wheels declare no licence, are MIT upstream. This closes the licence question left open in 0.1.0.

## 0.3.0 - 2026-11-27

- Responses to redacted requests now carry `X-Egressguard: redacted; rules=...` (blocked ones carry
  `blocked; rules=...`), so an agent that reads headers can tell a value was removed. Found in the end-to-end
  run with Claude Code, where the agent took a redacted request's plain 200 to mean nothing was caught.
- `egressguard run` prints a live line in your terminal for every block and redaction (`--quiet` turns it off).
- `scripts/claude_code_e2e.py`: contained end-to-end check with a real Claude Code CLI.

## 0.2.0 - 2026-11-26

- A `.egressguard.yml` in the project directory may now only tighten the policy: weaker actions, allowlist
  entries, extra passthrough hosts, `.env` files outside the project and `secrets.environment: false` from it
  are ignored and named at start. Loosening comes only from `--policy FILE` or `~/.egressguard/config.yml`.
  Breaking: a project file that loosened the defaults in 0.1.0 must move to one of those two places.

## 0.1.0 - 2026-11-17

First release.

- `egressguard run -- <command>`: local intercepting proxy (mitmproxy) for one command and its children, with
  proxy and CA trust passed only through that process's environment (Python, curl incl. Windows Schannel, Node 24,
  git). Model-API hosts are tunnelled without decryption.
- Content rules: private keys, AWS, GitHub, Anthropic, OpenAI and Stripe key formats; registered secrets from
  `.env` and the environment; git email, any email, OS username. Checked in URL, headers and body.
- Actions `block` (403 naming the rule), `redact`, `log`; per-host allowlist; fails closed on inspection errors.
- Outbound WebSocket messages and non-HTTP data in intercepted connections are checked too; allowlist and
  passthrough decisions use the connection target, never the `Host` header.
- `.egressguard.yml` policy file with validation; settings that weaken the defaults are announced at start.
- JSONL event log with HMAC-hashed values; `egressguard report`.
- `egressguard demo`: the whole flow on local fake servers with fake values.
