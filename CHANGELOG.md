# Changelog

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
