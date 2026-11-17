# Changelog

## 0.1.0 - 2026-11-17

First release.

- `egressguard run -- <command>`: local intercepting proxy (mitmproxy) for one command and its children, with
  proxy and CA trust passed only through that process's environment (Python, curl incl. Windows Schannel, Node 24,
  git). Model-API hosts are tunnelled without decryption.
- Content rules: private keys, AWS, GitHub, Anthropic, OpenAI and Stripe key formats; registered secrets from
  `.env` and the environment; git email, any email, OS username. Checked in URL, headers and body.
- Actions `block` (403 naming the rule), `redact`, `log`; per-host allowlist; fails closed on inspection errors.
- `.egressguard.yml` policy file with validation.
- JSONL event log with HMAC-hashed values; `egressguard report`.
- `egressguard demo`: the whole flow on local fake servers with fake values.
