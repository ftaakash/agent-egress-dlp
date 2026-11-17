# Contributing

```
py -m venv .venv                       # Linux/macOS: python3 -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m ruff format --check .
.venv\Scripts\python -m ruff check .
.venv\Scripts\python -m mypy
.venv\Scripts\python -m pytest
```

The tests start the real proxy and local fake HTTPS servers on 127.0.0.1 with a throwaway CA. They need `curl`,
`node` (24+) and `git` on `PATH` for the client tests. They set `EGRESSGUARD_HOME` to a temporary folder, so they
do not touch `~/.egressguard`.

Test values must be fake: use the AWS documentation key `AKIAIOSFODNN7EXAMPLE`, `example.com` addresses, and
build other token-shaped strings at runtime (see `tests/test_rules.py`) so no key-shaped literal is committed.

Every feature comes with an acceptance test written first. The scope of each version is in `docs/spec.md`;
ideas for later go to `docs/later.md`.
