# Later (not in v0.1)

Not built. Collected after the scope was frozen and from the risk spike.

- **Licence review of the mitmproxy tree** (user decision 2026-11-17: open for v0.2): `mitmproxy-windows` is
  LGPL-3.0-or-later; `mitmproxy_rs` declares no licence in its wheel metadata. Produce a full transitive licence
  list; decide whether a stdlib CONNECT + `ssl` proxy is worth the work.
- **CRL distribution point on the proxy CA**, served by the proxy, so Schannel curl and git need no relaxed
  revocation checking.
- **Merge the user's own curl config** into the per-session one instead of replacing it.
- **More real agents**: Codex, and Claude Code on Linux/macOS (Claude Code 2.1.330 on Windows 11 passed on 2026-11-26).
- **MCP over HTTP, HTTP/2, SSE/WebSocket and large or multipart bodies**: tests.
- **Per-request latency** added by the proxy (only start-up was timed in the spike: 0.77-0.80 s).
- **macOS** test run; CI on macOS.
- **PowerShell 5.1**: no per-process way was found to make `Invoke-WebRequest` use the proxy and trust its CA;
  document a wrapper or detect and warn.
- `egressguard run` could warn when the agent's environment already has a `NO_PROXY` it removes.
- **Log size**: `egressguard run` and `report` read the whole append-only log; add rotation or per-session counters once logs grow (code review, 2026-11-17).
- **Tell the agent about redactions** (real-agent run, 2026-11-26): Claude Code reported the email as "not flagged" because a redacted request still returns the upstream 200. Options: an `X-Egressguard: redacted rules=email` response header, or a stderr notice from `egressguard run`.
