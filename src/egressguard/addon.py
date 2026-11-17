"""mitmproxy addon: inspect non-model requests and apply block / redact / log. Fails closed."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mitmproxy import ctx, http
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from .eventlog import EventLog
from .policy import Policy
from .rules import Finding, Scanner, redact

BLOCK_HEADER = "X-Egressguard"


def _block(flow: http.HTTPFlow, text: str) -> None:
    flow.response = http.Response.make(
        403,
        text.encode("utf-8"),
        {"Content-Type": "text/plain; charset=utf-8", BLOCK_HEADER: "blocked"},
    )


class EgressGuard:
    def __init__(
        self,
        policy: Policy,
        scanner: Scanner,
        log: EventLog,
        resolve: dict[str, tuple[str, int]],
        ready_file: Path | None = None,
    ) -> None:
        self.policy = policy
        self.scanner = scanner
        self.log = log
        self.resolve = {k.lower(): v for k, v in resolve.items()}
        self.ready_file = ready_file

    # mitmproxy hooks -------------------------------------------------------------------------------------

    def running(self) -> None:
        if self.ready_file is None:
            return
        ps = ctx.master.addons.get("proxyserver")
        addrs = ps.listen_addrs() if ps else []
        port = int(addrs[0][1]) if addrs else 0
        tmp = self.ready_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"port": port, "pid": os.getpid()}), encoding="utf-8")
        os.replace(tmp, self.ready_file)
        self.log.write("proxy_start", port=port, passthrough=list(self.policy.passthrough_hosts))

    def server_connect(self, data: ServerConnectionHookData) -> None:
        addr = data.server.address
        if not addr:
            return
        host, port = str(addr[0]).lower(), int(addr[1])
        if self.policy.is_passthrough(host):
            # Passthrough hosts never reach `request`; this is the only place they can be seen.
            self.log.write("passthrough", host=host, port=port)
        if host in self.resolve:
            data.server.address = self.resolve[host]

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            self._inspect(flow)
        except Exception as e:  # fail closed: never forward a request we could not inspect
            self.log.write("addon_error", host=flow.request.pretty_host, error=type(e).__name__)
            _block(flow, "egressguard: internal error, request blocked (fail closed)\n")

    # inspection ------------------------------------------------------------------------------------------

    def _active(self, host: str, findings: list[Finding]) -> list[Finding]:
        out = []
        for f in findings:
            if self.policy.allowed(host, f.rule):
                self._log_finding(f, "allow", host)
            else:
                out.append(f)
        return out

    def _log_finding(self, f: Finding, action: str, host: str, method: str = "") -> None:
        self.log.write(
            "finding",
            rule=f.rule,
            action=action,
            where=f.where,
            host=host,
            method=method,
            value=self.log.hash_value(f.value),
        )

    def _inspect(self, flow: http.HTTPFlow) -> None:
        req = flow.request
        host = req.pretty_host.lower()
        method = req.method
        text_ok = True
        try:
            body = req.get_text(strict=True) or ""
        except ValueError:
            text_ok = False
            body = (req.raw_content or b"").decode("latin-1")

        headers = list(req.headers.items(multi=True))
        findings = self._active(host, self.scanner.scan_request(req.path, headers, body))
        act = self.policy.actions

        url_findings = [f for f in findings if f.where == "url"]
        log_path = redact(req.path, url_findings).split("?", 1)[0]

        blocking = [f for f in findings if act[f.rule] == "block"]
        redacting = [f for f in findings if act[f.rule] == "redact"]
        not_text = not text_ok and any(f.where == "body" for f in redacting)

        for f in findings:
            self._log_finding(f, act[f.rule], host, method)

        if blocking or not_text:
            first = blocking[0] if blocking else next(f for f in redacting if f.where == "body")
            reason = (
                f"{first.rule} in {first.where}"
                if blocking
                else f"{first.rule} in a body that is not text and cannot be redacted"
            )
            self.log.write("request", host=host, method=method, path=log_path, outcome="blocked")
            _block(
                flow,
                f"egressguard: blocked request to {host}: {reason}. The value was not sent. "
                "Remove it from the request, or allow it for this host in .egressguard.yml.\n",
            )
            return

        if redacting:
            self._apply_redactions(flow, redacting, body)
        outcome = "redacted" if redacting else "forwarded"
        self.log.write("request", host=host, method=method, path=log_path, outcome=outcome)

    def _apply_redactions(self, flow: http.HTTPFlow, redacting: list[Finding], body: str) -> None:
        req = flow.request
        host = req.pretty_host.lower()
        url_f = [f for f in redacting if f.where == "url"]
        if url_f:
            req.path = redact(req.path, url_f)
        if any(f.where.startswith("header:") for f in redacting):
            for name in dict.fromkeys(k for k, _ in req.headers.items(multi=True)):
                values = req.headers.get_all(name)
                new_values = [self._redact_header(host, name, v) for v in values]
                if new_values != values:
                    req.headers.set_all(name, new_values)
        body_f = [f for f in redacting if f.where == "body"]
        if body_f:
            req.set_text(redact(body, body_f))

    def _redact_header(self, host: str, name: str, value: str) -> str:
        fs = [
            f
            for f in self.scanner.scan(value, f"header:{name}")
            if self.policy.actions[f.rule] == "redact" and not self.policy.allowed(host, f.rule)
        ]
        return redact(value, fs) if fs else value
