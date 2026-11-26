"""mitmproxy addon: inspect non-model requests and apply block / redact / log. Fails closed."""

from __future__ import annotations

import json
import os
from pathlib import Path

from mitmproxy import ctx, http, tcp
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from .eventlog import EventLog
from .policy import Policy
from .rules import Finding, Scanner, redact

# Response header that tells the client what egressguard did to its request. Never sent upstream.
NOTICE_HEADER = "X-Egressguard"
BLOCK_HEADER = NOTICE_HEADER  # name kept for compatibility
_REDACTED_KEY = "egressguard_redacted"


def _block(flow: http.HTTPFlow, text: str, notice: str = "blocked") -> None:
    flow.response = http.Response.make(
        403,
        text.encode("utf-8"),
        {"Content-Type": "text/plain; charset=utf-8", NOTICE_HEADER: notice},
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
        self._unresolve = {v: k for k, v in self.resolve.items()}
        self.ready_file = ready_file

    def target_host(self, flow: http.HTTPFlow | tcp.TCPFlow) -> str:
        """The host the connection really goes to. Never the Host header, which the client controls."""
        addr = flow.server_conn.address
        if addr:
            key = (str(addr[0]), int(addr[1]))
            return self._unresolve.get(key, key[0]).lower()
        if isinstance(flow, http.HTTPFlow):
            return flow.request.host.lower()
        return ""

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
            self.log.write("addon_error", host=flow.request.host, error=type(e).__name__)
            _block(
                flow, "egressguard: internal error, request blocked (fail closed)\n", "blocked; reason=error"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        """Tell the client a request was redacted: a 200 alone would look as if nothing happened."""
        rules = flow.metadata.get(_REDACTED_KEY)
        if rules and flow.response is not None:
            flow.response.headers[NOTICE_HEADER] = f"redacted; rules={','.join(rules)}"

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Outbound WebSocket messages: block drops the message, redact rewrites a text message."""
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        if not msg.from_client:
            return
        try:
            host = self.target_host(flow)
            if self.policy.is_passthrough(host):
                return
            text = msg.text if msg.is_text else msg.content.decode("latin-1")
            findings = self._active(host, self.scanner.scan(text, "websocket"))
            act = self.policy.actions
            for f in findings:
                self._log_finding(f, act[f.rule], host, "WS")
            if any(act[f.rule] == "block" for f in findings):
                msg.drop()
            elif any(act[f.rule] == "redact" for f in findings):
                if msg.is_text:
                    msg.text = redact(text, [f for f in findings if act[f.rule] == "redact"])
                else:
                    msg.drop()
        except Exception as e:  # fail closed
            self.log.write("addon_error", host=flow.request.host, error=type(e).__name__)
            msg.drop()

    def tcp_message(self, flow: tcp.TCPFlow) -> None:
        """Non-HTTP data inside an intercepted connection. A raw stream cannot be rewritten safely, so any
        block or redact finding kills the connection."""
        msg = flow.messages[-1]
        if not msg.from_client:
            return
        host = ""
        try:
            host = self.target_host(flow)
            if self.policy.is_passthrough(host):
                return
            findings = self._active(host, self.scanner.scan(msg.content.decode("latin-1"), "tcp"))
            act = self.policy.actions
            for f in findings:
                self._log_finding(f, act[f.rule], host, "TCP")
            if any(act[f.rule] in ("block", "redact") for f in findings):
                self.log.write("tcp_blocked", host=host)
                flow.kill()
        except Exception as e:  # fail closed
            self.log.write("addon_error", host=host, error=type(e).__name__)
            if flow.killable:
                flow.kill()

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
        host = self.target_host(flow)
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

        if blocking or not_text:
            # Nothing of a blocked request is sent: findings that would only be redacted or logged are
            # recorded as "dropped" so the report does not count them as redactions.
            for f in findings:
                action = act[f.rule] if f in blocking else "dropped"
                if not blocking and f.where == "body" and act[f.rule] == "redact":
                    action = "block"
                self._log_finding(f, action, host, method)
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
                f"blocked; rules={','.join(sorted({f.rule for f in blocking} or {first.rule}))}",
            )
            return

        for f in findings:
            self._log_finding(f, act[f.rule], host, method)
        if redacting:
            self._apply_redactions(flow, redacting, body)
            flow.metadata[_REDACTED_KEY] = sorted({f.rule for f in redacting})
        outcome = "redacted" if redacting else "forwarded"
        self.log.write("request", host=host, method=method, path=log_path, outcome=outcome)

    def _apply_redactions(self, flow: http.HTTPFlow, redacting: list[Finding], body: str) -> None:
        req = flow.request
        host = self.target_host(flow)
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
