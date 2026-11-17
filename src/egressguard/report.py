"""`egressguard report`: a plain-text summary of the event log."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .eventlog import read_events


def summarise(events: list[dict[str, Any]], top: int = 10) -> str:
    if not events:
        return "no events in the log yet\n"
    requests = [e for e in events if e.get("event") == "request"]
    findings = [e for e in events if e.get("event") == "finding"]
    passthrough = [e for e in events if e.get("event") == "passthrough"]
    errors = [e for e in events if e.get("event") == "addon_error"]
    sessions = {e.get("session") for e in events}
    outcomes = Counter(str(e.get("outcome")) for e in requests)

    lines = [
        f"sessions: {len(sessions)}   requests inspected: {len(requests)}   "
        f"blocked: {outcomes['blocked']}   redacted: {outcomes['redacted']}   "
        f"passthrough connections: {len(passthrough)}",
        "",
        "Top hosts (requests inspected)",
    ]
    by_host = Counter(str(e.get("host")) for e in requests)
    host_outcomes: dict[str, Counter[str]] = {}
    for e in requests:
        host_outcomes.setdefault(str(e.get("host")), Counter())[str(e.get("outcome"))] += 1
    if not by_host:
        lines.append("  (none)")
    for host, n in by_host.most_common(top):
        oc = host_outcomes[host]
        detail = ", ".join(f"{oc[k]} {k}" for k in ("blocked", "redacted", "forwarded") if oc[k])
        lines.append(f"  {host:<40} {n:>5}   ({detail})")

    lines += ["", "Findings (rule, action, count)"]
    by_rule = Counter((str(e.get("rule")), str(e.get("action"))) for e in findings)
    if not by_rule:
        lines.append("  (none)")
    for (rule, action), n in sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"  {rule:<20} {action:<8} {n:>5}")

    lines += ["", "Passthrough connections (model hosts, not decrypted)"]
    by_pt = Counter(str(e.get("host")) for e in passthrough)
    if not by_pt:
        lines.append("  (none)")
    for host, n in by_pt.most_common(top):
        lines.append(f"  {host:<40} {n:>5}")

    if errors:
        lines += ["", f"Addon errors (requests blocked, fail closed): {len(errors)}"]
    return "\n".join(lines) + "\n"


def report(log_path: Path, last_session: bool = False) -> str:
    events = read_events(log_path)
    if last_session and events:
        last = events[-1].get("session")
        events = [e for e in events if e.get("session") == last]
    return f"egressguard report: {log_path}\n" + summarise(events)
