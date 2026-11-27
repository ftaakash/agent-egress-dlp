"""`egressguard report`: totals over the event log, or an after-session digest (text or Markdown)."""

from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass
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


NO_VALUES_NOTE = "This report and the log hold no matched values; the log keeps only keyed hashes of them."
MAX_PATHS = 5


def _by_session(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        out.setdefault(str(e.get("session")), []).append(e)
    return out


def _when(t: float | None) -> str:
    if t is None:
        return "?"
    return dt.datetime.fromtimestamp(t, dt.UTC).strftime("%Y-%m-%d %H:%M:%S")


def _duration(start: float | None, end: float | None) -> str:
    if start is None or end is None:
        return "?"
    s = max(0, int(round(end - start)))
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


@dataclass
class SessionStats:
    session: str
    start: float | None
    end: float | None
    inspected: int
    blocked: int
    redacted: int
    passthrough: int


def session_stats(session: str, events: list[dict[str, Any]]) -> SessionStats:
    times = [float(e["t"]) for e in events if isinstance(e.get("t"), int | float)]
    starts = [float(e["t"]) for e in events if e.get("event") == "proxy_start" and "t" in e]
    outcomes = Counter(str(e.get("outcome")) for e in events if e.get("event") == "request")
    return SessionStats(
        session=session,
        start=min(starts or times) if (starts or times) else None,
        end=max(times) if times else None,
        inspected=sum(outcomes.values()),
        blocked=outcomes["blocked"],
        redacted=outcomes["redacted"],
        passthrough=sum(1 for e in events if e.get("event") == "passthrough"),
    )


def _md(cell: object) -> str:
    """A Markdown table cell: pipes escaped, no line breaks."""
    return str(cell).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _table(fmt: str, header: list[str], rows: list[list[object]], widths: list[int]) -> list[str]:
    if fmt == "markdown":
        out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
        out += ["| " + " | ".join(_md(c) for c in r) + " |" for r in rows]
        return out

    def line(cells: list[object]) -> str:
        parts = []
        for c, w in zip(cells, widths, strict=True):
            parts.append(f"{c!s:>{-w}}" if w < 0 else f"{c!s:<{w}}")
        return "  " + "  ".join(parts).rstrip()

    return [line(list(header)), *(line(r) for r in rows)] if rows else ["  (none)"]


def digest(session: str, events: list[dict[str, Any]], fmt: str = "text") -> str:
    """After-session digest: what left the machine, what was blocked or redacted, what passed through."""
    st = session_stats(session, events)
    md = fmt == "markdown"
    h1 = f"# egressguard session {session}" if md else f"egressguard session {session}"
    bullet = "- " if md else "  "
    lines = [
        h1,
        "",
        f"{bullet}Started {_when(st.start)} UTC, ended {_when(st.end)} UTC ({_duration(st.start, st.end)})",
        f"{bullet}Requests inspected: {st.inspected}, blocked: {st.blocked}, redacted: {st.redacted}, "
        f"passthrough connections: {st.passthrough}",
    ]

    def section(title: str) -> None:
        lines.extend(["", f"## {title}" if md else title, *([""] if md else [])])

    # 1. What left the machine, by host
    section("What left the machine")
    hosts: dict[str, dict[str, Any]] = {}
    for e in events:
        if e.get("event") != "request":
            continue
        h = hosts.setdefault(str(e.get("host")), {"oc": Counter(), "methods": [], "paths": []})
        h["oc"][str(e.get("outcome"))] += 1
        if e.get("method") and e["method"] not in h["methods"]:
            h["methods"].append(str(e["method"]))
        if e.get("path") and e["path"] not in h["paths"]:
            h["paths"].append(str(e["path"]))
    rows: list[list[object]] = []
    for host, h in sorted(hosts.items(), key=lambda kv: -sum(kv[1]["oc"].values())):
        paths = h["paths"][:MAX_PATHS]
        more = len(h["paths"]) - len(paths)
        rows.append([
            host, h["oc"]["forwarded"], h["oc"]["redacted"], h["oc"]["blocked"],
            ", ".join(h["methods"]) or "-",
            ", ".join(paths) + (f" (+{more} more)" if more else "") or "-",
        ])  # fmt: skip
    lines += _table(
        fmt, ["Host", "Forwarded", "Redacted", "Blocked (not sent)", "Methods", "Paths"], rows,
        [40, -9, -8, -18, 12, 0],
    )  # fmt: skip

    # 2. Findings by rule
    section("Blocked and redacted, by rule")
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for e in events:
        if e.get("event") != "finding":
            continue
        g = groups.setdefault(
            (str(e.get("rule")), str(e.get("action")), str(e.get("where"))), {"n": 0, "hosts": []}
        )
        g["n"] += 1
        if e.get("host") not in g["hosts"]:
            g["hosts"].append(str(e.get("host")))
    rows = [
        [rule, action, where, ", ".join(g["hosts"]), g["n"]]
        for (rule, action, where), g in sorted(groups.items(), key=lambda kv: (-kv[1]["n"], kv[0]))
    ]
    lines += _table(fmt, ["Rule", "Action", "Where", "Hosts", "Count"], rows, [20, 8, 24, 30, -5])

    # 3. Passthrough
    section("Passthrough (model API hosts, not decrypted)")
    pt = Counter(str(e.get("host")) for e in events if e.get("event") == "passthrough")
    lines += _table(fmt, ["Host", "Connections"], [[h, n] for h, n in pt.most_common()], [40, -11])

    # 4. Errors
    errors = [e for e in events if e.get("event") in ("addon_error", "tcp_blocked")]
    if errors:
        section("Errors")
        rows = [
            [str(e.get("host")), "request blocked after an internal error (fail closed)"
             if e.get("event") == "addon_error" else "non-HTTP connection closed (a value matched a rule)"]
            for e in errors
        ]  # fmt: skip
        lines += _table(fmt, ["Host", "What happened"], rows, [40, 0])

    lines += ["", f"_{NO_VALUES_NOTE}_" if md else NO_VALUES_NOTE]
    return "\n".join(lines) + "\n"


def session_list(events: list[dict[str, Any]], fmt: str = "text") -> str:
    stats = [session_stats(s, evs) for s, evs in _by_session(events).items()]
    stats.sort(key=lambda s: s.start or 0, reverse=True)
    title = "## Sessions (newest first)" if fmt == "markdown" else "Sessions (newest first)"
    rows: list[list[object]] = [
        [
            s.session,
            _when(s.start),
            _duration(s.start, s.end),
            s.inspected,
            s.blocked,
            s.redacted,
            s.passthrough,
        ]
        for s in stats
    ]
    table = _table(
        fmt, ["Session", "Started (UTC)", "Duration", "Inspected", "Blocked", "Redacted", "Passthrough"],
        rows, [10, 19, 8, -9, -7, -8, -11],
    )  # fmt: skip
    return "\n".join([title, *([""] if fmt == "markdown" else []), *table]) + "\n"


def render(
    log_path: Path, *, last_session: bool = False, session: str | None = None, fmt: str = "text"
) -> tuple[int, str]:
    """Text for `egressguard report` and its exit code (1 when the requested session is not in the log)."""
    events = read_events(log_path)
    if not events:
        return 0, "no events in the log yet\n"
    if last_session or session:
        wanted = session or str(events[-1].get("session"))
        evs = [e for e in events if str(e.get("session")) == wanted]
        if not evs:
            return 1, f"no session {wanted} in {log_path}\n"
        return 0, digest(wanted, evs, fmt)
    body = summarise(events)
    totals = f"## Totals\n\n```\n{body}```\n" if fmt == "markdown" else f"Totals\n{body}"
    return 0, f"egressguard report: {log_path}\n\n" + session_list(events, fmt) + "\n" + totals


def report(log_path: Path, last_session: bool = False) -> str:
    """Plain-text report (used by the demo and the end-to-end script)."""
    return render(log_path, last_session=last_session)[1]
