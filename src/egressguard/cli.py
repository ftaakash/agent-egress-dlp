"""Command line: `egressguard report`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .eventlog import default_log_path
from .report import report


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="egressguard",
        description="Redact or block secrets, PII and identity in coding agents' non-model HTTP traffic.",
    )
    p.add_argument("--version", action="version", version=f"egressguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("report", help="summarise the event log")
    r.add_argument("--log", type=Path, help="event log (default: ~/.egressguard/egress.jsonl)")
    r.add_argument("--last", action="store_true", help="only the most recent session")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "report":
        sys.stdout.write(report(args.log or default_log_path(), last_session=args.last))
        return 0
    return 2  # pragma: no cover - argparse rejects unknown commands


if __name__ == "__main__":
    sys.exit(main())
