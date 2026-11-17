"""Command line: `egressguard run`, `egressguard report`, `egressguard demo`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .eventlog import default_log_path
from .policy import PolicyError, find_policy, load_policy
from .report import report


def _resolve_arg(value: str) -> tuple[str, tuple[str, int]]:
    try:
        host, addr = value.split("=", 1)
        ip, port = addr.rsplit(":", 1)
        return host.strip().lower(), (ip.strip(), int(port))
    except ValueError:
        raise argparse.ArgumentTypeError(f"expected HOST=IP:PORT, got {value!r}") from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="egressguard",
        description="Redact or block secrets, PII and identity in coding agents' non-model HTTP traffic.",
    )
    p.add_argument("--version", action="version", version=f"egressguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser(
        "run",
        help="run a command (your agent) behind the proxy",
        description="Run COMMAND with proxy and CA trust set for it and its children only.",
    )
    run.add_argument("--policy", type=Path, help="policy file (default: ./.egressguard.yml if present)")
    run.add_argument("--log", type=Path, help="event log (default: ~/.egressguard/egress.jsonl)")
    run.add_argument(
        "--extra-ca",
        type=Path,
        action="append",
        default=[],
        metavar="PEM",
        help="extra CA to trust for upstream servers and in the agent (e.g. a corporate CA); repeatable",
    )
    run.add_argument(
        "--resolve",
        type=_resolve_arg,
        action="append",
        default=[],
        metavar="HOST=IP:PORT",
        help="connect to HOST at IP:PORT instead (for local test servers, like curl --resolve); repeatable",
    )
    run.add_argument("cmd", nargs=argparse.REMAINDER, metavar="-- COMMAND [ARGS...]")

    r = sub.add_parser("report", help="summarise the event log")
    r.add_argument("--log", type=Path, help="event log (default: ~/.egressguard/egress.jsonl)")
    r.add_argument("--last", action="store_true", help="only the most recent session")

    sub.add_parser("demo", help="run the local demo (fake servers, fake values, no network)")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "run":
        return _run(parser, args)
    if args.command == "report":
        sys.stdout.write(report(args.log or default_log_path(), last_session=args.last))
        return 0
    if args.command == "demo":
        from .demo import demo

        return demo()
    return 2  # pragma: no cover - argparse rejects unknown commands


def _run(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    from .runner import ProxyStartError, run

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("run: give the command after --, e.g. egressguard run -- claude")
    cwd = Path.cwd()
    policy_path = args.policy or find_policy(cwd)
    if policy_path is not None:
        try:
            load_policy(policy_path)  # validate before starting anything
        except PolicyError as e:
            print(f"egressguard: {e}", file=sys.stderr)
            return 2
    for ca in args.extra_ca:
        if not ca.is_file():
            print(f"egressguard: --extra-ca file not found: {ca}", file=sys.stderr)
            return 2
    try:
        return run(
            cmd,
            policy_path=policy_path.resolve() if policy_path else None,
            log_path=(args.log or default_log_path()).resolve(),
            extra_ca=[p.resolve() for p in args.extra_ca],
            resolve=dict(args.resolve),
            cwd=cwd,
        )
    except ProxyStartError as e:
        print(f"egressguard: {e}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
