"""The proxy process: `python -m egressguard.proxy <session.json>`. Started by `egressguard run`."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from .eventlog import EventLog, egressguard_home
from .policy import Policy, load_policy
from .rules import Scanner
from .secrets import env_file_values, environment_values, git_email, os_username
from .session import SessionConfig


def ca_dir() -> Path:
    return egressguard_home() / "ca"


def build_scanner(policy: Policy, cwd: Path) -> Scanner:
    registered: list[str] = []
    for name in policy.env_files:
        p = Path(name)
        registered += env_file_values(p if p.is_absolute() else cwd / p)
    if policy.scan_environment:
        registered += environment_values(os.environ)
    return Scanner(registered=registered, git_email=git_email(cwd), os_username=os_username())


def _upstream_roots(cfg: SessionConfig) -> str | None:
    """With --extra-ca, the proxy must trust public roots plus the extra CAs (the option replaces certifi)."""
    if not cfg.extra_ca:
        return None
    import certifi

    out = Path(cfg.session_dir) / "upstream-roots.pem"
    parts = [Path(certifi.where()).read_text(encoding="utf-8")]
    parts += [Path(p).read_text(encoding="utf-8") for p in cfg.extra_ca]
    out.write_text("\n".join(parts), encoding="utf-8")
    return str(out)


async def serve(cfg: SessionConfig) -> None:
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    from .addon import EgressGuard

    policy = load_policy(Path(cfg.policy_path)) if cfg.policy_path else Policy.default()
    cwd = Path(cfg.cwd)
    log = EventLog(Path(cfg.log_path), session=cfg.session_id)
    ca_dir().mkdir(parents=True, exist_ok=True)

    opts = Options(listen_host="127.0.0.1", listen_port=0, confdir=str(ca_dir()))
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.options.update(
        ignore_hosts=[policy.ignore_hosts_regex()],
        connection_strategy="lazy",
        ssl_verify_upstream_trusted_ca=_upstream_roots(cfg),
    )
    master.addons.add(
        EgressGuard(policy, build_scanner(policy, cwd), log, cfg.resolve, ready_file=cfg.ready_file)
    )
    await master.run()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m egressguard.proxy <session.json>", file=sys.stderr)
        return 2
    asyncio.run(serve(SessionConfig.load(Path(args[0]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
