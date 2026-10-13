"""CLI: python -m fwlog [--file F | --ssh] [--since HORAS] [--out relatorio.md]"""
import argparse
import asyncio
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from .aggregate import aggregate
from .judge import judge
from .parse import parse_line
from .report import build

SSH_HOST = "cferreira@syslog.particula.local"
SSH_LOG = "/var/log/remote/OPNsense.particula.local/messages.log"


def read_lines(args) -> list[str]:
    if args.file:
        with open(args.file, errors="replace") as fh:
            return fh.read().splitlines()
    cmd = ["ssh", SSH_HOST, "sudo", "-n", "tail", "-n", str(args.lines), SSH_LOG]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.splitlines()


def main() -> int:
    p = argparse.ArgumentParser(prog="fwlog")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="arquivo de log local")
    src.add_argument("--ssh", action="store_true", help="ler do servidor de syslog via ssh + sudo -n")
    p.add_argument("--lines", type=int, default=100000, help="linhas finais lidas via ssh")
    p.add_argument("--since", type=float, default=24, help="janela em horas")
    p.add_argument("--out", default="relatorio.md")
    args = p.parse_args()

    lines = read_lines(args)
    events, dropped = [], 0
    for line in lines:
        e = parse_line(line)
        if e is None:
            dropped += 1
        else:
            events.append(e)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.since)
    events = [e for e in events if e.ts >= cutoff]

    groups = aggregate(events)
    verdicts = asyncio.run(judge(groups))
    report = build(len(events), dropped, groups, verdicts)
    with open(args.out, "w") as fh:
        fh.write(report)

    alerts = [v for v in verdicts if v.alert]
    for v in alerts:
        print(f"ALERTA: {v.group.src} {v.category} severidade={v.severity:.1f}", file=sys.stderr)
    print(f"Relatório em {args.out}")
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
