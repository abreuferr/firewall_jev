"""Converte linhas syslog do filterlog (OPNsense) em Event."""
import re
from dataclasses import dataclass
from datetime import datetime

LINE_RE = re.compile(r"^(\S+) \S+ filterlog\[\d+\]: (.+)$")


@dataclass(frozen=True)
class Event:
    ts: datetime
    iface: str
    action: str
    direction: str
    proto: str
    src: str
    dst: str
    dport: int | None


def parse_line(line: str) -> Event | None:
    """Retorna None se a linha não for um filterlog IPv4/IPv6 reconhecido."""
    m = LINE_RE.match(line.strip())
    if not m:
        return None
    f = m.group(2).split(",")
    try:
        ts = datetime.fromisoformat(m.group(1))
        iface, action, direction, ipver = f[4], f[6], f[7], f[8]
        if ipver == "4":
            proto, src, dst, rest = f[16], f[18], f[19], f[20:]
        elif ipver == "6":
            proto, src, dst, rest = f[12], f[15], f[16], f[17:]
        else:
            return None
        has_ports = proto in ("tcp", "udp") and len(rest) >= 2
        dport = int(rest[1]) if has_ports else None
    except (IndexError, ValueError):
        return None
    return Event(ts, iface, action, direction, proto, src, dst, dport)
