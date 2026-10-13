"""Agrupa eventos por origem para reduzir o volume enviado ao Jev."""
import ipaddress
import os
from collections import Counter
from dataclasses import dataclass, field

from .parse import Event

TOP_PORTS = 10
LAN = ipaddress.ip_network("192.168.1.0/24")  # rede do homelab
# IPs próprios (ex.: WAN do roteador) via env, para não gravar IP real no repo.
IGNORED_SRC = {ip for ip in os.environ.get("FWLOG_IGNORE_SRC", "").split(",") if ip}
IGNORED_PROTOS = {"igmp"}  # multicast do gateway: ruído interno esperado
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 443: "https",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5900: "vnc", 6081: "geneve",
    8080: "http-alt", 51820: "wireguard",
}


@dataclass
class Group:
    src: str
    proto: str
    iface: str
    direction: str
    action: str
    count: int = 0
    first: str = ""
    last: str = ""
    dsts: set = field(default_factory=set)
    ports: Counter = field(default_factory=Counter)

    def state(self) -> dict:
        """Estado enviado ao Jev: só números agregados, sem linhas cruas."""
        return {
            "src": self.src,
            "src_in_lan": ipaddress.ip_address(self.src) in LAN,
            "proto": self.proto,
            "iface": self.iface,
            "direction": self.direction,
            "action": self.action,
            "events": self.count,
            "first_seen": self.first,
            "last_seen": self.last,
            "distinct_destinations": len(self.dsts),
            "distinct_dst_ports": len(self.ports),
            "top_dst_ports": dict(self.ports.most_common(TOP_PORTS)),
            "known_services": {p: SERVICES[p] for p in self.ports if p in SERVICES},
        }


def aggregate(events: list[Event]) -> list[Group]:
    groups: dict[tuple, Group] = {}
    for e in events:
        if e.proto in IGNORED_PROTOS or e.src in IGNORED_SRC:
            continue
        key = (e.src, e.proto, e.iface, e.direction, e.action)
        g = groups.get(key)
        if g is None:
            g = groups[key] = Group(e.src, e.proto, e.iface, e.direction, e.action)
        ts = e.ts.isoformat()
        g.first = g.first or ts
        g.last = ts
        g.count += 1
        g.dsts.add(e.dst)
        if e.dport is not None:
            g.ports[e.dport] += 1
    return sorted(groups.values(), key=lambda g: g.count, reverse=True)
