from datetime import datetime, timezone

from .context import fwlog  # noqa: F401
from fwlog import aggregate as agg
from fwlog.parse import Event


def _ev(src, proto="tcp", dport=22):
    return Event(datetime.now(timezone.utc), "pppoe1", "block", "in", proto, src, "198.51.100.1", dport)


def test_agrupa_e_ignora_src_proprio(monkeypatch):
    monkeypatch.setattr(agg, "IGNORED_SRC", {"203.0.113.9"})
    groups = agg.aggregate([_ev("203.0.113.7", dport=22), _ev("203.0.113.7", dport=23), _ev("203.0.113.9")])
    assert len(groups) == 1 and groups[0].count == 2 and groups[0].state()["distinct_dst_ports"] == 2


def test_ignora_igmp():
    assert agg.aggregate([_ev("192.168.1.1", proto="igmp", dport=None)]) == []
