from .context import fwlog  # noqa: F401
from fwlog.parse import parse_line

TCP = ("2026-10-13T16:38:10+00:00 fw.example filterlog[1]: 10,,,abc,pppoe1,match,block,in,4,0x0,,51,0,0,DF,"
       "6,tcp,48,203.0.113.7,198.51.100.1,1001,22,0,S,1,,32768,,mss")
IGMP = ("2026-10-13T16:38:10+00:00 fw.example filterlog[1]: 10,,,abc,vtnet1,match,block,in,4,0x0,,1,0,0,DF,"
        "2,igmp,32,192.168.1.1,224.0.0.1,datalength=8")


def test_tcp_ipv4():
    e = parse_line(TCP)
    assert (e.src, e.dst, e.proto, e.dport, e.action) == ("203.0.113.7", "198.51.100.1", "tcp", 22, "block")


def test_igmp_sem_porta_e_linha_malformada():
    assert parse_line(IGMP).dport is None
    assert parse_line("lixo sem formato") is None
    assert parse_line("2026-10-13T16:38:10+00:00 h filterlog[1]: 10,,,abc") is None
