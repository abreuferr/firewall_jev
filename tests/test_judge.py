import asyncio
import os

import pytest

from .context import fwlog  # noqa: F401
from fwlog.aggregate import Group
from fwlog.judge import judge

pytestmark = pytest.mark.skipif(not os.environ.get("TYPESAFE_API_KEY"), reason="precisa de TYPESAFE_API_KEY (chama a API)")


def _group(src, count, dsts, ports):
    g = Group(src, "tcp", "pppoe1", "in", "block", count=count, first="2026-10-13T10:00:00+00:00", last="2026-10-13T10:05:00+00:00")
    g.dsts = set(dsts)
    for p in ports:
        g.ports[p] += 1
    return g


def test_varredura_gera_alerta_e_ruido_nao():
    scan = _group("203.0.113.7", 1500, [f"198.51.100.{i}" for i in range(1, 60)], range(1000, 1300))
    noise = _group("203.0.113.8", 3, ["198.51.100.1"], [51234])
    v_scan, v_noise = asyncio.run(judge([scan, noise]))
    assert v_scan.alert
    assert not v_noise.alert
