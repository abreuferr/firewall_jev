"""Relatório Markdown."""
from collections import Counter
from datetime import datetime, timezone

from .aggregate import Group
from .judge import Verdict


def _row(v: Verdict) -> str:
    g = v.group
    ports = ",".join(str(p) for p in list(g.ports)[:5]) or "-"
    return (f"| {g.src} | {g.proto} | {g.count} | {len(g.dsts)} | {ports} | {v.category} "
            f"({v.category_conf:.2f}) | {v.severity:.1f} ({v.severity_conf:.2f}) |")


def _table(verdicts: list[Verdict]) -> list[str]:
    head = ["| Origem | Proto | Eventos | Destinos | Portas | Categoria | Severidade |",
            "|---|---|---|---|---|---|---|"]
    return head + [_row(v) for v in verdicts] if verdicts else ["Nenhum."]


def build(total: int, dropped: int, groups: list[Group], verdicts: list[Verdict]) -> str:
    alerts = [v for v in verdicts if v.alert]
    review = [v for v in verdicts if v.uncertain and not v.alert]
    cats = Counter(v.category for v in verdicts)
    out = [
        f"# Relatório do firewall - {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", "",
        f"- Eventos analisados: {total}",
        f"- Linhas descartadas (não reconhecidas): {dropped}",
        f"- Grupos por origem: {len(groups)} (julgados pelo Jev: {len(verdicts)})",
        "- Categorias: " + (", ".join(f"{k}={n}" for k, n in cats.most_common()) or "-"), "",
        f"## Alertas ({len(alerts)})", *_table(alerts), "",
        f"## Revisão manual - baixa confiança ({len(review)})", *_table(review), "",
        "## Top origens por volume", *_table(verdicts[:10]),
    ]
    return "\n".join(out) + "\n"
