"""Julgamentos do Jev sobre grupos agregados. Regras de alerta ficam aqui, em código."""
import asyncio
from dataclasses import dataclass

from typesafe_sdk import AsyncTypeSafeClient, Choice, Noul, Score

# Limiares iniciais: calibrar com dados reais.
ALERT_SEVERITY = 2.0       # score esperado (0 a 3) a partir do qual há alerta
MIN_CONFIDENCE = 0.6       # confiança da severidade abaixo disso vai para revisão manual
ALERT_INTERNAL = 0.8       # probabilidade de anomalia interna que gera alerta
ALERT_SCAN = 0.9           # probabilidade de varredura que gera alerta (junto com a categoria)
ALERT_SCAN_CONF = 0.8      # confiança mínima da categoria "scan" para esse alerta
MAX_GROUPS = 100          # grupos mais volumosos enviados ao Jev
CONCURRENCY = 8

CONTEXT = (
    "Firewall de borda de um homelab. Política padrão: negar todo tráfego de entrada vindo da internet. "
    "Todo evento aqui é um bloqueio. Bloqueios de entrada vindos da internet são o ruído de fundo esperado; "
    "só importam quando mostram padrão: muitas portas ou destinos distintos, foco em serviço de autenticação, "
    "ou volume muito alto e sustentado. Uma única porta alta ou aleatória com poucos eventos é ruído. "
    "A LAN do homelab é 192.168.1.0/24 (`group.src_in_lan`). Cliente da LAN bloqueado ao acessar HTTPS ou outro serviço "
    "externo comum é, em geral, efeito de regra de filtragem de saída, não ataque: severidade baixa. "
    "Origem da LAN só é grave se varre muitas portas ou hosts internos, ou tenta serviços de administração."
)

CATEGORIES = {
    "scan": "Muitas portas distintas (dezenas) ou muitos destinos distintos pela mesma origem.",
    "brute_force": "Tentativas repetidas contra serviço de autenticação.",
    "internet_noise": "Ruído de fundo: poucas portas, um destino, poucos eventos, ou porta conhecida de serviço sem padrão de ataque.",
    "legitimate": "Tráfego esperado de rede doméstica bloqueado por engano ou regra.",
    "unknown": "Nenhuma das anteriores com clareza.",
}
SEVERITY = [
    "Ignorar: ruído de internet sem relação com serviços expostos.",
    "Baixa: sondagem isolada ou de baixo volume.",
    "Média: varredura ampla ou repetição persistente contra um serviço.",
    "Alta: ataque sustentado a serviço de autenticação, ou origem interna com comportamento hostil.",
]

QUESTIONS = {
    "scan": Noul(instructions="Considere `context`. O estado `group` mostra varredura de portas ou de hosts (muitas portas ou destinos distintos pela mesma origem)?"),
    "bruteforce": Noul(instructions="Considere `context`. O estado `group` mostra tentativas repetidas contra serviço de autenticação (SSH 22, RDP 3389, SMB 445, Telnet 23, VNC)?"),
    "internal_anomaly": Noul(instructions="Considere `context`. A origem está na LAN (`group.src_in_lan`) e se comporta como varredura da rede interna ou tentativa de administração remota, e não como cliente comum bloqueado por regra?"),
    "category": Choice(instructions="Considere `context`. Qual categoria descreve o tráfego bloqueado em `group`?", criteria=CATEGORIES),
    "severity": Score(instructions="Considere `context`. Qual a gravidade do tráfego em `group` para um homelab com firewall na borda?", criteria=SEVERITY),
}


@dataclass
class Verdict:
    group: object
    scan: float
    bruteforce: float
    internal_anomaly: float
    category: str
    category_conf: float
    severity: float
    severity_conf: float

    @property
    def uncertain(self) -> bool:
        return self.severity_conf < MIN_CONFIDENCE

    @property
    def alert(self) -> bool:
        if self.internal_anomaly >= ALERT_INTERNAL:
            return True
        if self.scan >= ALERT_SCAN and self.category == "scan" and self.category_conf >= ALERT_SCAN_CONF:
            return True
        return self.severity >= ALERT_SEVERITY and self.severity_conf >= MIN_CONFIDENCE


async def _judge_one(client, sem, group) -> Verdict:
    async with sem:
        r = await client.system_one(state={"context": CONTEXT, "group": group.state()}, questions=QUESTIONS)
    return Verdict(
        group,
        r.nouls["scan"].noul,
        r.nouls["bruteforce"].noul,
        r.nouls["internal_anomaly"].noul,
        r.choices["category"].choice,
        r.choices["category"].confidence,
        r.scores["severity"].score,
        r.scores["severity"].confidence,
    )


async def judge(groups: list) -> list[Verdict]:
    sem = asyncio.Semaphore(CONCURRENCY)
    async with AsyncTypeSafeClient() as client:
        return await asyncio.gather(*(_judge_one(client, sem, g) for g in groups[:MAX_GROUPS]))
