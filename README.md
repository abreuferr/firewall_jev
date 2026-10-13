# jev_ai

Analisa o log de firewall (OPNsense, filterlog) do homelab com o Jev, da TypeSafe.
Gera relatório em Markdown, classifica as origens bloqueadas e sinaliza alertas.

## Requisitos
- Python 3.11 ou mais novo.
- Variável de ambiente `TYPESAFE_API_KEY`.
- Para `--ssh`: acesso SSH a `cferreira@syslog.particula.local` e regra sudoers de leitura do log.

## Instalação
```
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

## Uso
```
python -m fwlog --ssh --since 24 --out relatorio.md
python -m fwlog --file amostra.log
```
Código de saída 1 quando há alerta, 0 caso contrário.

Para excluir origens próprias (por exemplo, o IP da WAN do roteador), use `FWLOG_IGNORE_SRC` com IPs separados por vírgula:
```
FWLOG_IGNORE_SRC=203.0.113.9 python -m fwlog --ssh
```

## Como funciona
1. Lê as linhas e extrai os eventos (`fwlog/parse.py`). Linhas não reconhecidas são contadas.
2. Agrupa por origem, protocolo, interface, direção e ação (`fwlog/aggregate.py`).
3. Envia ao Jev só o estado agregado de cada grupo (`fwlog/judge.py`): três perguntas sim/não (varredura, força bruta, anomalia interna), uma categoria e uma severidade de 0 a 3.
4. Regras em código decidem alerta e revisão manual. Os limiares ficam no topo de `fwlog/judge.py`.

## Testes
```
pytest tests
```
