# Convenções

- O Jev só julga. Parsing, agregação, limiares e alertas ficam em código.
- Nunca enviar linhas cruas em massa ao Jev. Enviar só estado agregado.
- Limiares de confiança ficam como constantes no topo de `fwlog/judge.py`. Calibrar com dados reais.
- Log real nunca vai para o repositório. Amostras de teste são anonimizadas (IPs de documentação RFC 5737).
- Acesso ao log: `ssh ... sudo -n`, somente leitura. Nunca escrever no servidor de syslog.
- `TYPESAFE_API_KEY` só por variável de ambiente. Nunca gravar em arquivo.
- Estrutura segue o python-guide-pt-br: pacote `fwlog/` na raiz, sem `src/`.
