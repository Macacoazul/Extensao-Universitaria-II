# Ambiente experimental (máquinas simuladas e situações hipotéticas)

Usado para **demonstrar** a arquitetura e gerar as evidências do Checkpoint 4 sem
depender do Docker Desktop. Roda em qualquer Linux como root, inclusive no WSL2 Ubuntu.

```bash
sudo apt install -y suricata nginx openssh-server ulogd2 rsyslog nftables iptables iproute2 \
                    iputils-ping netcat-openbsd curl python3-requests python3-numpy
sudo ./simulacao/ambiente.sh up          # cria as máquinas simuladas e sobe os serviços
sudo ./simulacao/executar_testes.sh      # fases 1–5 e testes T1–T6 (~5 min)
sudo python3 simulacao/gerar_prints.py   # prints/ (requer playwright + markdown)
sudo ./simulacao/ambiente.sh down
```

| Componente | No ambiente experimental | Natureza |
|---|---|---|
| Firewall | os arquivos de `pfsense/firewall/` com o mesmo `entrypoint.sh`, no namespace `fw` | real |
| Server / Cliente | namespaces `srv` (nginx e sshd reais) e `cli`, com os IPs do projeto | real (máquinas simuladas) |
| Internet | namespace `inet` com o site fictício 198.51.100.10 (RFC 5737) | simulado |
| Suricata | Suricata 7 escutando `br-lab-lan`, com as regras de `regras-ambiente-experimental.rules` | real |
| SIEM | `emulador_siem.py`, que coleta os mesmos logs e grava `alerts.json` no formato do Wazuh com as regras locais do projeto e as regras padrão usadas nos testes (IDs, níveis e frequências do ruleset oficial v4.14) | emulado |
| ai-analyst | código de `ia/` sem alterações (sem Ollama, entra no modo de contingência) | real (sem LLM) |
| Testes 1, 2 e 6 | `hipoteticos.py` escreve registros de log equivalentes; nenhum ataque é executado | hipotético |
| Testes 3, 4 e 5 | executados de fato dentro do ambiente experimental | real |

Os resultados demonstram o funcionamento da arquitetura, mas não substituem a execução
no laboratório completo (`lab.ps1`, com Wazuh e Ollama reais).
