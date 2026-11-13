# PROGRESSO — Laboratório SOC

Atualizado em: 2026-11-12 23:25

## Etapas

| Fase | Situação | Evidência |
|---|---|---|
| 0. Leitura dos Checkpoints e resumo | concluída | resumo enviado no chat |
| Implementação (compose, configs, IA, scripts) | concluída | este repositório |
| Diagnóstico do host (Windows) | pendente: rodar `scripts/00-diagnostico.ps1` | `diagnostico/diagnostico.txt` |
| **Ambiente experimental** (máquinas simuladas + situações hipotéticas) | **concluído em 12/11/2026, 22:53–22:58** | `simulacao/`, `testes/`, `prints/` |
| 1. Infra base | demonstrada no ambiente experimental | `testes/saidas/01_fase1_infra.txt` |
| 2. Firewall | demonstrada no ambiente experimental | `testes/saidas/02_fase2_firewall.txt` |
| 3. Sensor Suricata | demonstrada (Suricata real na bridge da LAN) | `testes/saidas/03_fase3_ids_siem.txt` |
| 4. SIEM | demonstrada com o emulador do SIEM; Wazuh real pendente no host | idem |
| 5. IA | ai-analyst real, em modo de contingência (sem Ollama no ambiente) | `ia/saude.md`, `ia/recomendacoes.md` |
| 6. Testes 1–6 | concluídos no ambiente experimental (1, 2 e 6 hipotéticos) | `testes/T1.md` … `testes/T6.md` |
| 7. Prints | 32 capturas | `prints/` |
| 8. Checkpoint 4 | gerado | `relatorio/Checkpoint4.docx` e `.pdf` |
| Publicação no GitHub | concluída em 12/11/2026 | https://github.com/Macacoazul/Extensao-Universitaria-II |
| Laboratório completo no Docker Desktop | pendente (rodar `lab.ps1`) | — |

## Resultado do ambiente experimental

- 85 alertas no formato do Wazuh e 9 incidentes analisados pela IA.
- T2: a IA recomendou o bloqueio, sem aplicar, porque era a 1ª ocorrência.
- T6: a IA detectou a reincidência e aplicou o bloqueio no firewall (blocklist) e no
  servidor (iptables via active response). A aplicação foi verificada com curl.
- O LLM não rodou no ambiente experimental; as análises usaram playbooks de contingência.

## Decisões

1. **Rede:** os Checkpoints e a pasta não trazem topologia nem IPs. Por isso valem os
   padrões do prompt: WAN 172.20.0.0/24, LAN 192.168.10.0/24 e gerência 172.30.0.0/24.
2. **Firewall:** opção (c), container nftables replicando as regras do pfSense. O host é
   Windows e o KVM dentro do Docker ainda vai ser confirmado no diagnóstico. Com VirtualBox,
   a VM não alcançaria as redes do Docker Desktop. Detalhes em `pfsense/README.md`.
3. **Sensor:** Suricata na bridge `br-lab-lan` (modo promíscuo, rede do host), não no
   namespace do firewall. O tráfego Cliente↔Server não passa pelo firewall.
4. **Wazuh:** single-node oficial v4.14.10, com portas publicadas só em 127.0.0.1. O
   dashboard fica em 8443, porque a 443 pode estar ocupada.
5. **Resposta a incidentes:** bloqueio em dois pontos.
   - Blocklist do firewall: tráfego roteado.
   - Active response `firewall-drop` no servidor: tráfego dentro da LAN.
   - Ambos só com aprovação ou com `AUTO_BLOCK=true`.
6. **Memória da IA:** SQLite + embeddings (numpy) em volume Docker. O SQLite fica fora da
   pasta do Windows para evitar problemas de lock em bind mount. ChromaDB foi dispensado
   pelo volume pequeno de um laboratório.
7. **Testes ofensivos (1, 2 e 6):** executados por você no Cliente. O `lab.ps1` registra o
   horário e extrai alertas e a análise da IA. Os testes 3, 4 e 5 são automáticos.
8. **`.env` fora do git:** o arquivo versionado é o `.env.example`. O `.env` tem
   credenciais e fica só na sua máquina.

## Pendências

- [ ] Completar no Checkpoint 4 os trechos em amarelo: ações extensionistas, reflexão pessoal e datas do cronograma marcadas "[confirmar]". (Nome completo e link do GitHub já preenchidos.)
- [ ] Rodar o diagnóstico e definir modelo da IA e limite de memória pela RAM real.
- [ ] Confirmar `vm.max_map_count` ≥ 262144 na VM do Docker. Se precisar, o
      `lab.ps1 preparar` mostra o comando, que é alteração fora da pasta e pede seu OK.
- [ ] Executar as fases 1 a 7 e registrar os resultados aqui.
- [ ] Gerar o Checkpoint 4 com as evidências reais.

## Problemas encontrados e soluções

| Data | Problema | Solução |
|---|---|---|
| 2026-11-12 | Não é possível digitar no terminal do Windows a partir do assistente | Fluxo por scripts: você roda o `lab.ps1` e as saídas vão para `testes/saidas/`, que o assistente lê |
| 2026-11-12 | Imagens do Wazuh/Ollama e regras ET Open sem acesso no ambiente do assistente | Ambiente experimental com namespaces, emulador do SIEM e réplica da regra GPL 2100498 |
| 2026-11-12 | nginx falhou ao abrir `[::]:80` (ambiente sem IPv6) | `listen [::]:80` removido no ambiente experimental |
| 2026-11-12 | Alertas de baixo nível de testes diferentes caíam no mesmo grupo | agrupamento por origem **e** categoria; reincidência só conta episódios anteriores |
| 2026-11-12 | Ecos da própria resposta (100103/100104/651) geravam novos incidentes | regras ignoradas por padrão na triagem; aplicação de bloqueio idempotente |
