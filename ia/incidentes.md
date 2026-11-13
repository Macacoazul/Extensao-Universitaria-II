# Historico de incidentes (memoria da IA)

Atualizado em 2026-11-12 22:57:28 -0300.

| Incidente | Inicio | Origem | Categoria | Regras | Nivel | Classificacao | Gravidade | Reincid. | Acao |
|---|---|---|---|---|---|---|---|---|---|
| INC-031d2acfa2 | 2026-11-12T22:54:33.226-0300 | 192.168.10.20 | autenticacao_ssh | 5760,5710 | 5 | suspeito | baixa | nao | monitorar |
| INC-83216e7b51 | 2026-11-12T22:57:15.294-0300 | 192.168.10.20 | autenticacao_ssh | 5763 | 10 | suspeito | alta | sim | firewall: 192.168.10.20 em quarentena por 1h; active-response: firewall-drop 192.168.10.20 no agente lab-server (001) |
| INC-530fc851e9 | 2026-11-12T22:56:00.259-0300 | 192.168.10.20 | firewall | 100101 | 5 | suspeito | baixa | nao | monitorar |
| INC-8ea8f59d43 | 2026-11-12T22:56:18.311-0300 | 192.168.10.20 | varredura | 100102 | 10 | suspeito | alta | nao | recomendado bloqueio |
| INC-6d971a74e7 | 2026-11-12T22:55:33.811-0300 |  | integridade_arquivos | 550 | 7 | suspeito | media | nao | monitorar |
| INC-95f6d4d633 | 2026-11-12T22:55:03.235-0300 | 198.51.100.10 | ids_assinatura | 100201 | 7 | suspeito | media | nao | monitorar |
| INC-6fb2fb5c24 | 2026-11-12T22:54:31.225-0300 | 192.168.10.20 | autenticacao_ssh | 5710,5760 | 5 | suspeito | baixa | nao | monitorar |
| INC-9b5c051faf | 2026-11-12T22:54:33.227-0300 | 192.168.10.20 | autenticacao_ssh | 5763 | 10 | suspeito | alta | nao | recomendado bloqueio |
| INC-35b47367e2 | 2026-11-12T22:54:00.215-0300 | 192.168.10.20 | ids_assinatura | 100211 | 8 | suspeito | media | nao | monitorar |
