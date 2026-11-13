# Recomendacoes da IA (aguardando aprovacao)

Cada incidente analisado aparece abaixo. Com `AUTO_BLOCK=false` (padrao), NENHUMA
acao foi aplicada: copie o comando para aplicar o bloqueio depois de revisar.
As sugestoes de regra sao propostas do modelo e devem ser revisadas antes do uso.

## INC-35b47367e2 — suspeito / gravidade media

- **Registrado em:** 2026-11-12 22:54:13 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:54:00.215-0300 → 2026-11-12T22:54:02.216-0300 (5 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** siem-emulador
- **Regras Wazuh:** 100211 (n8 x5)
- **MITRE ATT&CK:** T1046 Network Service Discovery (Discovery)
- **Reincidencia:** nao
- **Causa provavel:** O trafego correspondeu a uma assinatura do IDS (Suricata); a evidencia e o conteudo do pacote/fluxo descrito na assinatura.
- **Acao recomendada:** Conferir origem, destino e payload do fluxo no eve.json; confirmar se e teste autorizado; se nao for, investigar o host interno envolvido.
- **Confianca da IA:** media

**Decisao de bloqueio:** nao recomendado — sem reincidencia e gravidade abaixo de alta: apenas monitorar

Sugestao de regra (suricata) — revisar antes de usar: Evitar falsos positivos de testes sem perder a deteccao.

```
Manter a assinatura habilitada; se for teste recorrente autorizado, usar threshold/suppress apenas para o IP de teste.
```

---
## INC-9b5c051faf — suspeito / gravidade alta

- **Registrado em:** 2026-11-12 22:54:43 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:54:33.227-0300 → 2026-11-12T22:54:33.227-0300 (1 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** lab-server
- **Regras Wazuh:** 5763 (n10 x1)
- **MITRE ATT&CK:** T1110 Brute Force (Credential Access)
- **Reincidencia:** nao
- **Causa provavel:** Varias falhas de autenticacao SSH a partir da mesma origem em pouco tempo, padrao compativel com tentativa de adivinhacao de senha (forca bruta).
- **Acao recomendada:** Bloquear temporariamente a origem; verificar se houve login bem-sucedido apos as falhas (regra 5715); exigir chave SSH/MFA, limitar tentativas (MaxAuthTries) e revisar contas expostas.
- **Confianca da IA:** media

**Decisao de bloqueio:** RECOMENDADO — gravidade alta

Comandos para aprovar (rodar na pasta do projeto):

```powershell
docker compose exec firewall fw-block 192.168.10.20 1h    # Quarentena de 192.168.10.20 no firewall por 1h (bloqueia o trafego roteado: internet e gerencia, inclusive o agente Wazuh do host)
docker compose exec ai-analyst python -m analyst.acoes bloquear --ip 192.168.10.20 --agente lab-server    # firewall-drop (iptables) no agente lab-server: bloqueia 192.168.10.20 dentro da LAN
```

_Nao aplicado automaticamente: aguardando aprovacao (ou reincidencia, se AUTO_BLOCK=true)._

Sugestao de regra (active-response) — revisar antes de usar: Resposta automatica do Wazuh a forca bruta SSH, com bloqueio temporario de 10 minutos.

```
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763,5712</rules_id>
  <timeout>600</timeout>
</active-response>
```

---
## INC-6fb2fb5c24 — suspeito / gravidade baixa

- **Registrado em:** 2026-11-12 22:54:45 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:54:31.225-0300 → 2026-11-12T22:54:35.228-0300 (18 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** lab-server
- **Regras Wazuh:** 5710 (n5 x3), 5760 (n5 x15)
- **MITRE ATT&CK:** T1110.001 Password Guessing (Credential Access, Lateral Movement), T1021.004 SSH (Credential Access, Lateral Movement)
- **Reincidencia:** nao
- **Causa provavel:** Varias falhas de autenticacao SSH a partir da mesma origem em pouco tempo, padrao compativel com tentativa de adivinhacao de senha (forca bruta).
- **Acao recomendada:** Bloquear temporariamente a origem; verificar se houve login bem-sucedido apos as falhas (regra 5715); exigir chave SSH/MFA, limitar tentativas (MaxAuthTries) e revisar contas expostas.
- **Confianca da IA:** media

**Decisao de bloqueio:** nao recomendado — sem reincidencia e gravidade abaixo de alta: apenas monitorar

Sugestao de regra (active-response) — revisar antes de usar: Resposta automatica do Wazuh a forca bruta SSH, com bloqueio temporario de 10 minutos.

```
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763,5712</rules_id>
  <timeout>600</timeout>
</active-response>
```

---
## INC-95f6d4d633 — suspeito / gravidade media

- **Registrado em:** 2026-11-12 22:55:13 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:55:03.235-0300 → 2026-11-12T22:55:03.235-0300 (1 alertas)
- **Origem:** 198.51.100.10 | **Agentes:** siem-emulador
- **Regras Wazuh:** 100201 (n7 x1)
- **MITRE ATT&CK:** —
- **Reincidencia:** nao
- **Causa provavel:** O trafego correspondeu a uma assinatura do IDS (Suricata); a evidencia e o conteudo do pacote/fluxo descrito na assinatura.
- **Acao recomendada:** Conferir origem, destino e payload do fluxo no eve.json; confirmar se e teste autorizado; se nao for, investigar o host interno envolvido.
- **Confianca da IA:** media

**Decisao de bloqueio:** nao recomendado — 198.51.100.10 fora das redes do lab (192.168.10.0/24)

Sugestao de regra (suricata) — revisar antes de usar: Evitar falsos positivos de testes sem perder a deteccao.

```
Manter a assinatura habilitada; se for teste recorrente autorizado, usar threshold/suppress apenas para o IP de teste.
```

---
## INC-6d971a74e7 — suspeito / gravidade media

- **Registrado em:** 2026-11-12 22:55:43 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:55:33.811-0300 → 2026-11-12T22:55:33.811-0300 (1 alertas)
- **Origem:** — | **Agentes:** lab-server
- **Regras Wazuh:** 550 (n7 x1)
- **MITRE ATT&CK:** T1565.001 Stored Data Manipulation (Impact)
- **Reincidencia:** nao
- **Causa provavel:** Arquivo monitorado pelo FIM foi criado ou alterado (conteudo/hash diferente da linha de base).
- **Acao recomendada:** Confirmar se a mudanca foi planejada (gestao de mudancas); analisar o diff registrado; restaurar do backup se a alteracao nao for autorizada.
- **Confianca da IA:** media

**Decisao de bloqueio:** nao recomendado — incidente sem IP de origem

Sugestao de regra (wazuh) — revisar antes de usar: Eleva a prioridade de alteracoes no conteudo publicado do servidor web.

```
<rule id="100300" level="10">
  <if_sid>550</if_sid>
  <field name="file">^/var/www</field>
  <description>Conteudo web alterado: $(file)</description>
</rule>
```

---
## INC-8ea8f59d43 — suspeito / gravidade alta

- **Registrado em:** 2026-11-12 22:56:29 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:56:18.311-0300 → 2026-11-12T22:56:18.311-0300 (1 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** siem-emulador
- **Regras Wazuh:** 100102 (n10 x1)
- **MITRE ATT&CK:** T1046 Network Service Discovery (Discovery)
- **Reincidencia:** nao
- **Causa provavel:** Muitas tentativas de conexao a servicos/portas diferentes a partir da mesma origem, compativel com descoberta de servicos na rede (T1046).
- **Acao recomendada:** Identificar o processo/usuario que gerou as conexoes no host de origem; isolar o host se a atividade nao for autorizada; manter a politica default-deny entre segmentos.
- **Confianca da IA:** media

**Decisao de bloqueio:** RECOMENDADO — gravidade alta

Comandos para aprovar (rodar na pasta do projeto):

```powershell
docker compose exec firewall fw-block 192.168.10.20 1h    # Quarentena de 192.168.10.20 no firewall por 1h (bloqueia o trafego roteado: internet e gerencia, inclusive o agente Wazuh do host)
```

_Nao aplicado automaticamente: aguardando aprovacao (ou reincidencia, se AUTO_BLOCK=true)._

Sugestao de regra (firewall) — revisar antes de usar: Limita novas conexoes por origem para conter varreduras.

```
nft add rule inet filter forward iifname $LAN_IF ct state new meter scan { ip saddr limit rate over 30/minute } log prefix "FW-SCAN " group 1 drop
```

---
## INC-530fc851e9 — suspeito / gravidade baixa

- **Registrado em:** 2026-11-12 22:56:35 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:56:00.259-0300 → 2026-11-12T22:56:24.326-0300 (25 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** siem-emulador
- **Regras Wazuh:** 100101 (n5 x25)
- **MITRE ATT&CK:** —
- **Reincidencia:** nao
- **Causa provavel:** Trafego negado pela politica do firewall: a origem tentou acessar destinos/portas nao liberados.
- **Acao recomendada:** Verificar qual aplicacao no host de origem gera o trafego; manter o bloqueio; investigar se o volume indicar varredura.
- **Confianca da IA:** media

**Decisao de bloqueio:** nao recomendado — sem reincidencia e gravidade abaixo de alta: apenas monitorar

---
## INC-83216e7b51 — suspeito / gravidade alta

- **Registrado em:** 2026-11-12 22:57:25 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:57:15.294-0300 → 2026-11-12T22:57:15.294-0300 (1 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** lab-server
- **Regras Wazuh:** 5763 (n10 x1)
- **MITRE ATT&CK:** T1110 Brute Force (Credential Access)
- **Reincidencia:** SIM (2 incidente(s) anterior(es): INC-6fb2fb5c24, INC-9b5c051faf)
- **Causa provavel:** Varias falhas de autenticacao SSH a partir da mesma origem em pouco tempo, padrao compativel com tentativa de adivinhacao de senha (forca bruta).
- **Acao recomendada:** Bloquear temporariamente a origem; verificar se houve login bem-sucedido apos as falhas (regra 5715); exigir chave SSH/MFA, limitar tentativas (MaxAuthTries) e revisar contas expostas.
- **Confianca da IA:** media

**Decisao de bloqueio:** RECOMENDADO — reincidencia detectada

Comandos para aprovar (rodar na pasta do projeto):

```powershell
docker compose exec firewall fw-block 192.168.10.20 1h    # Quarentena de 192.168.10.20 no firewall por 1h (bloqueia o trafego roteado: internet e gerencia, inclusive o agente Wazuh do host)
docker compose exec ai-analyst python -m analyst.acoes bloquear --ip 192.168.10.20 --agente lab-server    # firewall-drop (iptables) no agente lab-server: bloqueia 192.168.10.20 dentro da LAN
```

**Aplicado automaticamente (AUTO_BLOCK=true, reincidencia confirmada):**
- firewall: 192.168.10.20 em quarentena por 1h
- active-response: firewall-drop 192.168.10.20 no agente lab-server (001)

Sugestao de regra (active-response) — revisar antes de usar: Resposta automatica do Wazuh a forca bruta SSH, com bloqueio temporario de 10 minutos.

```
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763,5712</rules_id>
  <timeout>600</timeout>
</active-response>
```

---
## INC-031d2acfa2 — suspeito / gravidade baixa

- **Registrado em:** 2026-11-12 22:57:28 -0300 (analise em 0.0 s, contingencia/playbook (LLM indisponivel: ConnectionError))
- **Periodo dos alertas:** 2026-11-12T22:54:33.226-0300 → 2026-11-12T22:57:17.296-0300 (26 alertas)
- **Origem:** 192.168.10.20 | **Agentes:** lab-server
- **Regras Wazuh:** 5760 (n5 x23), 5710 (n5 x3)
- **MITRE ATT&CK:** T1110.001 Password Guessing (Credential Access, Lateral Movement), T1021.004 SSH (Credential Access, Lateral Movement)
- **Reincidencia:** nao
- **Causa provavel:** Varias falhas de autenticacao SSH a partir da mesma origem em pouco tempo, padrao compativel com tentativa de adivinhacao de senha (forca bruta).
- **Acao recomendada:** Bloquear temporariamente a origem; verificar se houve login bem-sucedido apos as falhas (regra 5715); exigir chave SSH/MFA, limitar tentativas (MaxAuthTries) e revisar contas expostas.
- **Confianca da IA:** media

**Decisao de bloqueio:** nao recomendado — sem reincidencia e gravidade abaixo de alta: apenas monitorar

Sugestao de regra (active-response) — revisar antes de usar: Resposta automatica do Wazuh a forca bruta SSH, com bloqueio temporario de 10 minutos.

```
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5763,5712</rules_id>
  <timeout>600</timeout>
</active-response>
```

---
