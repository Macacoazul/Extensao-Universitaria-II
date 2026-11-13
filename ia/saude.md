# Saude do laboratorio — ATENCAO

Verificado em 2026-11-12T23:05:52-03:00.

**Problemas:**
- servico ollama sem resposta
- modelo deepseek-r1:8b nao carregado no Ollama

## Servicos

| Servico | Estado |
|---|---|
| firewall-api | OK |
| siem-emulador-api | OK |
| ollama | FALHA |

## Agentes Wazuh

| ID | Nome | IP | Status | Versao |
|---|---|---|---|---|
| 000 | siem-emulador | 127.0.0.1 | active | emulador |
| 001 | lab-server | 192.168.10.10 | active | simulado |
| 002 | lab-cliente | 192.168.10.20 | active | simulado |

## Suricata

- eve.json: existe; tamanho 754551 bytes
- ultima escrita ha: 0 s
- cresceu desde a ultima verificacao: True

## Wazuh / IA

- ultimo alerta gravado ha: 482 s
- modelos no Ollama: nenhum
