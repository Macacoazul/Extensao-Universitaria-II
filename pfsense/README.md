# Firewall do laboratorio — por que nao e o pfSense "de verdade"

O pfSense e baseado em FreeBSD e **nao roda como container Docker**. A ordem de
tentativa definida para o projeto foi:

| Opcao | Como | Requisito | Situacao |
|---|---|---|---|
| a) pfSense em VM QEMU/KVM dentro de container | imagem tipo `qemux/qemu` ligada as redes Docker | `/dev/kvm` disponivel dentro do Docker | depende do diagnostico (`diagnostico/diagnostico.txt`, secao "KVM dentro do Docker") |
| b) pfSense no VirtualBox/Hyper-V | VM ligada as redes do lab | as VMs precisariam alcancar as redes do Docker Desktop | no Windows as redes Docker ficam dentro da VM do WSL2 e nao sao alcancaveis por uma VM do VirtualBox sem gambiarras de roteamento |
| **c) container Linux com nftables** | `pfsense/firewall/` | nenhum | **usada** |

## O que a opcao (c) replica do pfSense

| Funcao no pfSense | Equivalente aqui |
|---|---|
| Interfaces WAN / LAN / OPT (gerencia) | 3 interfaces do container: 172.20.0.2 / 192.168.10.1 / 172.30.0.2 |
| Regras de firewall (Firewall > Rules), politica *default deny* | `nftables.conf.tpl`: `policy drop` em `input` e `forward`, liberando so o necessario |
| Outbound NAT automatico | `masquerade` da LAN saindo pela WAN |
| Log das regras de bloqueio (Status > System Logs > Firewall) | `log ... group 1` -> ulogd2 -> `/var/log/lab-fw/firewall.log` |
| Remote Syslog (Status > System Logs > Settings) | rsyslog envia para o Wazuh em UDP 514 |
| Aliases/tabela de bloqueio (ex.: pfBlocker, `easyrule`) | set `blocklist` com timeout + API/CLI `fw-block` |

## Regras (resumo)

| # | Origem | Destino | Porta/protocolo | Acao |
|---|---|---|---|---|
| 1 | IPs na `blocklist` | qualquer | qualquer | bloquear + log |
| 2 | LAN 192.168.10.0/24 | Internet (WAN) | DNS 53, HTTP 80, HTTPS 443, NTP 123, ICMP echo | liberar + NAT |
| 3 | LAN | Wazuh manager 172.30.0.10 | TCP 1514/1515 (agentes) | liberar |
| 4 | ai-analyst 172.30.0.21 | firewall | TCP 8088 (API de bloqueio) | liberar |
| 5 | LAN | firewall | ICMP echo (diagnostico) | liberar |
| 6 | qualquer outro | — | — | **bloquear + log** |

Trafego **entre hosts da mesma LAN** (Cliente <-> Server) e comutado pela bridge e
nao passa pelo firewall — igual a uma LAN fisica atras de um pfSense. Por isso o
sensor (Suricata) escuta a bridge da LAN, e a resposta a incidentes dentro da LAN
usa o *active response* do Wazuh (iptables no proprio servidor).

Comandos uteis:

```powershell
docker compose exec firewall fw-status            # regras com contadores + ultimos logs
docker compose exec firewall fw-block 192.168.10.20 30m
docker compose exec firewall fw-unblock 192.168.10.20
```
