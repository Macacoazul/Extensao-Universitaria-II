# Wazuh (single-node oficial)

Arquivos copiados do repositorio oficial `wazuh/wazuh-docker`, tag **v4.14.10**,
pasta `single-node/` (licenca GPLv2 em `LICENSE-wazuh-docker`):

- `generate-indexer-certs.yml` + `config/certs.yml` -> gera os certificados em
  `config/wazuh_indexer_ssl_certs/` (rodado por `lab.ps1 preparar`; nao vai para o git)
- `config/wazuh_indexer/*`, `config/wazuh_dashboard/*` -> sem alteracao
- `config/wazuh_cluster/wazuh_manager.conf` -> **alterado** (procure por `LAB:`):
  syslog remoto UDP 514 (somente rede de gerencia), leitura do `eve.json` do Suricata,
  re-registro de agentes recriados e nota sobre active response

Personalizacoes do lab (`config/custom/`, montadas via `/wazuh-config-mount`):

| Arquivo | Destino no manager | Conteudo |
|---|---|---|
| `local_decoder.xml` | `etc/decoders/` | decoders do firewall (`lab-fw`) |
| `local_rules.xml` | `etc/rules/` | 100100-100105 firewall; 100200-100211 nivel do Suricata por severidade e regras locais |
| `agent.conf` | `etc/shared/default/` | FIM em tempo real em /etc e /var/www; auth.log e logs do Nginx |

Senhas: os valores do `.env.example` sao os padroes do wazuh-docker. Para trocar a do
`admin`, gere o hash com
`docker run --rm -ti wazuh/wazuh-indexer:4.14.10 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh`,
atualize `config/wazuh_indexer/internal_users.yml` e o `.env`, e recrie o indexer
(procedimento "Change the password of Wazuh users" da documentacao oficial).

Teste de decoder/regra sem gerar trafego:

```powershell
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest
```
e cole, por exemplo:
`Nov 13 10:00:01 fw lab-fw: Nov 13 10:00:01 fw FW-DROP IN=eth1 OUT=eth2 SRC=192.168.10.20 DST=172.30.0.12 LEN=60 PROTO=TCP SPT=40000 DPT=5601`
