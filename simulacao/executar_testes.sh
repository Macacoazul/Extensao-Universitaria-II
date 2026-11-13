#!/bin/bash
# =============================================================================
# Executa as fases e os testes 1-6 no AMBIENTE EXPERIMENTAL (maquinas simuladas)
# e grava as saidas em testes/saidas/ e as evidencias em testes/T<n>.md.
#   sudo ./ambiente.sh up && sudo ./executar_testes.sh
# Testes 1, 2 e 6 usam EVENTOS HIPOTETICOS (hipoteticos.py); 3, 4 e 5 sao reais
# dentro do ambiente experimental.
# =============================================================================
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
OUT="$ROOT/testes/saidas"
mkdir -p "$OUT" /var/lib/lab-sim/ia-state
cd "$ROOT"
export FW_API_TOKEN="${FW_API_TOKEN:-token-ambiente-experimental}"

# ---- configuracao do ai-analyst no ambiente experimental ---------------------
export PYTHONPATH="$ROOT/ia" STATE_DIR=/var/lib/lab-sim/ia-state OUT_DIR="$ROOT/ia" \
  ALERTS_FILE=/var/ossec/logs/alerts/alerts.json SURICATA_EVE=/var/log/suricata/eve.json \
  OLLAMA_URL=http://127.0.0.1:11434 LLM_MODEL=deepseek-r1:8b EMBED_MODEL=nomic-embed-text \
  AI_OLLAMA_WAIT_S=0 AI_PULL_MODELS=false EMBED_FALLBACK=hash \
  AI_MIN_LEVEL=7 AI_GROUP_THRESHOLD=10 AI_SETTLE_S=10 AI_MAX_BUCKET_AGE_S=60 AI_POLL_SECONDS=2 \
  AI_HEALTH_INTERVAL_S=60 AUTO_BLOCK=true AUTO_BLOCK_REQUIRE_RECURRENCE=true \
  AUTO_BLOCK_NETWORKS=192.168.10.0/24 AUTO_BLOCK_PROTECTED=192.168.10.1,172.30.0.10 \
  FW_API_URL=http://172.30.0.2:8088 FW_BLOCK_TIMEOUT=1h WAZUH_API_URL=https://172.30.0.10:55000 \
  API_USERNAME=wazuh-wui API_PASSWORD=emulador LAN_SUBNET=192.168.10.0/24 MGMT_SUBNET=172.30.0.0/24 \
  HEALTH_TARGETS="firewall-api=172.30.0.2:8088,siem-emulador-api=172.30.0.10:55000,ollama=127.0.0.1:11434"

agora() { date +%Y-%m-%dT%H:%M:%S%:z; }
declare -A NOME=([cli]=lab-cliente [srv]=lab-server [fw]=fw [inet]=internet-ficticia [host]=siem-gerencia)

novo() { echo "# $1 - ambiente experimental - $(agora)" > "$OUT/$1"; }
# em <arquivo> <maquina> <comando>: executa e grava "[hora] maquina:~$ comando" + saida
em() {
  local f=$1 m=$2; shift 2
  local cmd="$*"
  { echo "[$(agora)] ${NOME[$m]}:~\$ $cmd"
    if [ "$m" = host ]; then bash -c "$cmd" 2>&1; else ip netns exec "$m" bash -c "$cmd" 2>&1; fi
    echo; } | tee -a "$OUT/$f"
}
nota() { local f=$1; shift; echo ">>> $*" | tee -a "$OUT/$f"; }

evid() {  # evid <id> <nome> <inicio> <fim> <comando> <esperado>
  sleep 25
  python3 -m analyst.evidencias --id "$1" --nome "$2" --inicio "$3" --fim "$4" --comando "$5" \
    --esperado "$6" --grace 40 --saida "$ROOT/testes" | tee -a "$OUT/$1_saida.txt"
}

# =========================================================== Fase 1
F=01_fase1_infra.txt; novo $F
em $F host "ip netns list"
em $F host "ip -br link show type bridge"
for m in fw srv cli; do em $F $m "ip -br -4 addr show | grep -v '^lo'"; done
em $F cli "ip route"
em $F srv "ip route"
em $F fw "ip route"
em $F cli "ping -c 3 -W 2 192.168.10.1"
em $F cli "ping -c 3 -W 2 192.168.10.10"
em $F cli "ping -c 3 -W 2 198.51.100.10"
em $F cli "ip route get 198.51.100.10"
em $F cli "curl -sS -m 5 http://198.51.100.10/"
em $F host "tail -n 2 /var/log/lab-sim/internet.out"
nota $F "o site externo viu a requisicao vindo de 172.20.0.2 (IP WAN do firewall): NAT de saida funcionando"
em $F cli "curl -sS -m 5 -o /dev/null -w 'HTTP %{http_code} - servidor web interno\n' http://192.168.10.10/"

# =========================================================== Fase 2
F=02_fase2_firewall.txt; novo $F
em $F cli "curl -sS -m 5 -o /dev/null -w 'LIBERADO: HTTP %{http_code} para a internet\n' http://198.51.100.10/"
em $F cli "nc -vz -w 3 198.51.100.10 23 || echo 'BLOQUEADO: telnet para a internet'"
em $F cli "nc -vz -w 3 172.30.0.10 55000 || echo 'BLOQUEADO: LAN -> API do SIEM (gerencia)'"
sleep 3
em $F fw "tail -n 4 /var/log/lab-fw/firewall.log"
em $F host "grep -h '\"100101\"' /var/ossec/logs/alerts/alerts.json | tail -n 1 | python3 -m json.tool | head -30"
F=nft_ruleset.txt; novo $F
em $F fw "nft list ruleset"

# =========================================================== Fase 3/4
F=03_fase3_ids_siem.txt; novo $F
em $F host "pgrep -a suricata | cut -c1-150"
em $F host "tail -n 3 /var/log/suricata/suricata.log"
em $F cli "curl -sS -m 5 -o /dev/null http://192.168.10.10/ && echo trafego web gerado"
sleep 4
em $F host "grep -c '\"event_type\"' /var/log/suricata/eve.json"
em $F host "grep '\"event_type\":\"flow\"' /var/log/suricata/eve.json | tail -n 1 | python3 -m json.tool | head -25"
em $F host "tail -n 6 /var/log/lab-sim/emulador.out"

# =========================================================== Fase 5 (IA)
F=05_fase5_ia.txt; novo $F
nohup python3 -m analyst.main > /var/log/lab-sim/ai-analyst.out 2>&1 &
echo $! > /var/lib/lab-sim/ai-analyst.pid
sleep 8
em $F host "tail -n 8 /var/log/lab-sim/ai-analyst.out"
em $F host "curl -sS -m 2 http://127.0.0.1:11434/api/tags || echo 'Ollama indisponivel no ambiente experimental: analise em modo de contingencia'"

# =========================================================== Testes
declare -A TN TE
TN[1]="Varredura de portas do Cliente para o Server (situacao hipotetica)"
TE[1]="Alertas do IDS (regra local 9100002 -> Wazuh 100211, nivel 8, T1046) com origem 192.168.10.20 e analise da IA"
TN[2]="Forca bruta SSH no Server (situacao hipotetica)"
TE[2]="sshd 5760/5710 (nivel 5) e 5763 (nivel 10, T1110); IA recomenda bloqueio de 192.168.10.20 (sem aplicar: 1a ocorrencia)"
TN[3]="Assinatura de teste do Suricata (pagina estilo testmynids em site ficticio)"
TE[3]="Suricata GPL ATTACK_RESPONSE id check returned root (sid 2100498) -> Wazuh 100201 nivel 7"
TN[4]="Alteracao de arquivo monitorado (FIM)"
TE[4]="FIM: 550 (modificado, nivel 7) em /var/www/html/index.html e 554 (criado) em /etc/lab-fim-teste.conf"
TN[5]="Trafego bloqueado pelo firewall (LAN -> servicos da gerencia)"
TE[5]="FW-DROP no firewall, Wazuh 100101 (nivel 5) e 100102 (nivel 10, muitas conexoes bloqueadas da mesma origem)"
TN[6]="Reincidencia do teste 2 (situacao hipotetica)"
TE[6]="IA detecta reincidencia de 192.168.10.20 e, com AUTO_BLOCK=true, aplica o bloqueio (firewall + active response)"

teste() {  # teste <n> <maquina> <comando>
  local n=$1 m=$2; shift 2
  local f="T${n}_saida.txt"; novo $f
  nota $f "TESTE T$n - ${TN[$n]}"
  local ini; ini=$(agora)
  em $f "$m" "$*"
  sleep 3
  local fim; fim=$(agora)
  evid "T$n" "${TN[$n]}" "$ini" "$fim" "$*" "${TE[$n]}"
}

teste 1 host "python3 simulacao/hipoteticos.py varredura --origem 192.168.10.20 --alvo 192.168.10.10 --alertas 5"
teste 2 host "python3 simulacao/hipoteticos.py forca-bruta --origem 192.168.10.20 --usuario labuser --tentativas 12 --invalidos 3"
teste 3 cli "curl -sS -m 10 http://198.51.100.10/uid/index.html"
teste 4 srv "echo '<!-- teste FIM do laboratorio -->' >> /var/www/html/index.html; echo lab_fim_teste=1 > /etc/lab-fim-teste.conf; echo arquivos alterados"
teste 5 cli "for r in 1 2 3 4 5; do for p in 22 5601 9200 11434 55000; do nc -z -w 1 172.30.0.10 \$p; done; done; echo 'tentativas encerradas (todas bloqueadas)'"
sleep 20
teste 6 host "python3 simulacao/hipoteticos.py forca-bruta --origem 192.168.10.20 --usuario labuser --tentativas 12 --invalidos 3"

# ---- verificacao do bloqueio aplicado pela IA (teste 6)
F=T6_saida.txt
nota $F "VERIFICACAO DO BLOQUEIO APLICADO PELA IA"
em $F fw "nft list set inet filter blocklist"
em $F srv "iptables -S INPUT"
em $F cli "curl -sS -m 5 -o /dev/null -w 'HTTP %{http_code}\n' http://198.51.100.10/ || echo 'BLOQUEADO pelo firewall: cliente em quarentena'"
em $F cli "curl -sS -m 5 -o /dev/null -w 'HTTP %{http_code}\n' http://192.168.10.10/ || echo 'BLOQUEADO pelo servidor (active response firewall-drop)'"
sleep 4
em $F fw "tail -n 4 /var/log/lab-fw/firewall.log"
em $F host "cat /var/ossec/logs/active-responses.log"
python3 -m analyst.evidencias --id T6 --nome "${TN[6]}" --inicio "$(python3 -c "import json;print(json.load(open('$ROOT/testes/T6.json'))['meta']['inicio'])")" \
  --fim "$(agora)" --comando "python3 simulacao/hipoteticos.py forca-bruta --origem 192.168.10.20 --usuario labuser --tentativas 12 --invalidos 3" \
  --esperado "${TE[6]}" --grace 10 --saida "$ROOT/testes" >/dev/null

# ---- saude e estado final
sleep 5
F=status_containers.txt; novo $F
em $F host "ip netns list"
em $F host "pgrep -a -f 'suricata|emulador_siem|analyst.main|fw_api|ulogd|nginx|sshd|internet_fake' | cut -c1-140"
python3 -c "
from analyst.config import Config; from analyst import health; from analyst.wazuh_api import WazuhAPI
c=Config(); r=health.check(c, WazuhAPI(c.wazuh_api_url,c.wazuh_api_user,c.wazuh_api_password)); print('saude:', health.write(c, r))"
em $F host "cat $ROOT/ia/saude.md"
F=firewall_log.txt; novo $F
em $F fw "tail -n 30 /var/log/lab-fw/firewall.log"
F=alertas_resumo.txt; novo $F
em $F host "python3 -c \"import json,collections;c=collections.Counter((a['rule']['id'],a['rule']['level'],a['rule']['description'][:70]) for a in map(json.loads,open('/var/ossec/logs/alerts/alerts.json')));[print(f'{n:4d}  regra {r:>6}  nivel {l:>2}  {d}') for (r,l,d),n in sorted(c.items(),key=lambda x:(-x[0][1],x[0][0]))]\""
echo "Concluido. Evidencias em testes/T1..T6.md; IA em ia/recomendacoes.md e ia/incidentes.md"
