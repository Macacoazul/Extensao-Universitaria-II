#!/bin/sh
# Inicializa o firewall do laboratorio:
#  1. descobre qual interface esta em cada rede (pelo IP definido no .env)
#  2. ajusta a rota padrao para a WAN
#  3. aplica as regras nftables (template + variaveis)
#  4. sobe ulogd2 (logs NFLOG), rsyslog (envio ao Wazuh) e a API de bloqueio
set -eu

log() { echo "[firewall] $*"; }

iface_for() {
  ip -o -4 addr show | awk -v ip="$1" '{split($4, a, "/"); if (a[1] == ip) {print $2; exit}}'
}

render() {  # render <template> <destino>
  python3 - "$1" "$2" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
# substitui apenas ${VAR}; $VAR (variaveis do nftables) fica intacto
text = re.sub(r"\$\{(\w+)\}", lambda m: os.environ[m.group(1)], open(src).read())
open(dst, "w").write(text)
PY
}

for i in $(seq 1 30); do
  WAN_IF=$(iface_for "$FW_WAN_IP"); LAN_IF=$(iface_for "$FW_LAN_IP"); MGMT_IF=$(iface_for "$FW_MGMT_IP")
  [ -n "$WAN_IF" ] && [ -n "$LAN_IF" ] && [ -n "$MGMT_IF" ] && break
  sleep 1
done
[ -n "${WAN_IF:-}" ] && [ -n "${LAN_IF:-}" ] && [ -n "${MGMT_IF:-}" ] || { log "ERRO: interfaces nao encontradas"; ip -o -4 addr show; exit 1; }
export WAN_IF LAN_IF MGMT_IF
log "WAN=$WAN_IF ($FW_WAN_IP)  LAN=$LAN_IF ($FW_LAN_IP)  MGMT=$MGMT_IF ($FW_MGMT_IP)"

# Rota padrao sempre pela WAN (o Docker pode escolher outra rede)
ip route replace default via "$WAN_GW" dev "$WAN_IF"
log "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"

render /etc/lab-fw/nftables.conf.tpl /etc/nftables.conf
nft -f /etc/nftables.conf
log "regras nftables aplicadas"

mkdir -p /var/log/lab-fw /var/log/ulogd /var/spool/rsyslog
touch /var/log/lab-fw/firewall.log
ulogd -d -c /etc/ulogd.conf
RSYSLOG_CONF="${RSYSLOG_CONF:-/etc/rsyslog.conf}"
render /etc/lab-fw/rsyslog.conf.tpl "$RSYSLOG_CONF"
rsyslogd -f "$RSYSLOG_CONF" -i "${RSYSLOG_PID:-/run/rsyslogd.pid}"
python3 /usr/local/bin/fw_api.py &
log "pronto: logs -> syslog udp://$WAZUH_MANAGER_IP:514 | API de bloqueio em $FW_MGMT_IP:8088"

exec tail -F /var/log/lab-fw/firewall.log
