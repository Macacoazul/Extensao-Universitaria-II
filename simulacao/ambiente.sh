#!/bin/bash
# =============================================================================
# AMBIENTE EXPERIMENTAL (maquinas simuladas) - Linux, como root
#
# Recria a topologia do laboratorio com network namespaces ("maquinas fakes"):
#   fw   firewall  WAN 172.20.0.2 | LAN 192.168.10.1 | MGMT 172.30.0.2  (nftables do projeto)
#   srv  Ubuntu Server 192.168.10.10 (nginx + sshd reais)
#   cli  Ubuntu Cliente 192.168.10.20
#   inet "internet" ficticia 172.20.0.1 + site 198.51.100.10 (faixa de documentacao RFC 5737)
#   host (namespace raiz) = gerencia 172.30.0.10: Suricata na bridge da LAN, emulador do SIEM,
#        ai-analyst
# Uso: sudo ./ambiente.sh up | down | status
# =============================================================================
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
SIM=/var/lib/lab-sim
LOGS=/var/log/lab-sim
FW_API_TOKEN="${FW_API_TOKEN:-token-ambiente-experimental}"
export FW_API_TOKEN

log() { echo "[ambiente] $*"; }
nsx() { ip netns exec "$@"; }

veth_to_bridge() {  # veth_to_bridge <ns> <ifname-no-ns> <bridge> <ip/cidr> <host-side-name>
  local ns=$1 ifn=$2 br=$3 addr=$4 host=$5
  ip link add "$host" type veth peer name "$ifn" netns "$ns"
  ip link set "$host" master "$br" up
  nsx "$ns" ip addr add "$addr" dev "$ifn"
  nsx "$ns" ip link set "$ifn" up
}

up() {
  mkdir -p "$SIM" "$LOGS" /var/log/suricata /var/log/lab-fw /var/ossec/logs/alerts
  # experimento limpo: sem alertas, memoria da IA ou artefatos de execucoes anteriores
  rm -rf "$SIM/ia-state" /etc/lab-fim-teste.conf
  : > /var/ossec/logs/alerts/alerts.json; : > "$LOGS/eve-hipotetico.json"; rm -f /var/ossec/logs/active-responses.log
  log "bridges da LAN, WAN e gerencia"
  for br in br-lab-lan br-lab-wan br-lab-mgmt; do ip link add "$br" type bridge 2>/dev/null; ip link set "$br" up; done
  ip addr add 172.30.0.10/24 dev br-lab-mgmt 2>/dev/null

  log "maquinas simuladas (namespaces)"
  for ns in fw srv cli inet; do ip netns add "$ns"; nsx "$ns" ip link set lo up; done
  veth_to_bridge fw  eth-lan  br-lab-lan  192.168.10.1/24  vh-fw-lan
  veth_to_bridge fw  eth-wan  br-lab-wan  172.20.0.2/24    vh-fw-wan
  veth_to_bridge fw  eth-mgmt br-lab-mgmt 172.30.0.2/24    vh-fw-mgmt
  veth_to_bridge srv eth0     br-lab-lan  192.168.10.10/24 vh-srv
  veth_to_bridge cli eth0     br-lab-lan  192.168.10.20/24 vh-cli
  veth_to_bridge inet eth0    br-lab-wan  172.20.0.1/24    vh-inet
  nsx inet ip addr add 198.51.100.10/32 dev lo
  nsx srv ip route add default via 192.168.10.1
  nsx cli ip route add default via 192.168.10.1
  nsx fw sysctl -qw net.ipv4.ip_forward=1
  ip route replace 192.168.10.0/24 via 172.30.0.2     # retorno gerencia -> LAN (como o wazuh-route)
  for i in /proc/sys/net/bridge/bridge-nf-call-iptables; do [ -f "$i" ] && echo 0 > "$i"; done

  log "firewall: instala os arquivos do container pfsense/firewall e roda o MESMO entrypoint"
  mkdir -p /etc/lab-fw
  cp "$ROOT/pfsense/firewall/nftables.conf.tpl" "$ROOT/pfsense/firewall/rsyslog.conf.tpl" /etc/lab-fw/
  cp "$ROOT/pfsense/firewall/ulogd.conf" /etc/ulogd.conf
  cp "$ROOT/pfsense/firewall/fw_api.py" "$ROOT/pfsense/firewall/fw-block" "$ROOT/pfsense/firewall/fw-unblock" \
     "$ROOT/pfsense/firewall/fw-status" /usr/local/bin/
  chmod +x /usr/local/bin/fw-*
  FW_WAN_IP=172.20.0.2 FW_LAN_IP=192.168.10.1 FW_MGMT_IP=172.30.0.2 WAN_GW=172.20.0.1 \
  LAN_SUBNET=192.168.10.0/24 WAZUH_MANAGER_IP=172.30.0.10 AI_ANALYST_IP=172.30.0.10 \
  FW_BLOCK_TIMEOUT=1h FW_BLOCK_NETWORKS=192.168.10.0/24 FW_PROTECTED=192.168.10.1,172.30.0.10 \
  RSYSLOG_CONF=/etc/lab-fw/rsyslog-fw.conf RSYSLOG_PID=/run/rsyslogd-fw.pid \
    nohup ip netns exec fw sh "$ROOT/pfsense/firewall/entrypoint.sh" > "$LOGS/firewall.out" 2>&1 &
  sleep 3

  log "syslog local (auth.log do servidor simulado)"
  sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf
  pgrep -f "rsyslogd -n" >/dev/null || (rsyslogd 2>/dev/null; true)

  log "servidor: nginx + sshd reais dentro do namespace srv"
  mkdir -p /var/www/html /run/sshd
  cp "$ROOT/lan/www/index.html" /var/www/html/index.html
  cp "$ROOT/lan/sshd-lab.conf" /etc/ssh/sshd_config.d/lab.conf
  id labuser >/dev/null 2>&1 || { useradd -m -s /bin/bash labuser; echo "labuser:$(head -c 12 /dev/urandom | base64)" | chpasswd; }
  ssh-keygen -A >/dev/null 2>&1
  sed -i '/listen \[::\]:80/d' /etc/nginx/sites-enabled/default 2>/dev/null   # ambiente sem IPv6
  nsx srv nginx
  nsx srv /usr/sbin/sshd

  log "internet ficticia: site 198.51.100.10 (pagina de teste do IDS)"
  nohup ip netns exec inet python3 "$DIR/internet_fake.py" > "$LOGS/internet.out" 2>&1 &

  log "Suricata escutando a bridge da LAN (br-lab-lan)"
  rm -f /var/log/suricata/eve.json
  suricata -D -c /etc/suricata/suricata.yaml --af-packet=br-lab-lan -k none \
    --set "vars.address-groups.HOME_NET=[192.168.10.0/24]" \
    -S "$DIR/regras-ambiente-experimental.rules" --pidfile /run/suricata-lab.pid >/dev/null 2>&1

  log "emulador do SIEM (formato de alertas do Wazuh) + API de agentes/active response"
  nohup python3 "$DIR/emulador_siem.py" > "$LOGS/emulador.out" 2>&1 &
  echo $! > "$SIM/emulador.pid"
  sleep 4
  log "pronto"
}

down() {
  # encerra tudo que roda dentro das maquinas simuladas e os processos do host (por PID)
  for ns in fw srv cli inet; do ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null; done
  for f in "$SIM"/*.pid /run/suricata-lab.pid; do [ -f "$f" ] && kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; done
  sleep 1
  for ns in fw srv cli inet; do ip netns del "$ns" 2>/dev/null; done
  for br in br-lab-lan br-lab-wan br-lab-mgmt; do ip link del "$br" 2>/dev/null; done
  log "ambiente removido"
}

status() {
  ip -br addr show | grep -E "br-lab|vh-" ; for ns in fw srv cli inet; do echo "== $ns"; nsx "$ns" ip -br addr; done
}

case "${1:-}" in
  up) up ;; down) down ;; status) status ;; *) echo "uso: $0 up|down|status"; exit 1 ;;
esac
