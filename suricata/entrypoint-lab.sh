#!/bin/sh
# Sensor IDS do laboratorio.
# Roda no namespace de rede do HOST (VM do Docker Desktop) e escuta a bridge
# da LAN (br-lab-lan) em modo promiscuo: assim enxerga o trafego entre Cliente
# e Server (que e comutado pela bridge e NAO passa pelo firewall) e tambem o
# trafego que vai da LAN para o firewall.
set -e
IFACE="${SURICATA_IFACE:-br-lab-lan}"
HOME_NET="${SURICATA_HOME_NET:-[192.168.10.0/24]}"

for i in $(seq 1 60); do [ -e "/sys/class/net/$IFACE" ] && break; sleep 1; done
[ -e "/sys/class/net/$IFACE" ] || { echo "[suricata] interface $IFACE nao existe"; ls /sys/class/net; exit 1; }

echo "[suricata] atualizando regras ET Open (suricata-update) + regras locais do lab"
suricata-update update-sources >/dev/null 2>&1 || true
suricata-update --no-test --local /etc/suricata/lab/local.rules \
  || echo "[suricata] AVISO: suricata-update falhou; usando as regras ja existentes"

echo "[suricata] iniciando em $IFACE (HOME_NET=$HOME_NET)"
exec /docker-entrypoint.sh -k none --af-packet="$IFACE" \
  --set "vars.address-groups.HOME_NET=$HOME_NET"
