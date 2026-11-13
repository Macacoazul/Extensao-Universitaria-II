#!/bin/bash
# Inicializacao dos hosts da LAN (server/cliente)
set -u
log() { echo "[$ROLE] $*"; }

# 1) Rota padrao pelo firewall (o trafego da LAN sai somente pelo firewall)
ip route replace default via "${FW_LAN_IP}" && log "rota padrao via ${FW_LAN_IP}"

# 2) Syslog local (gera /var/log/auth.log e /var/log/syslog)
rm -f /run/rsyslogd.pid; rsyslogd

# 3) Servicos do servidor
if [ "$ROLE" = "server" ]; then
  if ! id "${LAB_SSH_USER}" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "${LAB_SSH_USER}"
    echo "${LAB_SSH_USER}:${LAB_SSH_PASSWORD}" | chpasswd
    log "usuario ${LAB_SSH_USER} criado"
  fi
  mkdir -p /run/sshd /var/www/html && ssh-keygen -A >/dev/null
  [ -f /var/www/html/index.html ] && grep -q "Laboratorio SOC" /var/www/html/index.html || cp /opt/lab-www/index.html /var/www/html/index.html
  /usr/sbin/sshd && log "sshd ativo"
  nginx && log "nginx ativo"
fi

# 4) Agente Wazuh: aponta para o manager e define o nome do agente
CONF=/var/ossec/etc/ossec.conf
sed -i "s#<address>.*</address>#<address>${WAZUH_MANAGER_IP}</address>#" "$CONF"
if grep -q "<agent_name>" "$CONF"; then
  sed -i "s#<agent_name>.*</agent_name>#<agent_name>${WAZUH_AGENT_NAME}</agent_name>#" "$CONF"
else
  sed -i "s#<enrollment>#<enrollment>\n      <agent_name>${WAZUH_AGENT_NAME}</agent_name>#" "$CONF"
fi
/var/ossec/bin/wazuh-control start && log "agente Wazuh iniciado (${WAZUH_AGENT_NAME} -> ${WAZUH_MANAGER_IP})"

touch /var/log/auth.log /var/log/syslog
exec tail -F /var/log/auth.log /var/ossec/logs/ossec.log
