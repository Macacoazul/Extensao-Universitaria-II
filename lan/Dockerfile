# Hosts da LAN (Ubuntu Server e Ubuntu Cliente) com agente Wazuh.
# ROLE=server  -> SSH + Nginx (alvo/servicos)
# ROLE=cliente -> estacao de usuario (origem dos testes)
FROM ubuntu:24.04
ARG ROLE=cliente
ARG WAZUH_VERSION=4.14.10
ENV ROLE=${ROLE} DEBIAN_FRONTEND=noninteractive TZ=America/Sao_Paulo

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg iproute2 iptables iputils-ping netcat-openbsd dnsutils \
      rsyslog procps tzdata less nano openssh-client python3 \
 && if [ "$ROLE" = "server" ]; then apt-get install -y --no-install-recommends openssh-server nginx; fi \
 && rm -rf /var/lib/apt/lists/*

# Agente Wazuh (repositorio oficial). O endereco do manager e o nome do agente
# sao ajustados no entrypoint, a partir das variaveis do compose.
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && WAZUH_MANAGER=127.0.0.1 apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 \
 && rm -rf /var/lib/apt/lists/*

# rsyslog sem o modulo de kernel (nao existe dentro de container)
RUN sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf

COPY sshd-lab.conf /etc/ssh/sshd_config.d/lab.conf
COPY www/ /opt/lab-www/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
