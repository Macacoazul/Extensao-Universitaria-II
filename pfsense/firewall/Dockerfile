# Firewall/roteador do laboratorio (opcao "c": container Linux com nftables
# replicando as regras que seriam aplicadas no pfSense). Ver pfsense/README.md.
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nftables ulogd2 rsyslog iproute2 iputils-ping tcpdump python3 procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY nftables.conf.tpl /etc/lab-fw/nftables.conf.tpl
COPY ulogd.conf /etc/ulogd.conf
COPY rsyslog.conf.tpl /etc/lab-fw/rsyslog.conf.tpl
COPY fw_api.py /usr/local/bin/fw_api.py
COPY fw-block fw-unblock fw-status entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/fw-block /usr/local/bin/fw-unblock /usr/local/bin/fw-status /usr/local/bin/entrypoint.sh \
 && mkdir -p /var/log/ulogd /var/log/lab-fw
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
