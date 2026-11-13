# =============================================================================
# Regras do firewall do lab (equivalentes as regras planejadas para o pfSense)
# Politica: negar tudo por padrao e liberar apenas o necessario.
# Variaveis ${...} sao substituidas pelo entrypoint.sh a partir do .env.
# =============================================================================
flush ruleset

define WAN_IF  = "${WAN_IF}"
define LAN_IF  = "${LAN_IF}"
define MGMT_IF = "${MGMT_IF}"
define LAN_NET = ${LAN_SUBNET}
define WAZUH   = ${WAZUH_MANAGER_IP}
define ANALYST = ${AI_ANALYST_IP}

table inet filter {
    # Lista de bloqueio dinamica (usada pela API / IA e pelo comando fw-block)
    set blocklist {
        type ipv4_addr
        flags timeout
    }

    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
        ct state invalid drop
        # Ping ao gateway a partir da LAN (diagnostico)
        iifname $LAN_IF icmp type echo-request accept
        # API de bloqueio: somente o ai-analyst, pela rede de gerencia
        iifname $MGMT_IF ip saddr $ANALYST tcp dport 8088 accept
        limit rate 20/second burst 40 packets log prefix "FW-DROP-IN " group 1
        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        ct state invalid drop

        # 1) IPs bloqueados (resposta a incidentes)
        ip saddr @blocklist limit rate 20/second log prefix "FW-BLOCKLIST " group 1
        ip saddr @blocklist counter drop
        ip daddr @blocklist counter drop

        # 2) LAN -> Internet: somente servicos necessarios
        iifname $LAN_IF oifname $WAN_IF ip saddr $LAN_NET udp dport { 53, 123 } counter accept
        iifname $LAN_IF oifname $WAN_IF ip saddr $LAN_NET tcp dport { 53, 80, 443 } counter accept
        iifname $LAN_IF oifname $WAN_IF ip saddr $LAN_NET icmp type echo-request counter accept

        # 3) LAN -> Gerencia: somente agentes Wazuh (eventos 1514, registro 1515)
        iifname $LAN_IF oifname $MGMT_IF ip daddr $WAZUH tcp dport { 1514, 1515 } counter accept

        # 4) Todo o resto: registra e bloqueia
        limit rate 50/second burst 100 packets log prefix "FW-DROP " group 1
        counter drop
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # NAT de saida (equivalente ao Outbound NAT automatico do pfSense)
        oifname $WAN_IF ip saddr $LAN_NET masquerade
    }
}
