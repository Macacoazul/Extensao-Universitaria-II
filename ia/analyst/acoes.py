"""Aprovacao manual das recomendacoes (bloqueio/desbloqueio).

  python -m analyst.acoes bloquear --ip 192.168.10.20 [--agente lab-server]
  python -m analyst.acoes desbloquear --ip 192.168.10.20
  python -m analyst.acoes listar
As mesmas salvaguardas do AUTO_BLOCK valem aqui (so IPs do lab, nunca protegidos).
"""
from __future__ import annotations

import argparse
import sys

import requests

from analyst.config import Config
from analyst.prevention import block_agent, block_firewall
from analyst.wazuh_api import WazuhAPI


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("acao", choices=["bloquear", "desbloquear", "listar"])
    p.add_argument("--ip")
    p.add_argument("--agente", action="append", default=[])
    args = p.parse_args()
    cfg = Config()
    if args.acao == "listar":
        r = requests.get(f"{cfg.fw_api_url}/blocklist", headers={"X-Token": cfg.fw_api_token}, timeout=10)
        print(r.text)
        return
    ok, why = cfg.ip_allowed_for_block(args.ip)
    if not ok:
        sys.exit(f"recusado: {why}")
    if args.acao == "desbloquear":
        r = requests.post(f"{cfg.fw_api_url}/unblock", headers={"X-Token": cfg.fw_api_token},
                          json={"ip": args.ip}, timeout=10)
        print(r.text)
        print("Obs.: regras firewall-drop aplicadas nos agentes saem ao reiniciar o container do agente.")
        return
    print(block_firewall(cfg, args.ip, "aprovacao manual"))
    api = WazuhAPI(cfg.wazuh_api_url, cfg.wazuh_api_user, cfg.wazuh_api_password)
    for agent in args.agente:
        print(block_agent(cfg, api, agent, args.ip))


if __name__ == "__main__":
    main()
