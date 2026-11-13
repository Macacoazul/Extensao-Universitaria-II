"""Prevencao: transforma a analise em acoes recomendadas e (opcionalmente) aplica.

Por padrao (AUTO_BLOCK=false) NADA e aplicado: as acoes vao para
ia/recomendacoes.md com os comandos prontos para aprovacao manual.
Com AUTO_BLOCK=true, o bloqueio so acontece se:
  * (padrao) houver REINCIDENCIA (AUTO_BLOCK_REQUIRE_RECURRENCE=true): a primeira
    ocorrencia grave gera apenas recomendacao;
  * o IP de origem pertence as redes do lab (AUTO_BLOCK_NETWORKS);
  * o IP nao esta na lista de protegidos (gateway, Wazuh, IA);
  * houve reincidencia OU a gravidade e alta/critica;
  * a IA nao classificou como benigno / falso positivo provavel.
"""
from __future__ import annotations

import logging

import requests

from analyst.config import Config
from analyst.wazuh_api import WazuhAPI

log = logging.getLogger(__name__)

MANAGER_NAMES = {"wazuh.manager", "wazuh-manager", "siem-emulador"}


def plan(cfg: Config, inc: dict, analysis: dict, recurrence: bool) -> dict:
    ip = inc.get("srcip")
    eligible, why = cfg.ip_allowed_for_block(ip)
    grave = analysis.get("gravidade") in ("alta", "critica")
    benign = analysis.get("classificacao") in ("benigno", "falso_positivo_provavel")
    should = eligible and (recurrence or grave) and not benign
    agents = [a for a in inc.get("agents", []) if a not in MANAGER_NAMES]
    actions = []
    if should:
        actions.append({"tipo": "firewall-blocklist",
                        "descricao": f"Quarentena de {ip} no firewall por {cfg.fw_block_timeout} "
                                     "(bloqueia o trafego roteado: internet e gerencia, inclusive o agente Wazuh do host)",
                        "comando": f"docker compose exec firewall fw-block {ip} {cfg.fw_block_timeout}"})
        for a in agents:
            actions.append({"tipo": "wazuh-active-response",
                            "descricao": f"firewall-drop (iptables) no agente {a}: bloqueia {ip} dentro da LAN",
                            "comando": f"docker compose exec ai-analyst python -m analyst.acoes bloquear "
                                       f"--ip {ip} --agente {a}"})
    motivo = why if not eligible else (
        "reincidencia detectada" if recurrence else ("gravidade " + analysis.get("gravidade", "?")) if grave
        else "sem reincidencia e gravidade abaixo de alta: apenas monitorar")
    if eligible and benign:
        motivo = "IA classificou como benigno/falso positivo provavel: nao bloquear"
    auto = should and cfg.auto_block and (recurrence or not cfg.auto_block_require_recurrence)
    return {"bloquear": should, "elegivel": eligible, "motivo": motivo, "acoes": actions, "agentes": agents,
            "aplicar_auto": auto, "reincidencia": recurrence}


def block_firewall(cfg: Config, ip: str, reason: str) -> str:
    r = requests.post(f"{cfg.fw_api_url}/block", headers={"X-Token": cfg.fw_api_token}, timeout=10,
                      json={"ip": ip, "timeout": cfg.fw_block_timeout, "reason": reason})
    if r.status_code != 200:
        return f"firewall: ERRO {r.status_code} {r.text[:200]}"
    return f"firewall: {ip} em quarentena por {cfg.fw_block_timeout}"


def block_agent(cfg: Config, api: WazuhAPI, agent: str, ip: str) -> str:
    agent_id = api.agent_id(agent)
    if not agent_id:
        return f"active-response: agente {agent} nao encontrado"
    res = api.firewall_drop(agent_id, ip)
    failed = res.get("data", {}).get("total_failed_items", 0)
    return f"active-response: firewall-drop {ip} no agente {agent} ({agent_id})" + (" COM FALHA" if failed else "")


_AR_DONE: set[tuple[str, str]] = set()   # (agente, ip) ja bloqueados por active response nesta execucao


def firewall_blocked(cfg: Config, ip: str) -> bool:
    try:
        r = requests.get(f"{cfg.fw_api_url}/blocklist", headers={"X-Token": cfg.fw_api_token}, timeout=5)
        return r.status_code == 200 and ip in (r.json().get("blocklist") or [])
    except (requests.RequestException, ValueError):
        return False


def execute(cfg: Config, api: WazuhAPI, p: dict, inc: dict) -> list[str]:
    """Aplica o plano (somente com AUTO_BLOCK=true e plano elegivel). Idempotente."""
    if not p.get("aplicar_auto"):
        return []
    ip = inc["srcip"]
    results = []
    try:
        if firewall_blocked(cfg, ip):
            results.append(f"firewall: {ip} ja estava em quarentena")
        else:
            results.append(block_firewall(cfg, ip, f"{inc['id']} {p['motivo']}"))
    except requests.RequestException as exc:
        results.append(f"firewall: falha ({exc.__class__.__name__})")
    for agent in p.get("agentes", []):
        if (agent, ip) in _AR_DONE:
            results.append(f"active-response: {ip} ja bloqueado no agente {agent}")
            continue
        try:
            res = block_agent(cfg, api, agent, ip)
            results.append(res)
            if "FALHA" not in res and "nao encontrado" not in res:
                _AR_DONE.add((agent, ip))
        except requests.RequestException as exc:
            results.append(f"active-response em {agent}: falha ({exc.__class__.__name__})")
    log.warning("AUTO_BLOCK aplicado para %s: %s", ip, results)
    return results
