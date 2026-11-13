"""Relatorio periodico de saude do laboratorio (ia/saude.md).

Verifica, a partir da rede de gerencia:
* servicos respondendo (firewall, Wazuh manager/indexer/dashboard, Ollama);
* agentes Wazuh conectados (API do Wazuh) -> Server e Cliente ativos;
* Suricata gerando eventos (idade e crescimento do eve.json);
* alertas chegando ao Wazuh (idade do alerts.json).
O estado de cada container e inferido pelo servico que ele expoe; a lista
completa de containers vem de `docker compose ps` (scripts/status.ps1).
"""
from __future__ import annotations

import json
import os
import socket
from datetime import datetime
from pathlib import Path

import requests

from analyst.alerts import file_age_seconds
from analyst.config import Config
from analyst.wazuh_api import WazuhAPI


def tcp_ok(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check(cfg: Config, api: WazuhAPI, prev: dict | None = None) -> dict:
    res: dict = {"timestamp": datetime.now().astimezone().isoformat(timespec="seconds"), "servicos": {},
                 "agentes": [], "suricata": {}, "wazuh_alertas": {}, "modelos": []}
    for item in cfg.health_targets:
        name, _, hp = item.partition("=")
        host, _, port = hp.rpartition(":")
        res["servicos"][name] = tcp_ok(host, int(port))
    try:
        res["agentes"] = api.agents()
    except Exception as exc:  # noqa: BLE001 - relatorio deve sair mesmo com erro
        res["agentes_erro"] = str(exc)[:200]
    size = os.path.getsize(cfg.suricata_eve) if os.path.exists(cfg.suricata_eve) else None
    res["suricata"] = {"eve_existe": size is not None, "tamanho_bytes": size,
                       "idade_ultima_escrita_s": file_age_seconds(cfg.suricata_eve),
                       "cresceu_desde_ultima_verificacao": None}
    if prev and size is not None and prev.get("suricata", {}).get("tamanho_bytes") is not None:
        res["suricata"]["cresceu_desde_ultima_verificacao"] = size > prev["suricata"]["tamanho_bytes"]
    res["wazuh_alertas"] = {"idade_ultimo_alerta_s": file_age_seconds(cfg.alerts_file)}
    try:
        tags = requests.get(f"{cfg.ollama_url}/api/tags", timeout=5).json().get("models", [])
        res["modelos"] = [t.get("name") for t in tags]
    except requests.RequestException:
        res["modelos"] = []
    return res


def status_of(res: dict, cfg: Config) -> tuple[str, list[str]]:
    problems = [f"servico {n} sem resposta" for n, ok in res["servicos"].items() if not ok]
    active = [a for a in res.get("agentes", []) if a.get("status") == "active" and a.get("id") != "000"]
    if len(active) < 2:
        problems.append(f"apenas {len(active)} agente(s) ativo(s) (esperado: Server e Cliente)")
    age = res["suricata"].get("idade_ultima_escrita_s")
    if age is None:
        problems.append("eve.json do Suricata nao encontrado")
    elif age > 300:
        problems.append(f"Suricata sem eventos novos ha {int(age)} s")
    if not any(m.split(":")[0] == cfg.llm_model.split(":")[0] for m in res["modelos"]):
        problems.append(f"modelo {cfg.llm_model} nao carregado no Ollama")
    return ("OK" if not problems else "ATENCAO"), problems


def write(cfg: Config, res: dict) -> str:
    status, problems = status_of(res, cfg)
    ok = lambda b: "OK" if b else "FALHA"  # noqa: E731
    lines = [f"# Saude do laboratorio — {status}", "", f"Verificado em {res['timestamp']}.", ""]
    if problems:
        lines += ["**Problemas:**"] + [f"- {p}" for p in problems] + [""]
    lines += ["## Servicos", "", "| Servico | Estado |", "|---|---|"]
    lines += [f"| {n} | {ok(v)} |" for n, v in res["servicos"].items()]
    lines += ["", "## Agentes Wazuh", "", "| ID | Nome | IP | Status | Versao |", "|---|---|---|---|---|"]
    lines += [f"| {a.get('id')} | {a.get('name')} | {a.get('ip')} | {a.get('status')} | {a.get('version', '')} |"
              for a in res.get("agentes", [])]
    if res.get("agentes_erro"):
        lines.append(f"\nErro ao consultar a API do Wazuh: {res['agentes_erro']}")
    s = res["suricata"]
    lines += ["", "## Suricata", "",
              f"- eve.json: {'existe' if s['eve_existe'] else 'NAO encontrado'}; tamanho {s['tamanho_bytes']} bytes",
              f"- ultima escrita ha: {int(s['idade_ultima_escrita_s']) if s['idade_ultima_escrita_s'] is not None else '—'} s",
              f"- cresceu desde a ultima verificacao: {s['cresceu_desde_ultima_verificacao']}",
              "", "## Wazuh / IA", "",
              f"- ultimo alerta gravado ha: {int(res['wazuh_alertas']['idade_ultimo_alerta_s']) if res['wazuh_alertas']['idade_ultimo_alerta_s'] is not None else '—'} s",
              f"- modelos no Ollama: {', '.join(res['modelos']) or 'nenhum'}", ""]
    Path(cfg.out_dir, "saude.md").write_text("\n".join(lines), encoding="utf-8")
    with Path(cfg.state_dir, "saude.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({**res, "status": status, "problemas": problems}, ensure_ascii=False) + "\n")
    return status
