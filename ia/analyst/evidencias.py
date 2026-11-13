"""Extrai as evidencias de um teste: alertas do Wazuh no intervalo + analises da IA.

Uso (dentro do container ai-analyst):
  python -m analyst.evidencias --id T3 --nome "Assinatura de teste" \
      --inicio 2026-11-13T10:00:00-03:00 --fim 2026-11-13T10:01:00-03:00 \
      --comando "curl http://testmynids.org/uid/index.html" --esperado "alerta GPL ATTACK_RESPONSE"
Gera /lab-testes/<ID>.md e /lab-testes/<ID>.json (pasta testes/ do projeto).
"""
from __future__ import annotations

import argparse
import json
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path

from analyst.alerts import iter_alerts_file, parse_ts
from analyst.config import Config
from analyst.memory import Memory


def collect(cfg: Config, start: datetime, end: datetime, grace_s: int) -> list[dict]:
    limit = end + timedelta(seconds=grace_s)
    out = []
    for a in iter_alerts_file(cfg.alerts_file):
        ts = a.ts
        if ts and start <= ts <= limit:
            out.append(a.summary())
    return out


def by_rule(alerts: list[dict]) -> list[dict]:
    rules: "OrderedDict[str, dict]" = OrderedDict()
    for a in alerts:
        r = rules.setdefault(a["rule_id"], {"rule_id": a["rule_id"], "level": a["level"],
                                            "description": a["description"], "count": 0,
                                            "first": a["timestamp"], "last": a["timestamp"],
                                            "srcips": set(), "agents": set(),
                                            "mitre": ", ".join(a["mitre"].get("id", []))})
        r["count"] += 1
        r["last"] = a["timestamp"]
        if a.get("srcip"):
            r["srcips"].add(a["srcip"])
        if a.get("agent"):
            r["agents"].add(a["agent"])
    rows = []
    for r in rules.values():
        r["srcips"] = ", ".join(sorted(r["srcips"]))
        r["agents"] = ", ".join(sorted(r["agents"]))
        rows.append(r)
    return sorted(rows, key=lambda r: (-r["level"], r["first"] or ""))


def render(meta: dict, rules: list[dict], incidents: list[dict]) -> str:
    lines = [f"# Teste {meta['id']} — {meta['nome']}", "",
             f"- **Comando:** `{meta['comando']}`",
             f"- **Inicio:** {meta['inicio']}  |  **Fim:** {meta['fim']}",
             f"- **Resultado esperado:** {meta['esperado']}",
             f"- **Resultado obtido (automatico):** {meta['obtido']}",
             "", "## Alertas do Wazuh no intervalo", ""]
    if rules:
        lines += ["| Regra | Nivel | Descricao | Qtde | Primeiro | Ultimo | Origem | Agente | MITRE |",
                  "|---|---|---|---|---|---|---|---|---|"]
        lines += [f"| {r['rule_id']} | {r['level']} | {r['description']} | {r['count']} | {r['first']} | "
                  f"{r['last']} | {r['srcips']} | {r['agents']} | {r['mitre']} |" for r in rules]
    else:
        lines.append("Nenhum alerta encontrado no intervalo.")
    lines += ["", "## Analise da IA", ""]
    if not incidents:
        lines.append("Nenhuma analise registrada no intervalo (o LLM pode ainda estar processando; "
                     "rode a extracao novamente em alguns minutos).")
    for inc in incidents:
        a = json.loads(inc.get("analysis") or "{}")
        mitre = ", ".join(f"{m.get('tecnica_id')} {m.get('tecnica')}" for m in a.get("mitre", [])) or "—"
        lines += [f"### {inc['id']} ({inc.get('category')}, origem {inc.get('srcip') or '—'})", "",
                  f"- Classificacao: **{a.get('classificacao')}** | Gravidade: **{a.get('gravidade')}** | "
                  f"Confianca: {a.get('confianca')}",
                  f"- Origem da analise: {a.get('origem_analise', 'llm')}",
                  f"- Regras: {inc.get('rule_ids')} | alertas agrupados: {inc.get('alert_count')} | "
                  f"nivel maximo: {inc.get('max_level')}",
                  f"- Causa provavel: {a.get('causa_provavel')}",
                  f"- MITRE ATT&CK: {mitre}",
                  f"- Acao recomendada: {a.get('acao_recomendada')}",
                  f"- Reincidencia: {'SIM' if inc.get('recurrence') else 'nao'} "
                  f"(incidentes anteriores da mesma origem: {inc.get('prior_count')})",
                  f"- Acao registrada: {inc.get('action')}",
                  f"- Resumo: {a.get('resumo')}", ""]
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--id", required=True)
    p.add_argument("--nome", required=True)
    p.add_argument("--inicio", required=True)
    p.add_argument("--fim", required=True)
    p.add_argument("--comando", default="")
    p.add_argument("--esperado", default="")
    p.add_argument("--grace", type=int, default=180, help="segundos apos o fim para incluir alertas")
    p.add_argument("--saida", default="/lab-testes")
    args = p.parse_args()

    cfg = Config()
    start, end = datetime.fromisoformat(args.inicio), datetime.fromisoformat(args.fim)
    alerts = collect(cfg, start, end, args.grace)
    rules = by_rule(alerts)
    limit = end + timedelta(seconds=args.grace)
    incidents = []
    for inc in reversed(Memory(cfg.state_dir).recent(1000)):     # pela hora dos ALERTAS do incidente
        first = parse_ts(inc.get("first_ts"))
        if first and start <= first <= limit:
            incidents.append(inc)
    top = rules[0] if rules else None
    obtido = (f"{len(alerts)} alerta(s) em {len(rules)} regra(s); mais grave: regra {top['rule_id']} "
              f"nivel {top['level']} ({top['description']})") if top else "nenhum alerta"
    meta = {"id": args.id, "nome": args.nome, "comando": args.comando, "inicio": args.inicio,
            "fim": args.fim, "esperado": args.esperado, "obtido": obtido}
    out = Path(args.saida)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.id}.md").write_text(render(meta, rules, incidents), encoding="utf-8")
    (out / f"{args.id}.json").write_text(json.dumps(
        {"meta": meta, "regras": rules, "alertas": alerts[:500], "incidentes": incidents},
        ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(f"{args.id}: {obtido}")
    print(f"evidencias gravadas em testes/{args.id}.md")


if __name__ == "__main__":
    main()
