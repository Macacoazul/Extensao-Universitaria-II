"""Arquivos legiveis para o usuario em ia/ (recomendacoes, incidentes, saude)."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

REC_HEADER = """# Recomendacoes da IA (aguardando aprovacao)

Cada incidente analisado aparece abaixo. Com `AUTO_BLOCK=false` (padrao), NENHUMA
acao foi aplicada: copie o comando para aplicar o bloqueio depois de revisar.
As sugestoes de regra sao propostas do modelo e devem ser revisadas antes do uso.

"""


def _now() -> str:
    return datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def append_recommendation(out_dir: str, inc: dict, result: dict, plan: dict, applied: list[str]) -> None:
    path = Path(out_dir) / "recomendacoes.md"
    if not path.exists():
        path.write_text(REC_HEADER, encoding="utf-8")
    a = result["analysis"]
    mitre = ", ".join(f"{m.get('tecnica_id')} {m.get('tecnica')} ({m.get('tatica')})" for m in a.get("mitre", [])) or "—"
    rules = ", ".join(f"{rid} (n{r['level']} x{r['count']})" for rid, r in inc["rules"].items())
    sr = a.get("sugestao_regra") or {}
    lines = [
        f"## {inc['id']} — {a.get('classificacao')} / gravidade {a.get('gravidade')}",
        "",
        f"- **Registrado em:** {_now()} (analise em {result['seconds']} s, {a.get('origem_analise')})",
        f"- **Periodo dos alertas:** {inc.get('first_ts')} → {inc.get('last_ts')} ({inc['count']} alertas)",
        f"- **Origem:** {inc.get('srcip') or '—'} | **Agentes:** {', '.join(inc.get('agents', [])) or '—'}",
        f"- **Regras Wazuh:** {rules}",
        f"- **MITRE ATT&CK:** {mitre}",
        f"- **Reincidencia:** {'SIM' if result['recurrence'] else 'nao'}"
        + (f" ({len(result['prior'])} incidente(s) anterior(es): "
           f"{', '.join(p['id'] for p in result['prior'][:5])})" if result['prior'] else ""),
        f"- **Causa provavel:** {a.get('causa_provavel')}",
        f"- **Acao recomendada:** {a.get('acao_recomendada')}",
        f"- **Confianca da IA:** {a.get('confianca')}",
        "",
        f"**Decisao de bloqueio:** {'RECOMENDADO' if plan['bloquear'] else 'nao recomendado'} — {plan['motivo']}",
    ]
    if plan["acoes"]:
        lines += ["", "Comandos para aprovar (rodar na pasta do projeto):", "", "```powershell"]
        lines += [f"{x['comando']}    # {x['descricao']}" for x in plan["acoes"]]
        lines += ["```"]
    if applied:
        lines += ["", "**Aplicado automaticamente (AUTO_BLOCK=true, reincidencia confirmada):**"] + [f"- {x}" for x in applied]
    elif plan.get("bloquear"):
        lines += ["", "_Nao aplicado automaticamente: aguardando aprovacao (ou reincidencia, se AUTO_BLOCK=true)._"]
    if sr.get("tipo") and sr.get("tipo") != "nenhuma" and sr.get("conteudo"):
        lines += ["", f"Sugestao de regra ({sr['tipo']}) — revisar antes de usar: {sr.get('justificativa', '')}",
                  "", "```", sr["conteudo"].strip(), "```"]
    lines += ["", "---", ""]
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def write_incidents(out_dir: str, rows: list[dict]) -> None:
    lines = ["# Historico de incidentes (memoria da IA)", "", f"Atualizado em {_now()}.", "",
             "| Incidente | Inicio | Origem | Categoria | Regras | Nivel | Classificacao | Gravidade | Reincid. | Acao |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        a = json.loads(r.get("analysis") or "{}")
        lines.append(f"| {r['id']} | {r.get('first_ts') or ''} | {r.get('srcip') or ''} | {r.get('category')} | "
                     f"{r.get('rule_ids')} | {r.get('max_level')} | {a.get('classificacao', '')} | "
                     f"{a.get('gravidade', '')} | {'sim' if r.get('recurrence') else 'nao'} | {r.get('action') or ''} |")
    (Path(out_dir) / "incidentes.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def save_analysis_json(out_dir: str, inc: dict, result: dict, plan: dict, applied: list[str]) -> None:
    folder = Path(out_dir) / "analises"
    folder.mkdir(parents=True, exist_ok=True)
    doc = {"incidente": inc, "analise": result["analysis"], "reincidencia": result["recurrence"],
           "anteriores": [p["id"] for p in result["prior"]], "semelhantes": result["similar"],
           "prevencao": plan, "aplicado": applied, "tempo_s": result["seconds"], "prompt": result["prompt"]}
    (folder / f"{inc['id']}.json").write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
