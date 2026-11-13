"""Monta o contexto (incidente + memoria) e obtem a analise do LLM."""
from __future__ import annotations

import json

from analyst.config import Config
from analyst.llm import OllamaClient
from analyst.memory import Memory


def behavior_text(inc: dict) -> str:
    """Texto usado no embedding: descreve o COMPORTAMENTO (sem IPs), para achar casos parecidos."""
    rules = "; ".join(f"{r['description']} (nivel {r['level']}, {r['count']}x)" for r in inc["rules"].values())
    return f"categoria {inc['category']}. regras: {rules}. motivo: {inc['reason']}"


# Playbooks de contingencia: usados quando o LLM nao responde (ou responde sem JSON valido).
# Sao conhecimento fixo por categoria + dados do proprio incidente; nao substituem o LLM.
PLAYBOOKS = {
    "autenticacao_ssh": {
        "causa": "Varias falhas de autenticacao SSH a partir da mesma origem em pouco tempo, padrao "
                 "compativel com tentativa de adivinhacao de senha (forca bruta).",
        "acao": "Bloquear temporariamente a origem; verificar se houve login bem-sucedido apos as falhas "
                "(regra 5715); exigir chave SSH/MFA, limitar tentativas (MaxAuthTries) e revisar contas expostas.",
        "regra": ("active-response",
                  "<active-response>\n  <command>firewall-drop</command>\n  <location>local</location>\n"
                  "  <rules_id>5763,5712</rules_id>\n  <timeout>600</timeout>\n</active-response>",
                  "Resposta automatica do Wazuh a forca bruta SSH, com bloqueio temporario de 10 minutos."),
    },
    "varredura": {
        "causa": "Muitas tentativas de conexao a servicos/portas diferentes a partir da mesma origem, "
                 "compativel com descoberta de servicos na rede (T1046).",
        "acao": "Identificar o processo/usuario que gerou as conexoes no host de origem; isolar o host se a "
                "atividade nao for autorizada; manter a politica default-deny entre segmentos.",
        "regra": ("firewall",
                  "nft add rule inet filter forward iifname $LAN_IF ct state new meter scan "
                  "{ ip saddr limit rate over 30/minute } log prefix \"FW-SCAN \" group 1 drop",
                  "Limita novas conexoes por origem para conter varreduras."),
    },
    "ids_assinatura": {
        "causa": "O trafego correspondeu a uma assinatura do IDS (Suricata); a evidencia e o conteudo do "
                 "pacote/fluxo descrito na assinatura.",
        "acao": "Conferir origem, destino e payload do fluxo no eve.json; confirmar se e teste autorizado; "
                "se nao for, investigar o host interno envolvido.",
        "regra": ("suricata", "Manter a assinatura habilitada; se for teste recorrente autorizado, usar "
                  "threshold/suppress apenas para o IP de teste.",
                  "Evitar falsos positivos de testes sem perder a deteccao."),
    },
    "integridade_arquivos": {
        "causa": "Arquivo monitorado pelo FIM foi criado ou alterado (conteudo/hash diferente da linha de base).",
        "acao": "Confirmar se a mudanca foi planejada (gestao de mudancas); analisar o diff registrado; "
                "restaurar do backup se a alteracao nao for autorizada.",
        "regra": ("wazuh",
                  "<rule id=\"100300\" level=\"10\">\n  <if_sid>550</if_sid>\n  "
                  "<field name=\"file\">^/var/www</field>\n  <description>Conteudo web alterado: "
                  "$(file)</description>\n</rule>",
                  "Eleva a prioridade de alteracoes no conteudo publicado do servidor web."),
    },
    "firewall": {
        "causa": "Trafego negado pela politica do firewall: a origem tentou acessar destinos/portas nao liberados.",
        "acao": "Verificar qual aplicacao no host de origem gera o trafego; manter o bloqueio; investigar se "
                "o volume indicar varredura.",
        "regra": ("nenhuma", "", "A politica atual ja bloqueia e registra o trafego."),
    },
}


def fallback_analysis(inc: dict) -> dict:
    """Analise de contingencia (sem LLM): playbook da categoria + dados do incidente."""
    lvl = inc.get("max_level", 0)
    grav = "critica" if lvl >= 12 else "alta" if lvl >= 10 else "media" if lvl >= 7 else "baixa"
    seen, mitre = set(), []
    for r in inc["rules"].values():
        m = r.get("mitre") or {}
        techniques = m.get("technique") or []
        for i, tid in enumerate(m.get("id", [])):
            if tid in seen:
                continue
            seen.add(tid)
            mitre.append({"tecnica_id": tid,
                          "tecnica": techniques[i] if i < len(techniques) else "",
                          "tatica": ", ".join(m.get("tactic", []))})
    pb = PLAYBOOKS.get(inc.get("category"), {})
    tipo, conteudo, just = pb.get("regra", ("nenhuma", "", "sem playbook para a categoria"))
    rules = ", ".join(f"{rid} ({r['description']})" for rid, r in inc["rules"].items())
    return {
        "classificacao": "suspeito" if (lvl >= 7 or inc.get("count", 0) >= 10) else "benigno",
        "gravidade": grav,
        "causa_provavel": pb.get("causa", "Alertas do Wazuh sem playbook especifico para a categoria."),
        "mitre": mitre,
        "acao_recomendada": pb.get("acao", "Verificar os eventos de origem e confirmar se a atividade era esperada."),
        "sugestao_regra": {"tipo": tipo, "conteudo": conteudo, "justificativa": just},
        "reincidencia": False,
        "confianca": "media" if pb else "baixa",
        "resumo": f"{inc['count']} alerta(s) da categoria {inc['category']} (nivel maximo {lvl}) "
                  f"de {inc.get('srcip') or 'origem nao informada'}: {rules}.",
    }


def build_prompt(inc: dict, prior: list[dict], similar: list[dict]) -> str:
    lines = [
        f"INCIDENTE {inc['id']}",
        f"Motivo da triagem: {inc['reason']}",
        f"Categoria: {inc['category']}",
        f"Origem (srcip): {inc.get('srcip') or 'nao informada'}",
        f"Destinos: {', '.join(inc.get('dstips', [])) or 'n/d'}",
        f"Agentes/fontes: {', '.join(inc.get('agents', [])) or 'n/d'}",
        f"Periodo: {inc.get('first_ts')} -> {inc.get('last_ts')} | alertas: {inc['count']} | "
        f"nivel maximo: {inc['max_level']}",
        "Regras disparadas:",
    ]
    for rid, r in inc["rules"].items():
        m = r.get("mitre") or {}
        mitre = ", ".join(f"{t} ({', '.join(m.get('tactic', []))})" for t in m.get("id", [])) or "sem mapeamento"
        lines.append(f"- {rid} (nivel {r['level']}, {r['count']}x): {r['description']} | MITRE: {mitre}")
    lines.append("Amostras de eventos:")
    for s in inc.get("samples", [])[:5]:
        detail = s.get("signature") or s.get("file") or s.get("full_log") or ""
        lines.append(f"- {s.get('timestamp')} regra {s.get('rule_id')} agente {s.get('agent')} "
                     f"{s.get('srcip') or ''}->{s.get('dstip') or ''}:{s.get('dstport') or ''} | {detail[:250]}")
    lines.append("")
    lines.append("MEMORIA DO SOC (incidentes anteriores):")
    if prior:
        lines.append(f"- {len(prior)} incidente(s) anterior(es) da MESMA origem e categoria/regra:")
        for p in prior[:5]:
            a = json.loads(p.get("analysis") or "{}")
            lines.append(f"  - {p['id']} em {p.get('first_ts')}: {a.get('classificacao')}/{a.get('gravidade')}; "
                         f"acao: {p.get('action') or 'nenhuma'}")
    else:
        lines.append("- nenhum incidente anterior desta origem")
    if similar:
        lines.append("- Casos semelhantes (similaridade semantica):")
        for s in similar:
            a = json.loads(s.get("analysis") or "{}")
            lines.append(f"  - {s['id']} (score {s['score']}, origem {s.get('srcip')}): {a.get('resumo', '')[:200]}")
    lines.append("")
    lines.append("Responda apenas com o JSON do esquema.")
    return "\n".join(lines)


def analyze(cfg: Config, llm: OllamaClient, memory: Memory, inc: dict) -> dict:
    rule_ids = list(inc["rules"].keys())
    prior = memory.prior(inc.get("srcip"), inc["category"], rule_ids, inc.get("first_ts"))
    recurrence = len(prior) >= cfg.recurrence_threshold
    text = behavior_text(inc)
    embedding = llm.embed(text)
    similar = memory.similar(embedding, k=3, min_score=cfg.similarity_min)
    prompt = build_prompt(inc, prior, similar)
    analysis, seconds, raw = llm.analyze(prompt, fallback_analysis(inc))
    if recurrence:
        analysis["reincidencia"] = True
    return {"analysis": analysis, "recurrence": recurrence, "prior": prior, "similar": similar,
            "embedding": embedding, "summary": text, "seconds": round(seconds, 1), "prompt": prompt,
            "raw": raw}
