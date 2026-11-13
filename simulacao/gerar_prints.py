"""Gera as capturas (prints/) do AMBIENTE EXPERIMENTAL com Playwright headless.

Cada print e uma renderizacao fiel de um artefato real da execucao:
saidas de terminal (testes/saidas), evidencias e analises (testes/T*.md,
ia/*.md) e o painel de alertas montado a partir do alerts.json (formato Wazuh)
produzido pelo emulador do SIEM. Todo print traz a faixa
"Ambiente experimental — situacoes hipoteticas".
"""
from __future__ import annotations

import html
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

import markdown
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "prints"
SAIDAS = ROOT / "testes" / "saidas"
ALERTS = Path("/var/ossec/logs/alerts/alerts.json")
FAIXA = "AMBIENTE EXPERIMENTAL — teste realizado com máquinas simuladas e situações hipotéticas"
LOG: list[str] = []
N = [0]

CSS_BASE = """
body{margin:0;font-family:'Segoe UI',Roboto,'DejaVu Sans',sans-serif;background:#f4f6f9;color:#1d2330}
.faixa{background:#7a4b00;color:#fff;font-size:12px;padding:5px 14px;letter-spacing:.3px}
.bar{background:#2b3240;color:#e8ebf0;padding:9px 14px;font-size:14px;font-weight:600}
"""
CSS_TERM = CSS_BASE + """
pre{background:#1e1e1e;color:#d4d4d4;font:12.5px/1.4 'DejaVu Sans Mono',Consolas,monospace;padding:14px;margin:0;
    white-space:pre-wrap;word-break:break-all}
.cmd{color:#4ec9b0;font-weight:bold}.ok{color:#89d185}.blk{color:#f48771;font-weight:bold}.hl{color:#dcdcaa}
"""
CSS_DOC = CSS_BASE + """
.doc{background:#fff;margin:0;padding:18px 26px;font-size:13.5px;line-height:1.45}
.doc h1{font-size:20px;margin:4px 0 10px}.doc h2{font-size:16px;margin:16px 0 6px;color:#2b3a67}
.doc h3{font-size:14px;margin:12px 0 4px;color:#7a4b00}
table{border-collapse:collapse;width:100%;font-size:12px;margin:6px 0}
th,td{border:1px solid #d5dae3;padding:4px 6px;text-align:left;vertical-align:top}
th{background:#eef1f6}code,pre{background:#f1f3f6;font-size:12px}pre{padding:8px;white-space:pre-wrap}
.n10,.n12{background:#c62828;color:#fff;font-weight:700;text-align:center}.n8,.n7{background:#ef6c00;color:#fff;
font-weight:700;text-align:center}.n5,.n4{background:#f9a825;text-align:center}.n3,.n0{background:#cfd8dc;text-align:center}
.kpi{display:inline-block;background:#fff;border:1px solid #d5dae3;border-radius:6px;padding:8px 14px;margin:0 8px 10px 0}
.kpi b{display:block;font-size:20px}
"""


def dest(slug: str) -> Path:
    N[0] += 1
    return OUT / f"{N[0]:02d}_{slug}.png"


def shoot(page, doc: str, path: Path, width: int = 1280) -> None:
    page.set_viewport_size({"width": width, "height": 200})
    page.set_content(doc, wait_until="load")
    page.screenshot(path=str(path), full_page=True)
    LOG.append(path.name)


def color_terminal(text: str) -> str:
    out = []
    for line in html.escape(text).splitlines():
        if re.match(r"^\[\d{4}-\d\d-\d\dT[\d:]+[-+]\d\d:\d\d\] [\w.-]+:~\$", line):
            line = f'<span class="cmd">{line}</span>'
        elif re.search(r"BLOQUEADO|timed out|refused|DROP|FW-DROP|FW-BLOCKLIST|quarentena", line):
            line = f'<span class="blk">{line}</span>'
        elif re.search(r"LIBERADO|HTTP 200| 0% packet loss|bytes from|requisicao de 172\.20\.0\.2", line):
            line = f'<span class="ok">{line}</span>'
        elif line.startswith("&gt;&gt;&gt;"):
            line = f'<span class="hl">{line}</span>'
        out.append(line)
    return "\n".join(out)


def terminal(page, fname: str, slug: str, titulo: str) -> None:
    f = SAIDAS / fname
    if not f.exists():
        LOG.append(f"-- {fname} inexistente")
        return
    text = f.read_text(encoding="utf-8", errors="replace")
    doc = (f"<html><head><meta charset='utf-8'><style>{CSS_TERM}</style></head><body>"
           f"<div class='faixa'>{FAIXA}</div><div class='bar'>Terminal — {html.escape(titulo)}</div>"
           f"<pre>{color_terminal(text)}</pre></body></html>")
    shoot(page, doc, dest(slug))


def md_page(page, md_text: str, slug: str, titulo: str, width: int = 1280) -> None:
    body = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    doc = (f"<html><head><meta charset='utf-8'><style>{CSS_DOC}</style></head><body>"
           f"<div class='faixa'>{FAIXA}</div><div class='bar'>{html.escape(titulo)}</div>"
           f"<div class='doc'>{body}</div></body></html>")
    shoot(page, doc, dest(slug), width)


def image_page(page, img: Path, slug: str, titulo: str) -> None:
    import base64
    b64 = base64.b64encode(img.read_bytes()).decode()
    doc = (f"<html><head><meta charset='utf-8'><style>{CSS_DOC}</style></head><body>"
           f"<div class='faixa'>{FAIXA}</div><div class='bar'>{html.escape(titulo)}</div>"
           f"<div class='doc'><img style='width:100%' src='data:image/png;base64,{b64}'></div></body></html>")
    shoot(page, doc, dest(slug), 1600)


def alert_panel(page, alerts: list[dict], slug: str, titulo: str) -> None:
    by_level: dict[int, int] = {}
    for a in alerts:
        by_level[a["rule"]["level"]] = by_level.get(a["rule"]["level"], 0) + 1
    kpis = "".join(f"<span class='kpi'><b>{v}</b>alertas nível {k}</span>"
                   for k, v in sorted(by_level.items(), reverse=True))
    rows = []
    for a in alerts[-60:]:
        r, d = a["rule"], a.get("data", {})
        src = d.get("srcip") or d.get("src_ip") or ""
        dst = d.get("dstip") or d.get("dest_ip") or ""
        path = a.get("syscheck", {}).get("path", "")
        mitre = ", ".join(r.get("mitre", {}).get("id", []))
        lvl = r["level"]
        rows.append(f"<tr><td>{html.escape(a['timestamp'][11:23])}</td><td>{html.escape(a['agent']['name'])}</td>"
                    f"<td>{r['id']}</td><td class='n{lvl}'>{lvl}</td><td>{html.escape(r['description'])}</td>"
                    f"<td>{html.escape(src)}</td><td>{html.escape(dst or path)}</td><td>{mitre}</td></tr>")
    table = ("<table><tr><th>Hora</th><th>Agente</th><th>Regra</th><th>Nível</th><th>Descrição</th>"
             "<th>Origem</th><th>Destino / arquivo</th><th>MITRE</th></tr>" + "".join(rows) + "</table>")
    nota = ("<p style='font-size:11.5px;color:#555'>Painel gerado a partir do <code>alerts.json</code> "
            "(formato Wazuh) produzido no ambiente experimental. Não é o dashboard do Wazuh.</p>")
    doc = (f"<html><head><meta charset='utf-8'><style>{CSS_DOC}</style></head><body>"
           f"<div class='faixa'>{FAIXA}</div><div class='bar'>{html.escape(titulo)}</div>"
           f"<div class='doc'>{kpis}{table}{nota}</div></body></html>")
    shoot(page, doc, dest(slug), 1400)


def rec_section(inc_id: str) -> str:
    text = (ROOT / "ia" / "recomendacoes.md").read_text(encoding="utf-8")
    m = re.search(rf"(## {inc_id}.*?)\n---", text, flags=re.S)
    return m.group(1) if m else ""


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for old in OUT.glob("*.png"):
        old.unlink()
    alerts = [json.loads(line) for line in ALERTS.read_text().splitlines() if line.strip()] if ALERTS.exists() else []
    with sync_playwright() as p:
        b = p.chromium.launch()
        page = b.new_page()
        image_page(page, ROOT / "relatorio/diagramas/ambiente_experimental.png", "topologia_ambiente_experimental",
                   "Topologia do ambiente experimental (máquinas simuladas)")
        terminal(page, "status_containers.txt", "maquinas_e_servicos_ativos", "máquinas simuladas e serviços ativos")
        terminal(page, "01_fase1_infra.txt", "fase1_ping_rotas_nat", "Fase 1 — endereços, rotas, ping e NAT")
        terminal(page, "02_fase2_firewall.txt", "fase2_firewall_liberado_bloqueado", "Fase 2 — regras do firewall")
        terminal(page, "nft_ruleset.txt", "firewall_regras_nftables", "Regras ativas do firewall (nft list ruleset)")
        terminal(page, "03_fase3_ids_siem.txt", "fase3_suricata_e_siem", "Fases 3 e 4 — Suricata e coleta pelo SIEM")
        terminal(page, "05_fase5_ia.txt", "fase5_ai_analyst", "Fase 5 — ai-analyst")
        for n in range(1, 7):
            tj = ROOT / "testes" / f"T{n}.json"
            if not tj.exists():
                continue
            data = json.loads(tj.read_text(encoding="utf-8"))
            nome = data["meta"]["nome"]
            terminal(page, f"T{n}_saida.txt", f"teste{n}_terminal", f"Teste {n} — {nome}")
            ini = datetime.fromisoformat(data["meta"]["inicio"])
            fim = datetime.fromisoformat(data["meta"]["fim"]) + timedelta(seconds=12)
            janela = [a for a in alerts if ini <= datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") <= fim]
            alert_panel(page, janela, f"teste{n}_alertas_siem", f"Teste {n} — alertas no SIEM ({nome})")
            md_page(page, (ROOT / "testes" / f"T{n}.md").read_text(encoding="utf-8"), f"teste{n}_analise_ia",
                    f"Teste {n} — evidências e análise do ai-analyst")
            for inc in data.get("incidentes", []):
                if n in (2, 6) and inc.get("max_level", 0) >= 10:
                    sec = rec_section(inc["id"])
                    if sec:
                        md_page(page, sec, f"teste{n}_recomendacao_ia", f"Teste {n} — ia/recomendacoes.md ({inc['id']})")
        md_page(page, (ROOT / "ia" / "incidentes.md").read_text(encoding="utf-8"), "ia_historico_incidentes",
                "ia/incidentes.md — memória de incidentes da IA", 1500)
        md_page(page, (ROOT / "ia" / "saude.md").read_text(encoding="utf-8"), "ia_relatorio_saude",
                "ia/saude.md — relatório de saúde gerado pela IA")
        alert_panel(page, alerts, "painel_geral_alertas", "Painel geral — todos os alertas do experimento")
        terminal(page, "alertas_resumo.txt", "resumo_alertas_por_regra", "Resumo de alertas por regra")
        terminal(page, "firewall_log.txt", "firewall_logs", "Log do firewall (enviado ao SIEM por syslog)")
        b.close()
    (OUT / "prints_log.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
    print("\n".join(LOG))


if __name__ == "__main__":
    sys.exit(main())
