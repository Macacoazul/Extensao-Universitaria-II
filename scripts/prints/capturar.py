"""Fase 7: capturas de tela automaticas (Playwright headless, rede de gerencia).

1. Saidas de terminal (testes/saidas/*.txt) -> imagem estilo terminal
2. Dashboard do Wazuh: login, agentes, Threat Hunting, eventos de cada teste, FIM, MITRE
3. Arquivos da IA (recomendacoes, incidentes, saude) -> imagem
Tudo em prints/ com numeracao sequencial. Falhas ficam em prints/prints_log.txt
(indicando a tela para print manual).
"""
from __future__ import annotations

import html
import json
import os
import re
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = Path(os.environ.get("PRINTS_BASE", "/work"))
OUT = BASE / "prints"
SAIDAS = BASE / "testes" / "saidas"
URL = os.environ.get("DASHBOARD_URL", "https://wazuh.dashboard:5601").rstrip("/")
USER = os.environ.get("INDEXER_USERNAME", "admin")
PASS = os.environ.get("INDEXER_PASSWORD", "")
LOG: list[str] = []
N = [0]

TERMINAIS = [  # (arquivo em testes/saidas, nome do print)
    ("status_containers.txt", "topologia_containers"),
    ("01_fase1_infra.txt", "fase1_ping_rotas_internet"),
    ("02_fase2_firewall.txt", "fase2_regras_liberado_bloqueado"),
    ("nft_ruleset.txt", "firewall_regras_nftables"),
    ("firewall_log.txt", "firewall_logs"),
    ("03_fase3_wazuh_suricata.txt", "fase3_wazuh_suricata"),
    ("agentes_wazuh.txt", "wazuh_agentes_terminal"),
    ("05_fase5_ia.txt", "fase5_ia_ollama"),
] + [(f"T{i}_saida.txt", f"teste{i}_terminal") for i in range(1, 7)]


def name(slug: str) -> Path:
    N[0] += 1
    return OUT / f"{N[0]:02d}_{slug}.png"


def text_page(page, title: str, text: str, dest: Path) -> None:
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)[-15000:]
    doc = f"""<html><head><meta charset="utf-8"><style>
      body{{margin:0;background:#1e1e1e;font-family:Consolas,'DejaVu Sans Mono',monospace}}
      .bar{{background:#323233;color:#ccc;padding:8px 14px;font:13px sans-serif}}
      pre{{color:#d4d4d4;font-size:13px;line-height:1.35;padding:14px;margin:0;white-space:pre-wrap;word-break:break-all}}
    </style></head><body><div class="bar">{html.escape(title)}</div><pre>{html.escape(text)}</pre></body></html>"""
    page.set_viewport_size({"width": 1280, "height": 120})
    page.set_content(doc)
    page.screenshot(path=str(dest), full_page=True)
    LOG.append(f"OK  {dest.name} <- {title}")


def terminals(page) -> None:
    for fname, slug in TERMINAIS:
        f = SAIDAS / fname
        if f.exists():
            text_page(page, f"terminal: {fname}", f.read_text(encoding="utf-8-sig", errors="replace"), name(slug))
        else:
            LOG.append(f"--  {fname} nao existe (rode o comando correspondente do lab.ps1)")


def login(page) -> bool:
    try:
        page.goto(URL + "/app/login", wait_until="domcontentloaded", timeout=60000)
        page.fill('[data-test-subj="user-name"]', USER, timeout=30000)
        page.fill('[data-test-subj="password"]', PASS)
        page.click('[data-test-subj="submit"]')
        page.wait_for_url(re.compile(r".*/app/(?!login).*"), timeout=60000)
        page.wait_for_timeout(6000)
        return True
    except Exception as exc:  # noqa: BLE001 - qualquer falha -> prints manuais
        LOG.append(f"ERRO login no dashboard ({exc.__class__.__name__}) - prints do Wazuh devem ser manuais")
        return False


def shot(page, path: str, slug: str, query: str | None = None, wait_ms: int = 9000) -> None:
    dest = name(slug)
    try:
        page.goto(URL + path, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(wait_ms)
        if query:
            box = page.locator('[data-test-subj="queryInput"]').first
            box.click(timeout=15000)
            box.fill(query)
            box.press("Enter")
            page.wait_for_timeout(wait_ms)
        page.screenshot(path=str(dest), full_page=False)
        LOG.append(f"OK  {dest.name} <- {path} {query or ''}")
    except Exception as exc:  # noqa: BLE001
        LOG.append(f"ERRO {dest.name}: abrir manualmente {path} filtro '{query or ''}' ({exc.__class__.__name__})")


def dashboard(page) -> None:
    if not login(page):
        return
    page.set_viewport_size({"width": 1600, "height": 900})
    shot(page, "/app/wz-home", "wazuh_overview")
    shot(page, "/app/endpoints-summary#/agents-preview/", "wazuh_agentes")
    shot(page, "/app/threat-hunting#/overview/?tab=general&tabView=dashboard", "wazuh_security_events")
    shot(page, "/app/threat-hunting#/overview/?tab=general&tabView=events", "wazuh_eventos_suricata", "rule.groups:suricata")
    shot(page, "/app/threat-hunting#/overview/?tab=general&tabView=events", "wazuh_eventos_firewall", "rule.groups:lab-fw")
    shot(page, "/app/file-integrity-monitoring#/overview/?tab=fim&tabView=events", "wazuh_fim_eventos")
    shot(page, "/app/mitre-attack#/overview/?tab=mitre&tabView=dashboard", "wazuh_mitre")
    for i in range(1, 7):
        f = BASE / "testes" / f"T{i}.json"
        if not f.exists():
            continue
        rules = [r["rule_id"] for r in json.loads(f.read_text(encoding="utf-8")).get("regras", [])][:6]
        if rules:
            q = "rule.id:(" + " or ".join(rules) + ")"
            shot(page, "/app/threat-hunting#/overview/?tab=general&tabView=events", f"teste{i}_alertas_wazuh", q)


def ia_files(page) -> None:
    for fname, slug in (("recomendacoes.md", "ia_recomendacoes"), ("incidentes.md", "ia_incidentes"),
                        ("saude.md", "ia_saude")):
        f = BASE / "ia" / fname
        if f.exists():
            text_page(page, f"ia/{fname}", f.read_text(encoding="utf-8", errors="replace"), name(slug))
    for i in range(1, 7):
        f = BASE / "testes" / f"T{i}.md"
        if f.exists():
            text_page(page, f"testes/T{i}.md (evidencias + analise da IA)", f.read_text(encoding="utf-8"),
                      name(f"teste{i}_analise_ia"))


def main() -> None:
    OUT.mkdir(exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True, locale="pt-BR")
        texto = ctx.new_page()      # pagina so para renderizar textos
        terminals(texto)
        dashboard(ctx.new_page())
        ia_files(texto)
        browser.close()
    (OUT / "prints_log.txt").write_text("\n".join(LOG) + "\n", encoding="utf-8")
    print("\n".join(LOG))


if __name__ == "__main__":
    main()
