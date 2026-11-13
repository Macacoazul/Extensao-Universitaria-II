"""Laco principal do ai-analyst."""
from __future__ import annotations

import logging
import signal
import time

from analyst import health, prevention, reports
from analyst.alerts import AlertTailer
from analyst.analyzer import analyze
from analyst.config import Config
from analyst.llm import OllamaClient
from analyst.memory import Memory
from analyst.triage import Triage
from analyst.wazuh_api import WazuhAPI

log = logging.getLogger("ai-analyst")
RUNNING = True


def _stop(*_):
    global RUNNING
    RUNNING = False


def process(cfg: Config, llm: OllamaClient, memory: Memory, api: WazuhAPI, incident) -> None:
    inc = incident.as_dict()
    log.info("Analisando %s (%s, origem %s, %d alertas)", inc["id"], inc["category"], inc["srcip"], inc["count"])
    result = analyze(cfg, llm, memory, inc)
    plan = prevention.plan(cfg, inc, result["analysis"], result["recurrence"])
    applied = prevention.execute(cfg, api, plan, inc)
    action = "; ".join(applied) if applied else ("recomendado bloqueio" if plan["bloquear"] else "monitorar")
    memory.save(inc, result["summary"], result["analysis"], result["recurrence"], len(result["prior"]),
                action, result["embedding"])
    reports.append_recommendation(cfg.out_dir, inc, result, plan, applied)
    reports.save_analysis_json(cfg.out_dir, inc, result, plan, applied)
    reports.write_incidents(cfg.out_dir, memory.recent())
    a = result["analysis"]
    log.info("%s -> %s/%s reincidencia=%s acao=%s (%.1fs)", inc["id"], a.get("classificacao"),
             a.get("gravidade"), result["recurrence"], action, result["seconds"])


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    signal.signal(signal.SIGTERM, _stop)
    cfg = Config()
    llm = OllamaClient(cfg.ollama_url, cfg.llm_model, cfg.embed_model, cfg.llm_timeout_s, cfg.embed_fallback)
    memory = Memory(cfg.state_dir)
    api = WazuhAPI(cfg.wazuh_api_url, cfg.wazuh_api_user, cfg.wazuh_api_password)
    log.info("ai-analyst iniciando: modelo=%s embeddings=%s AUTO_BLOCK=%s nivel_min=%d",
             cfg.llm_model, cfg.embed_model, cfg.auto_block, cfg.min_level)

    if llm.wait_ready(cfg.ollama_wait_s):
        if cfg.pull_models:
            for m in (cfg.llm_model, cfg.embed_model):
                try:
                    llm.ensure(m)
                except Exception as exc:  # noqa: BLE001
                    log.error("Nao foi possivel baixar %s: %s", m, exc)
    else:
        log.error("Ollama indisponivel em %s; seguirei com analise de fallback", cfg.ollama_url)

    tailer = AlertTailer(cfg.alerts_file, cfg.state_dir, cfg.from_start)
    triage = Triage(cfg)
    last_health, prev_health = 0.0, None
    while RUNNING:
        for alert in tailer.read_new():
            triage.feed(alert)
        for incident in triage.ready():
            try:
                process(cfg, llm, memory, api, incident)
            except Exception:  # noqa: BLE001 - um incidente com erro nao derruba o servico
                log.exception("Erro ao processar incidente")
        if time.time() - last_health >= cfg.health_interval_s:
            try:
                prev_health = health.check(cfg, api, prev_health)
                log.info("Saude: %s", health.write(cfg, prev_health))
            except Exception:  # noqa: BLE001
                log.exception("Erro no relatorio de saude")
            last_health = time.time()
        time.sleep(cfg.poll_seconds)


if __name__ == "__main__":
    main()
