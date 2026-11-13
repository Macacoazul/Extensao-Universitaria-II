"""Fluxo completo com um Ollama falso: 2 rajadas da mesma origem -> reincidencia."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from conftest import alert, write_alerts


class FakeOllama(BaseHTTPRequestHandler):
    calls = []

    def _json(self, obj):
        raw = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._json({"models": [{"name": "deepseek-r1:8b"}, {"name": "nomic-embed-text:latest"}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakeOllama.calls.append((self.path, body))
        if self.path == "/api/embed":
            return self._json({"embeddings": [[0.1, 0.9, 0.2]]})
        reinc = "MESMA origem" in body["messages"][1]["content"]
        content = {"classificacao": "potencialmente_malicioso", "gravidade": "media",
                   "causa_provavel": "tentativas repetidas de login SSH", "mitre": [
                       {"tecnica_id": "T1110", "tecnica": "Brute Force", "tatica": "Credential Access"}],
                   "acao_recomendada": "bloquear a origem", "sugestao_regra": {
                       "tipo": "firewall", "conteudo": "nft add element inet filter blocklist { 192.168.10.20 }",
                       "justificativa": "origem do lab"}, "reincidencia": reinc, "confianca": "alta",
                   "resumo": "forca bruta SSH"}
        self._json({"message": {"content": "<think>...</think>" + json.dumps(content)}})

    def log_message(self, *a):
        pass


@pytest.fixture
def ollama(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("OLLAMA_URL", f"http://127.0.0.1:{srv.server_address[1]}")
    yield
    srv.shutdown()


def test_recurrence_detected_and_block_recommended(env, ollama):
    from analyst.alerts import AlertTailer
    from analyst.config import Config
    from analyst.llm import OllamaClient
    from analyst.main import process
    from analyst.memory import Memory
    from analyst.triage import Triage
    from analyst.wazuh_api import WazuhAPI

    cfg = Config()
    llm = OllamaClient(cfg.ollama_url, cfg.llm_model, cfg.embed_model)
    mem = Memory(cfg.state_dir)
    api = WazuhAPI("https://127.0.0.1:1", "u", "p")
    tailer = AlertTailer(cfg.alerts_file, cfg.state_dir, from_start=True)

    for burst, t0 in ((1, 1000), (2, 5000)):
        write_alerts(env["alerts"], [alert(ts=f"2026-11-13T10:0{burst}:0{i}.000-0300") for i in range(8)])
        tr = Triage(cfg)
        for a in tailer.read_new():
            tr.feed(a, now=t0)
        for inc in tr.ready(flush=True):
            process(cfg, llm, mem, api, inc)

    rows = mem.recent()
    assert len(rows) == 2 and rows[0]["recurrence"] == 1 and rows[1]["recurrence"] == 0
    rec = (env["out"] / "recomendacoes.md").read_text(encoding="utf-8")
    assert "Reincidencia:** SIM" in rec and "fw-block 192.168.10.20" in rec
    assert "Decisao de bloqueio:** RECOMENDADO" in rec       # 2a rajada: reincidencia
    assert (env["out"] / "incidentes.md").exists()
    assert len(list((env["out"] / "analises").glob("*.json"))) == 2
    prompts = [b["messages"][1]["content"] for p, b in FakeOllama.calls if p == "/api/chat"]
    assert "nenhum incidente anterior" in prompts[0] and "MESMA origem" in prompts[1]


def test_evidencias_cli(env, ollama, monkeypatch, capsys):
    from analyst import evidencias
    write_alerts(env["alerts"], [alert(ts="2026-11-13T10:00:05.000-0300"),
                                 alert(rule_id="5710", level=5, ts="2026-11-13T10:00:06.000-0300"),
                                 alert(ts="2026-11-13T11:00:00.000-0300")])
    monkeypatch.setattr("sys.argv", ["x", "--id", "T2", "--nome", "SSH", "--inicio", "2026-11-13T10:00:00-03:00",
                                     "--fim", "2026-11-13T10:01:00-03:00", "--grace", "60",
                                     "--saida", str(env["tmp"] / "testes")])
    evidencias.main()
    md = (env["tmp"] / "testes" / "T2.md").read_text(encoding="utf-8")
    assert "| 5763 | 10 |" in md and "| 5710 | 5 |" in md and "11:00:00" not in md
