"""Memoria de incidentes ("aprender com as falhas").

SQLite (volume do container) guarda cada incidente, a analise da IA, a acao
tomada e um embedding do resumo. Antes de cada nova analise:
* busca incidentes anteriores da MESMA origem e categoria (reincidencia);
* busca incidentes SEMANTICAMENTE parecidos (similaridade de cosseno dos
  embeddings) para dar contexto ao LLM (RAG).
Para o volume de um laboratorio, SQLite + numpy e suficiente; ChromaDB seria
uma troca direta caso o historico cresca muito.
"""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

import numpy as np

from analyst.alerts import parse_ts

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    first_ts TEXT, last_ts TEXT,
    key TEXT, category TEXT, srcip TEXT,
    agents TEXT, rule_ids TEXT,
    max_level INTEGER, alert_count INTEGER,
    summary TEXT,
    analysis TEXT,
    recurrence INTEGER DEFAULT 0,
    prior_count INTEGER DEFAULT 0,
    action TEXT,
    embedding BLOB
);
CREATE INDEX IF NOT EXISTS ix_inc_src ON incidents(srcip, category);
"""


class Memory:
    def __init__(self, state_dir: str):
        self.path = Path(state_dir) / "historico.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._conn()) as c, c:
            c.executescript(SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------ escrita
    def save(self, inc: dict, summary: str, analysis: dict, recurrence: bool, prior_count: int,
             action: str, embedding: list[float] | None) -> None:
        blob = np.asarray(embedding, dtype=np.float32).tobytes() if embedding else None
        with closing(self._conn()) as c, c:
            c.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (inc["id"], time.time(), inc.get("first_ts"), inc.get("last_ts"), inc["key"],
                 inc["category"], inc.get("srcip"), ",".join(inc.get("agents", [])),
                 ",".join(inc.get("rules", {}).keys()), inc.get("max_level"), inc.get("count"),
                 summary, json.dumps(analysis, ensure_ascii=False), int(recurrence), prior_count,
                 action, blob))

    # ------------------------------------------------------------ consultas
    def prior(self, srcip: str | None, category: str, rule_ids: list[str],
              before_ts: str | None = None) -> list[dict]:
        """Incidentes ANTERIORES da mesma origem (mesma categoria ou regra em comum).

        So contam episodios encerrados antes do inicio do incidente atual
        (last_ts anterior a before_ts): alertas do mesmo episodio que caem em
        incidentes diferentes nao sao "reincidencia".
        """
        if not srcip:
            return []
        limit = parse_ts(before_ts) if before_ts else None
        with closing(self._conn()) as c:
            rows = c.execute(
                "SELECT id, created_at, first_ts, last_ts, category, rule_ids, max_level, alert_count, "
                "analysis, action FROM incidents WHERE srcip = ? ORDER BY created_at DESC LIMIT 50",
                (srcip,)).fetchall()
        out = []
        for r in rows:
            last = parse_ts(r["last_ts"])
            if limit and last and last >= limit:
                continue
            if r["category"] == category or set((r["rule_ids"] or "").split(",")) & set(rule_ids):
                out.append(dict(r))
        return out

    def similar(self, embedding: list[float] | None, k: int = 3, min_score: float = 0.8) -> list[dict]:
        if not embedding:
            return []
        q = np.asarray(embedding, dtype=np.float32)
        qn = np.linalg.norm(q) or 1.0
        with closing(self._conn()) as c:
            rows = c.execute("SELECT id, first_ts, srcip, category, summary, analysis, action, embedding "
                             "FROM incidents WHERE embedding IS NOT NULL ORDER BY created_at DESC LIMIT 2000"
                             ).fetchall()
        scored = []
        for r in rows:
            v = np.frombuffer(r["embedding"], dtype=np.float32)
            if v.shape != q.shape:
                continue
            score = float(np.dot(q, v) / (qn * (np.linalg.norm(v) or 1.0)))
            if score >= min_score:
                d = dict(r)
                d.pop("embedding")
                d["score"] = round(score, 3)
                scored.append(d)
        return sorted(scored, key=lambda d: -d["score"])[:k]

    def recent(self, limit: int = 50) -> list[dict]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT id, created_at, first_ts, last_ts, category, srcip, agents, rule_ids, "
                             "max_level, alert_count, summary, analysis, recurrence, prior_count, action "
                             "FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def between(self, start: float, end: float) -> list[dict]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT id, created_at, first_ts, last_ts, category, srcip, agents, rule_ids, "
                             "max_level, alert_count, summary, analysis, recurrence, prior_count, action "
                             "FROM incidents WHERE created_at BETWEEN ? AND ? ORDER BY created_at",
                             (start, end)).fetchall()
        return [dict(r) for r in rows]
