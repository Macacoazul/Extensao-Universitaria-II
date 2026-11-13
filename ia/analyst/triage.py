"""Triagem: decide QUAIS alertas viram incidentes para a IA analisar.

Regras (configuraveis):
* nivel >= AI_MIN_LEVEL  -> incidente (agrupado por categoria + origem);
* nivel menor           -> conta por origem; a partir de AI_GROUP_THRESHOLD
                            alertas na janela AI_GROUP_WINDOW_S vira incidente
                            "agrupado por origem";
* agrupamento: alertas da mesma chave entram no mesmo "balde"; o balde e
  enviado para analise quando fica AI_SETTLE_S sem alertas novos ou atinge
  AI_MAX_BUCKET_AGE_S. Isso evita chamar o LLM centenas de vezes durante uma
  rajada (ex.: forca bruta gera dezenas de alertas por minuto).
"""
from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from analyst.alerts import Alert
from analyst.config import Config


@dataclass
class Incident:
    key: str
    category: str
    srcip: str | None
    reason: str
    first_seen: float
    last_seen: float
    first_ts: str | None = None
    last_ts: str | None = None
    alerts: list[dict] = field(default_factory=list)
    rules: dict = field(default_factory=dict)
    agents: set = field(default_factory=set)
    dstips: set = field(default_factory=set)
    count: int = 0
    max_level: int = 0

    @property
    def id(self) -> str:
        h = hashlib.sha1(f"{self.key}|{self.first_ts}|{self.first_seen}".encode()).hexdigest()[:10]
        return f"INC-{h}"

    def add(self, alert: Alert, now: float) -> None:
        s = alert.summary()
        self.count += 1
        self.last_seen = now
        self.last_ts = s["timestamp"] or self.last_ts
        self.first_ts = self.first_ts or s["timestamp"]
        self.max_level = max(self.max_level, alert.level)
        r = self.rules.setdefault(alert.rule_id, {
            "description": alert.description, "level": alert.level, "count": 0,
            "groups": alert.groups, "mitre": alert.mitre})
        r["count"] += 1
        if alert.agent:
            self.agents.add(alert.agent)
        if alert.dstip:
            self.dstips.add(alert.dstip)
        if len(self.alerts) < 6:
            self.alerts.append(s)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "key": self.key, "category": self.category, "srcip": self.srcip,
            "reason": self.reason, "first_ts": self.first_ts, "last_ts": self.last_ts,
            "count": self.count, "max_level": self.max_level, "rules": self.rules,
            "agents": sorted(self.agents), "dstips": sorted(self.dstips), "samples": self.alerts,
        }


class Triage:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.buckets: dict[str, Incident] = {}
        self.low: dict[str, deque] = defaultdict(deque)   # "categoria|srcip" -> [(t, alert)]

    def _ignored(self, a: Alert) -> bool:
        return a.rule_id in self.cfg.ignore_rules or bool(set(a.groups) & set(self.cfg.ignore_groups))

    def _bucket(self, key: str, category: str, srcip: str | None, reason: str, now: float) -> Incident:
        inc = self.buckets.get(key)
        if inc is None:
            inc = Incident(key=key, category=category, srcip=srcip, reason=reason,
                           first_seen=now, last_seen=now)
            self.buckets[key] = inc
        return inc

    def feed(self, alert: Alert, now: float | None = None) -> None:
        now = time.time() if now is None else now
        if self._ignored(alert):
            return
        origin = alert.srcip or f"agente:{alert.agent or alert.agent_id}"
        if alert.level >= self.cfg.min_level:
            key = f"{alert.category}|{origin}"
            self._bucket(key, alert.category, alert.srcip, f"nivel >= {self.cfg.min_level}", now).add(alert, now)
            return
        if not alert.srcip:
            return
        q = self.low[f"{alert.category}|{alert.srcip}"]
        q.append((now, alert))
        while q and now - q[0][0] > self.cfg.group_window_s:
            q.popleft()
        key = f"agrupado|{alert.category}|{alert.srcip}"
        if key in self.buckets:
            self.buckets[key].add(alert, now)
        elif len(q) >= self.cfg.group_threshold:
            inc = self._bucket(key, alert.category, alert.srcip,
                               f"{len(q)} alertas de nivel < {self.cfg.min_level} da mesma origem "
                               f"em {self.cfg.group_window_s}s", now)
            for _, a in q:
                inc.add(a, now)
            q.clear()

    def ready(self, now: float | None = None, flush: bool = False) -> list[Incident]:
        now = time.time() if now is None else now
        out = []
        for key, inc in list(self.buckets.items()):
            if flush or now - inc.last_seen >= self.cfg.settle_s or now - inc.first_seen >= self.cfg.max_bucket_age_s:
                out.append(self.buckets.pop(key))
        return out
