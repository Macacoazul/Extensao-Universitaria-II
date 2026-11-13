"""Leitura incremental do alerts.json do Wazuh (como um `tail -f` com estado).

O arquivo e montado somente-leitura a partir do volume de logs do manager.
O deslocamento lido e salvo em STATE_DIR para nao reanalisar alertas apos
reinicio. Rotacao diaria do Wazuh e detectada pela troca de inode/tamanho.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator

log = logging.getLogger(__name__)


def parse_ts(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _get(d: dict, path: str, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


@dataclass
class Alert:
    raw: dict

    @property
    def ts(self) -> datetime | None:
        return parse_ts(self.raw.get("timestamp"))

    @property
    def rule_id(self) -> str:
        return str(_get(self.raw, "rule.id", ""))

    @property
    def level(self) -> int:
        try:
            return int(_get(self.raw, "rule.level", 0))
        except (TypeError, ValueError):
            return 0

    @property
    def description(self) -> str:
        return str(_get(self.raw, "rule.description", ""))

    @property
    def groups(self) -> list[str]:
        return list(_get(self.raw, "rule.groups", []) or [])

    @property
    def mitre(self) -> dict:
        m = _get(self.raw, "rule.mitre", {}) or {}
        return {"id": m.get("id", []), "tactic": m.get("tactic", []), "technique": m.get("technique", [])}

    @property
    def agent(self) -> str:
        return str(_get(self.raw, "agent.name", ""))

    @property
    def agent_id(self) -> str:
        return str(_get(self.raw, "agent.id", ""))

    @property
    def srcip(self) -> str | None:
        for path in ("data.srcip", "data.src_ip", "data.flow.src_ip"):
            v = _get(self.raw, path)
            if v:
                return str(v)
        return None

    @property
    def dstip(self) -> str | None:
        for path in ("data.dstip", "data.dest_ip"):
            v = _get(self.raw, path)
            if v:
                return str(v)
        return None

    @property
    def dstport(self) -> str | None:
        for path in ("data.dstport", "data.dest_port"):
            v = _get(self.raw, path)
            if v not in (None, ""):
                return str(v)
        return None

    @property
    def category(self) -> str:
        """Categoria estavel para agrupar/detectar reincidencia."""
        g = set(self.groups)
        for name, keys in (
            ("autenticacao_ssh", {"authentication_failures", "authentication_failed", "invalid_login", "sshd"}),
            ("varredura", {"multiple_drops", "attempted-recon"}),
            ("ids_assinatura", {"ids", "suricata"}),
            ("firewall", {"firewall", "firewall_drop", "lab-fw"}),
            ("integridade_arquivos", {"syscheck", "syscheck_file", "syscheck_entry_modified"}),
            ("web", {"web", "accesslog", "nginx"}),
        ):
            if g & keys:
                return name
        return self.groups[0] if self.groups else "outros"

    def summary(self) -> dict:
        return {
            "timestamp": self.raw.get("timestamp"),
            "rule_id": self.rule_id,
            "level": self.level,
            "description": self.description,
            "groups": self.groups,
            "mitre": self.mitre,
            "agent": self.agent,
            "srcip": self.srcip,
            "dstip": self.dstip,
            "dstport": self.dstport,
            "signature": _get(self.raw, "data.alert.signature"),
            "file": _get(self.raw, "syscheck.path"),
            "full_log": (self.raw.get("full_log") or "")[:400],
        }


class AlertTailer:
    def __init__(self, path: str, state_dir: str, from_start: bool = False):
        self.path = Path(path)
        self.state_file = Path(state_dir) / "alerts_offset.json"
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.inode, self.offset = self._load_state(from_start)

    def _load_state(self, from_start: bool) -> tuple[int | None, int]:
        if self.state_file.exists():
            try:
                st = json.loads(self.state_file.read_text())
                return st.get("inode"), int(st.get("offset", 0))
            except (ValueError, OSError):
                pass
        if not from_start and self.path.exists():
            st = self.path.stat()
            log.info("Iniciando no fim de %s (alertas antigos nao serao analisados)", self.path)
            return st.st_ino, st.st_size
        return None, 0

    def _save_state(self) -> None:
        self.state_file.write_text(json.dumps({"inode": self.inode, "offset": self.offset}))

    def read_new(self) -> Iterator[Alert]:
        if not self.path.exists():
            return
        st = self.path.stat()
        if self.inode is not None and (st.st_ino != self.inode or st.st_size < self.offset):
            log.info("alerts.json rotacionado; lendo do inicio")
            self.offset = 0
        self.inode = st.st_ino
        with self.path.open("rb") as fh:
            fh.seek(self.offset)
            for raw_line in fh:
                if not raw_line.endswith(b"\n"):
                    break  # linha ainda sendo escrita
                self.offset += len(raw_line)
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    yield Alert(json.loads(line))
                except json.JSONDecodeError:
                    log.warning("linha invalida em alerts.json ignorada")
        self._save_state()


def iter_alerts_file(path: str) -> Iterator[Alert]:
    """Le um arquivo de alertas inteiro (usado na extracao de evidencias)."""
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield Alert(json.loads(line))
                except json.JSONDecodeError:
                    continue


def file_age_seconds(path: str) -> float | None:
    try:
        return datetime.now().timestamp() - os.stat(path).st_mtime
    except OSError:
        return None
