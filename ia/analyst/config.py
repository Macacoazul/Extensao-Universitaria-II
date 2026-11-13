"""Configuracao via variaveis de ambiente (definidas no .env / compose)."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "sim")


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


@dataclass
class Config:
    ollama_url: str = field(default_factory=lambda: os.environ.get("OLLAMA_URL", "http://ollama:11434").rstrip("/"))
    llm_model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL", "deepseek-r1:8b"))
    embed_model: str = field(default_factory=lambda: os.environ.get("EMBED_MODEL", "nomic-embed-text"))
    llm_timeout_s: int = field(default_factory=lambda: int(os.environ.get("LLM_TIMEOUT_S", "600")))
    pull_models: bool = field(default_factory=lambda: _bool("AI_PULL_MODELS", True))
    ollama_wait_s: int = field(default_factory=lambda: int(os.environ.get("AI_OLLAMA_WAIT_S", "600")))
    # "hash": se o Ollama nao gerar embeddings, usa um embedding local por hashing de termos
    embed_fallback: str = field(default_factory=lambda: os.environ.get("EMBED_FALLBACK", "hash"))

    alerts_file: str = field(default_factory=lambda: os.environ.get("ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
    suricata_eve: str = field(default_factory=lambda: os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"))
    state_dir: str = field(default_factory=lambda: os.environ.get("STATE_DIR", "/data"))
    out_dir: str = field(default_factory=lambda: os.environ.get("OUT_DIR", "/lab-ia"))
    from_start: bool = field(default_factory=lambda: _bool("AI_FROM_START", False))

    min_level: int = field(default_factory=lambda: int(os.environ.get("AI_MIN_LEVEL", "7")))
    group_threshold: int = field(default_factory=lambda: int(os.environ.get("AI_GROUP_THRESHOLD", "10")))
    group_window_s: int = field(default_factory=lambda: int(os.environ.get("AI_GROUP_WINDOW_S", "300")))
    settle_s: int = field(default_factory=lambda: int(os.environ.get("AI_SETTLE_S", "45")))
    max_bucket_age_s: int = field(default_factory=lambda: int(os.environ.get("AI_MAX_BUCKET_AGE_S", "180")))
    poll_seconds: int = field(default_factory=lambda: int(os.environ.get("AI_POLL_SECONDS", "15")))
    health_interval_s: int = field(default_factory=lambda: int(os.environ.get("AI_HEALTH_INTERVAL_S", "300")))
    recurrence_threshold: int = field(default_factory=lambda: int(os.environ.get("AI_RECURRENCE_THRESHOLD", "1")))
    similarity_min: float = field(default_factory=lambda: float(os.environ.get("AI_SIMILARITY_MIN", "0.80")))
    ignore_rules: list[str] = field(default_factory=lambda: _list("AI_IGNORE_RULES", "100103,100104,100105,651,652"))
    ignore_groups: list[str] = field(default_factory=lambda: _list(
        "AI_IGNORE_GROUPS", "sca,rootcheck,syscollector,vulnerability-detector"))

    auto_block: bool = field(default_factory=lambda: _bool("AUTO_BLOCK", False))
    # true: aplicacao automatica somente em REINCIDENCIA (primeira ocorrencia grave so recomenda)
    auto_block_require_recurrence: bool = field(default_factory=lambda: _bool("AUTO_BLOCK_REQUIRE_RECURRENCE", True))
    auto_block_networks: list[str] = field(default_factory=lambda: _list("AUTO_BLOCK_NETWORKS", "192.168.10.0/24"))
    auto_block_protected: list[str] = field(default_factory=lambda: _list("AUTO_BLOCK_PROTECTED", ""))
    fw_api_url: str = field(default_factory=lambda: os.environ.get("FW_API_URL", "http://172.30.0.2:8088").rstrip("/"))
    fw_api_token: str = field(default_factory=lambda: os.environ.get("FW_API_TOKEN", ""))
    fw_block_timeout: str = field(default_factory=lambda: os.environ.get("FW_BLOCK_TIMEOUT", "1h"))

    wazuh_api_url: str = field(default_factory=lambda: os.environ.get("WAZUH_API_URL", "https://wazuh.manager:55000").rstrip("/"))
    wazuh_api_user: str = field(default_factory=lambda: os.environ.get("API_USERNAME", "wazuh-wui"))
    wazuh_api_password: str = field(default_factory=lambda: os.environ.get("API_PASSWORD", ""))

    health_targets: list[str] = field(default_factory=lambda: _list(
        "HEALTH_TARGETS",
        "firewall=172.30.0.2:8088,wazuh-manager=wazuh.manager:55000,wazuh-indexer=wazuh.indexer:9200,"
        "wazuh-dashboard=wazuh.dashboard:5601,ollama=ollama:11434"))

    def ip_allowed_for_block(self, ip: str | None) -> tuple[bool, str]:
        """Bloqueio so para IPs do lab e nunca para IPs protegidos."""
        if not ip:
            return False, "incidente sem IP de origem"
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, f"IP invalido: {ip}"
        if ip in self.auto_block_protected:
            return False, f"{ip} esta na lista de IPs protegidos"
        if not any(addr in ipaddress.ip_network(n, strict=False) for n in self.auto_block_networks):
            return False, f"{ip} fora das redes do lab ({', '.join(self.auto_block_networks)})"
        return True, "ok"
