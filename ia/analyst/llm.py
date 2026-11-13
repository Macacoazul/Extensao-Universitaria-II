"""Cliente do Ollama: analise estruturada de incidentes e embeddings."""
from __future__ import annotations

import json
import logging
import re
import time

import requests

log = logging.getLogger(__name__)

CLASSES = ["benigno", "suspeito", "potencialmente_malicioso", "falso_positivo_provavel"]
SEVERIDADES = ["baixa", "media", "alta", "critica"]
TIPOS_REGRA = ["firewall", "wazuh", "suricata", "active-response", "nenhuma"]

SCHEMA = {
    "type": "object",
    "properties": {
        "classificacao": {"type": "string", "enum": CLASSES},
        "gravidade": {"type": "string", "enum": SEVERIDADES},
        "causa_provavel": {"type": "string"},
        "mitre": {"type": "array", "items": {"type": "object", "properties": {
            "tecnica_id": {"type": "string"}, "tecnica": {"type": "string"}, "tatica": {"type": "string"}},
            "required": ["tecnica_id", "tecnica", "tatica"]}},
        "acao_recomendada": {"type": "string"},
        "sugestao_regra": {"type": "object", "properties": {
            "tipo": {"type": "string", "enum": TIPOS_REGRA},
            "conteudo": {"type": "string"}, "justificativa": {"type": "string"}},
            "required": ["tipo", "conteudo", "justificativa"]},
        "reincidencia": {"type": "boolean"},
        "confianca": {"type": "string", "enum": ["baixa", "media", "alta"]},
        "resumo": {"type": "string"},
    },
    "required": ["classificacao", "gravidade", "causa_provavel", "mitre", "acao_recomendada",
                 "sugestao_regra", "reincidencia", "confianca", "resumo"],
}

import os

_LAB = (f"rede {os.environ.get('LAN_SUBNET', '192.168.10.0/24')}: firewall {os.environ.get('FW_LAN_IP', '192.168.10.1')}, "
        f"servidor {os.environ.get('SERVER_IP', '192.168.10.10')}, cliente {os.environ.get('CLIENTE_IP', '192.168.10.20')}; "
        f"gerencia {os.environ.get('MGMT_SUBNET', '172.30.0.0/24')} com Wazuh e IA")

SYSTEM = (
    "Voce e um analista de SOC nivel 2 trabalhando em um LABORATORIO academico isolado "
    f"({_LAB}). "
    "Analise o incidente (grupo de alertas do Wazuh/Suricata/firewall) e responda SOMENTE com JSON "
    "no esquema pedido, em portugues do Brasil. Regras: (1) baseie-se apenas nas evidencias "
    "fornecidas; nao invente fatos; (2) uma anomalia ou alerta nao prova um ataque: use "
    "'suspeito' ou 'potencialmente_malicioso' conforme a evidencia; (3) use o mapeamento MITRE "
    "ATT&CK das regras quando existir e so acrescente tecnicas com justificativa; (4) se houver "
    "incidentes anteriores da mesma origem, marque reincidencia=true e considere isso na gravidade; "
    "(5) a sugestao de regra deve ser objetiva e aplicavel ao laboratorio (nftables, regra Wazuh "
    "XML, regra Suricata ou active-response)."
)


def strip_think(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text or "", flags=re.S).strip()


def extract_json(text: str) -> dict | None:
    text = strip_think(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", text, flags=re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def normalize(result: dict | None, fallback: dict) -> dict:
    if not isinstance(result, dict):
        return {**fallback, "origem_analise": "contingencia/playbook (LLM sem JSON valido)"}
    out = {**fallback, **{k: v for k, v in result.items() if k in SCHEMA["properties"]}}
    if out.get("classificacao") not in CLASSES:
        out["classificacao"] = fallback["classificacao"]
    if out.get("gravidade") not in SEVERIDADES:
        out["gravidade"] = fallback["gravidade"]
    sr = out.get("sugestao_regra")
    if not isinstance(sr, dict) or sr.get("tipo") not in TIPOS_REGRA:
        out["sugestao_regra"] = fallback["sugestao_regra"]
    if not isinstance(out.get("mitre"), list):
        out["mitre"] = fallback["mitre"]
    out["origem_analise"] = "llm"
    return out


def hash_embedding(text: str, dim: int = 256) -> list[float]:
    """Embedding local (feature hashing de palavras e bigramas), sem modelo.

    Usado somente quando o Ollama nao responde. Captura sobreposicao lexical
    (mesmas regras/descricoes), suficiente para achar incidentes parecidos no lab.
    """
    import hashlib
    import math
    words = re.findall(r"[a-z0-9_.]+", (text or "").lower())
    feats = words + [f"{a} {b}" for a, b in zip(words, words[1:])]
    vec = [0.0] * dim
    for f in feats:
        h = int(hashlib.md5(f.encode()).hexdigest(), 16)
        vec[h % dim] += 1.0 if (h >> 8) % 2 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


class OllamaClient:
    def __init__(self, url: str, model: str, embed_model: str, timeout_s: int = 600, embed_fallback: str = "hash"):
        self.url, self.model, self.embed_model, self.timeout = url, model, embed_model, timeout_s
        self.embed_fallback = embed_fallback

    def wait_ready(self, max_wait_s: int = 600) -> bool:
        if max_wait_s <= 0:
            return False
        t0 = time.time()
        while time.time() - t0 < max_wait_s:
            try:
                requests.get(f"{self.url}/api/tags", timeout=5).raise_for_status()
                return True
            except requests.RequestException:
                time.sleep(5)
        return False

    def models(self) -> list[str]:
        r = requests.get(f"{self.url}/api/tags", timeout=10)
        r.raise_for_status()
        return [m.get("name", "") for m in r.json().get("models", [])]

    def ensure(self, name: str) -> None:
        have = self.models()
        if any(m == name or m == f"{name}:latest" or m.split(":")[0] == name for m in have):
            return
        log.info("Baixando modelo %s no Ollama (pode demorar varios minutos)...", name)
        r = requests.post(f"{self.url}/api/pull", json={"model": name, "stream": False}, timeout=None)
        r.raise_for_status()
        log.info("Modelo %s pronto", name)

    def embed(self, text: str) -> list[float] | None:
        try:
            r = requests.post(f"{self.url}/api/embed", json={"model": self.embed_model, "input": text}, timeout=120)
            if r.status_code == 404:
                r = requests.post(f"{self.url}/api/embeddings",
                                  json={"model": self.embed_model, "prompt": text}, timeout=120)
                r.raise_for_status()
                return r.json().get("embedding")
            r.raise_for_status()
            emb = r.json().get("embeddings") or []
            return emb[0] if emb else None
        except requests.RequestException as exc:
            if self.embed_fallback == "hash":
                log.info("Ollama sem embeddings (%s); usando embedding local por hashing", exc.__class__.__name__)
                return hash_embedding(text)
            log.warning("Falha ao gerar embedding: %s", exc)
            return None

    def analyze(self, prompt: str, fallback: dict) -> tuple[dict, float, str]:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
            "stream": False,
            "format": SCHEMA,
            "options": {"temperature": 0.2, "num_ctx": 8192},
        }
        t0 = time.time()
        try:
            r = requests.post(f"{self.url}/api/chat", json=body, timeout=self.timeout)
            r.raise_for_status()
            content = r.json().get("message", {}).get("content", "")
        except requests.RequestException as exc:
            log.error("Falha na chamada ao LLM: %s", exc)
            return {**fallback, "origem_analise": f"contingencia/playbook (LLM indisponivel: {exc.__class__.__name__})"}, \
                time.time() - t0, ""
        return normalize(extract_json(content), fallback), time.time() - t0, content
