import json

from analyst.alerts import Alert, AlertTailer
from analyst.config import Config
from analyst.llm import extract_json, normalize
from analyst.analyzer import fallback_analysis
from analyst.memory import Memory
from analyst.prevention import plan
from analyst.triage import Triage

from conftest import alert, write_alerts


def test_alert_fields_and_categories():
    a = Alert(alert())
    assert a.srcip == "192.168.10.20" and a.level == 10 and a.category == "autenticacao_ssh"
    s = Alert(alert(rule_id="100210", groups=("ids", "suricata", "lab-ids"), srcip=None,
                    src_ip="192.168.10.20", dest_ip="192.168.10.10", dest_port=22))
    assert s.srcip == "192.168.10.20" and s.dstip == "192.168.10.10" and s.category == "ids_assinatura"
    f = Alert(alert(rule_id="550", level=7, srcip=None, groups=("ossec", "syscheck", "syscheck_entry_modified")))
    assert f.category == "integridade_arquivos" and f.srcip is None


def test_tailer_reads_only_new_and_survives_restart(env):
    write_alerts(env["alerts"], [alert()])
    t = AlertTailer(str(env["alerts"]), str(env["state"]))       # comeca no fim
    assert list(t.read_new()) == []
    write_alerts(env["alerts"], [alert(), alert()])
    assert len(list(t.read_new())) == 2
    write_alerts(env["alerts"], [alert()])
    t2 = AlertTailer(str(env["alerts"]), str(env["state"]))      # retoma do offset salvo
    assert len(list(t2.read_new())) == 1


def test_triage_groups_burst_into_one_incident(env):
    cfg = Config()
    tr = Triage(cfg)
    for i in range(30):
        tr.feed(Alert(alert()), now=1000 + i)
    assert tr.ready(now=1030) == []                       # ainda chegando alertas
    incs = tr.ready(now=1030 + cfg.settle_s + 1)
    assert len(incs) == 1 and incs[0].count == 30 and incs[0].srcip == "192.168.10.20"


def test_triage_low_level_grouping_and_ignore(env):
    cfg = Config()
    tr = Triage(cfg)
    for i in range(cfg.group_threshold):
        tr.feed(Alert(alert(rule_id="100101", level=5, groups=("lab-fw", "firewall", "firewall_drop"))), now=2000 + i)
    tr.feed(Alert(alert(rule_id="19007", level=7, groups=("sca",))), now=2001)
    incs = tr.ready(flush=True)
    assert len(incs) == 1 and incs[0].category == "firewall" and incs[0].key.startswith("agrupado|")


def test_llm_json_extraction_and_fallback():
    inc = {"id": "INC-1", "count": 3, "category": "x", "max_level": 10,
           "rules": {"5763": {"level": 10, "count": 3, "description": "d",
                              "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]}}}}
    fb = fallback_analysis(inc)
    assert fb["gravidade"] == "alta" and fb["mitre"][0]["tecnica_id"] == "T1110"
    raw = '<think>raciocinio</think>{"classificacao":"potencialmente_malicioso","gravidade":"inexistente"}'
    out = normalize(extract_json(raw), fb)
    assert out["classificacao"] == "potencialmente_malicioso" and out["gravidade"] == "alta"
    assert normalize(None, fb)["origem_analise"].startswith("contingencia")


def test_memory_prior_and_similarity(env):
    m = Memory(str(env["state"]))
    inc = {"id": "INC-a", "key": "k", "category": "autenticacao_ssh", "srcip": "192.168.10.20",
           "agents": ["lab-server"], "rules": {"5763": {}}, "max_level": 10, "count": 5}
    m.save(inc, "texto", {"classificacao": "suspeito"}, False, 0, "monitorar", [1.0, 0.0, 0.0])
    assert len(m.prior("192.168.10.20", "autenticacao_ssh", ["5763"])) == 1
    assert m.prior("192.168.10.99", "autenticacao_ssh", ["5763"]) == []
    assert m.similar([0.9, 0.1, 0.0], min_score=0.8)[0]["id"] == "INC-a"
    assert m.similar([0.0, 1.0, 0.0], min_score=0.8) == []


def test_prevention_guards(env):
    cfg = Config()
    grave = {"gravidade": "alta", "classificacao": "potencialmente_malicioso"}
    inc = {"id": "I", "srcip": "192.168.10.20", "agents": ["lab-server", "wazuh.manager"]}
    p = plan(cfg, inc, grave, recurrence=False)
    assert p["bloquear"] and [a["tipo"] for a in p["acoes"]] == ["firewall-blocklist", "wazuh-active-response"]
    assert not plan(cfg, {**inc, "srcip": "8.8.8.8"}, grave, True)["bloquear"]          # fora do lab
    assert not plan(cfg, {**inc, "srcip": "192.168.10.1"}, grave, True)["bloquear"]     # protegido
    leve = {"gravidade": "media", "classificacao": "suspeito"}
    assert not plan(cfg, inc, leve, recurrence=False)["bloquear"]
    assert plan(cfg, inc, leve, recurrence=True)["bloquear"]                            # reincidencia
    assert not plan(cfg, inc, {"gravidade": "alta", "classificacao": "falso_positivo_provavel"}, True)["bloquear"]


def test_auto_block_only_on_recurrence(env, monkeypatch):
    monkeypatch.setenv("AUTO_BLOCK", "true")
    cfg = Config()
    grave = {"gravidade": "alta", "classificacao": "potencialmente_malicioso"}
    inc = {"id": "I", "srcip": "192.168.10.20", "agents": ["lab-server"]}
    assert plan(cfg, inc, grave, recurrence=False)["aplicar_auto"] is False
    assert plan(cfg, inc, grave, recurrence=True)["aplicar_auto"] is True
    monkeypatch.setenv("AUTO_BLOCK_REQUIRE_RECURRENCE", "false")
    assert plan(Config(), inc, grave, recurrence=False)["aplicar_auto"] is True


def test_hash_embedding_similarity():
    from analyst.llm import hash_embedding
    import numpy as np
    a = hash_embedding("categoria autenticacao_ssh regras: sshd brute force (nivel 10, 3x)")
    b = hash_embedding("categoria autenticacao_ssh regras: sshd brute force (nivel 10, 9x)")
    c = hash_embedding("categoria integridade_arquivos regras: integrity checksum changed")
    assert np.dot(a, b) > 0.8 > np.dot(a, c)


def test_prior_ignores_same_episode(env):
    m = Memory(str(env["state"]))
    base = {"key": "k", "category": "firewall", "srcip": "192.168.10.20", "agents": [], "rules": {"100102": {}},
            "max_level": 10, "count": 1}
    m.save({**base, "id": "A", "first_ts": "2026-11-13T10:00:00.000-0300", "last_ts": "2026-11-13T10:00:30.000-0300"},
           "t", {}, False, 0, "", None)
    # incidente do mesmo episodio (comecou antes do fim de A): nao e reincidencia
    assert m.prior("192.168.10.20", "firewall", ["100101"], "2026-11-13T10:00:10.000-0300") == []
    # episodio posterior: reincidencia
    assert len(m.prior("192.168.10.20", "firewall", ["100101"], "2026-11-13T10:05:00.000-0300")) == 1
