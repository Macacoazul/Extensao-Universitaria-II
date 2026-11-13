import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def alert(rule_id="5763", level=10, srcip="192.168.10.20", groups=("syslog", "sshd", "authentication_failures"),
          ts="2026-11-13T10:00:01.123-0300", agent="lab-server", desc="sshd: brute force trying to get access",
          mitre=("T1110",), **data):
    d = {"srcip": srcip, **data} if srcip else dict(data)
    return {"timestamp": ts, "rule": {"id": rule_id, "level": level, "description": desc, "groups": list(groups),
                                      "mitre": {"id": list(mitre), "tactic": ["Credential Access"],
                                                "technique": ["Brute Force"]}},
            "agent": {"id": "001", "name": agent}, "data": d,
            "full_log": f"Failed password for labuser from {srcip} port 51234 ssh2"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    state, out = tmp_path / "state", tmp_path / "out"
    state.mkdir(); out.mkdir()
    alerts = tmp_path / "alerts.json"
    alerts.write_text("")
    monkeypatch.setenv("STATE_DIR", str(state))
    monkeypatch.setenv("OUT_DIR", str(out))
    monkeypatch.setenv("ALERTS_FILE", str(alerts))
    monkeypatch.setenv("AUTO_BLOCK_PROTECTED", "192.168.10.1,172.30.0.10")
    return {"state": state, "out": out, "alerts": alerts, "tmp": tmp_path}


def write_alerts(path, alerts):
    with open(path, "a", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(a) + "\n")
