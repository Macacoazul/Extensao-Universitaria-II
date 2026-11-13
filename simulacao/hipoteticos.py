"""Eventos HIPOTETICOS para os testes 1, 2 e 6 do ambiente experimental.

Nenhuma varredura ou tentativa real de login e executada. Este script apenas
ESCREVE registros de log iguais aos que os sensores gerariam se o comportamento
ocorresse, para demonstrar a cadeia deteccao -> SIEM -> IA -> prevencao:

  varredura   -> alertas no formato EVE do Suricata (regra local sid 9100002),
                 gravados em /var/log/lab-sim/eve-hipotetico.json
  forca-bruta -> linhas do sshd ("Failed password ...", "Invalid user ...")
                 enviadas ao syslog local com `logger` (vao para /var/log/auth.log)

Os registros de Suricata levam o campo "lab_hipotetico": true.
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=-3))
EVE = Path("/var/log/lab-sim/eve-hipotetico.json")


def ts() -> str:
    d = datetime.now(TZ)
    return d.strftime("%Y-%m-%dT%H:%M:%S.%f") + d.strftime("%z")


def varredura(origem: str, alvo: str, alertas: int) -> None:
    EVE.parent.mkdir(parents=True, exist_ok=True)
    with EVE.open("a", encoding="utf-8") as fh:
        for i in range(alertas):
            ev = {"timestamp": ts(), "flow_id": random.randint(10**14, 10**15), "in_iface": "br-lab-lan",
                  "event_type": "alert", "src_ip": origem, "src_port": random.randint(40000, 60000),
                  "dest_ip": alvo, "dest_port": random.choice([21, 23, 25, 110, 139, 445, 3306, 5432, 8080]),
                  "proto": "TCP", "direction": "to_server",
                  "alert": {"action": "allowed", "gid": 1, "signature_id": 9100002, "rev": 1,
                            "signature": "LAB Possivel varredura de portas na LAN",
                            "category": "Attempted Information Leak", "severity": 2},
                  "lab_hipotetico": True}
            fh.write(json.dumps(ev) + "\n")
            fh.flush()
            time.sleep(0.5)
    print(f"{alertas} alerta(s) hipotetico(s) de varredura {origem} -> {alvo} gravados em {EVE}")


def forca_bruta(origem: str, usuario: str, tentativas: int, invalidos: int) -> None:
    pid = random.randint(2000, 30000)
    for i in range(invalidos):
        porta = random.randint(40000, 60000)
        subprocess.run(["logger", "-p", "authpriv.info", "-t", f"sshd[{pid + i}]",
                        f"Invalid user admin from {origem} port {porta}"], check=True)
        subprocess.run(["logger", "-p", "authpriv.info", "-t", f"sshd[{pid + i}]",
                        f"Failed password for invalid user admin from {origem} port {porta} ssh2"], check=True)
        time.sleep(0.3)
    for i in range(tentativas):
        porta = random.randint(40000, 60000)
        subprocess.run(["logger", "-p", "authpriv.info", "-t", f"sshd[{pid + 100 + i}]",
                        f"Failed password for {usuario} from {origem} port {porta} ssh2"], check=True)
        time.sleep(0.3)
    print(f"{tentativas + invalidos} tentativa(s) hipotetica(s) de login SSH de {origem} registradas no auth.log")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("cenario", choices=["varredura", "forca-bruta"])
    p.add_argument("--origem", default="192.168.10.20")
    p.add_argument("--alvo", default="192.168.10.10")
    p.add_argument("--alertas", type=int, default=5)
    p.add_argument("--usuario", default="labuser")
    p.add_argument("--tentativas", type=int, default=12)
    p.add_argument("--invalidos", type=int, default=3)
    a = p.parse_args()
    if a.cenario == "varredura":
        varredura(a.origem, a.alvo, a.alertas)
    else:
        forca_bruta(a.origem, a.usuario, a.tentativas, a.invalidos)


if __name__ == "__main__":
    main()
