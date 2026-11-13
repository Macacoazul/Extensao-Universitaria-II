"""Emulador do SIEM para o AMBIENTE EXPERIMENTAL.

O Wazuh (manager/indexer/dashboard) nao pode ser executado no ambiente
experimental. Este emulador faz o papel do manager: coleta os mesmos logs que o
Wazuh coletaria e grava alertas NO FORMATO do alerts.json do Wazuh, usando:
  * as regras LOCAIS do projeto (wazuh/config/custom/local_rules.xml), com a
    mesma logica (IDs 100101-100105, 100200-100211);
  * as regras PADRAO do Wazuh necessarias aos testes, com ID, nivel, frequencia,
    MITRE e grupos copiados do ruleset oficial v4.14 (0095-sshd_rules.xml,
    0015-ossec_rules.xml, 0475-suricata_rules.xml).
Assim o ai-analyst recebe exatamente o tipo de entrada que receberia do Wazuh.

Fontes coletadas:
  - syslog UDP 172.30.0.10:514  <- firewall (nftables -> ulogd2 -> rsyslog)
  - /var/log/suricata/eve.json  <- Suricata real escutando a bridge da LAN
  - /var/log/lab-sim/eve-hipotetico.json <- eventos HIPOTETICOS (testes 1/2/6)
  - /var/log/auth.log           <- sshd do servidor simulado (+ linhas hipoteticas via logger)
  - FIM: varredura periodica de /etc e /var/www (servidor simulado)
Tambem expoe uma API minima compativel com a do Wazuh (55000/https) para o
ai-analyst consultar agentes e executar o active response firewall-drop, que e
aplicado de verdade (iptables) no namespace do servidor simulado.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import secrets
import socketserver
import ssl
import subprocess
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

TZ = timezone(timedelta(hours=-3))
ALERTS = Path(os.environ.get("ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
AR_LOG = Path("/var/ossec/logs/active-responses.log")
EVE_FILES = [Path("/var/log/suricata/eve.json"), Path("/var/log/lab-sim/eve-hipotetico.json")]
AUTH_LOG = Path("/var/log/auth.log")
FIM_DIRS = [Path("/etc"), Path("/var/www")]
FIM_IGNORE = re.compile(r"^/etc/(mtab|resolv\.conf|hosts|hostname|ld\.so\.cache|ssh/ssh_host_.*|lab-fw/.*)$|\.swp$")
MANAGER = {"id": "000", "name": "siem-emulador"}
SERVER = {"id": "001", "name": "lab-server", "ip": "192.168.10.10"}
CLIENTE = {"id": "002", "name": "lab-cliente", "ip": "192.168.10.20"}

MITRE = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Password Guessing", "Credential Access"),
    "T1021.004": ("SSH", "Lateral Movement"),
    "T1078": ("Valid Accounts", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"),
    "T1021": ("Remote Services", "Lateral Movement"),
    "T1565.001": ("Stored Data Manipulation", "Impact"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1485": ("Data Destruction", "Impact"),
}

_lock = threading.Lock()
_seq = [0]


def now_ts() -> str:
    d = datetime.now(TZ)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}" + d.strftime("%z")


def mitre(ids: list[str]) -> dict | None:
    if not ids:
        return None
    return {"id": ids, "technique": [MITRE.get(i, ("", ""))[0] for i in ids],
            "tactic": sorted({t.strip() for i in ids for t in MITRE.get(i, ("", ""))[1].split(",") if t.strip()})}


def emit(rule_id: str, level: int, desc: str, groups: list[str], agent: dict, data: dict | None = None,
         full_log: str = "", location: str = "", mitre_ids: list[str] | None = None, decoder: str = "",
         extra: dict | None = None, firedtimes: int = 1) -> None:
    with _lock:
        _seq[0] += 1
        alert = {"timestamp": now_ts(),
                 "rule": {"level": level, "description": desc, "id": rule_id, "firedtimes": firedtimes,
                          "groups": groups},
                 "agent": agent, "manager": {"name": MANAGER["name"]},
                 "id": f"{time.time():.0f}.{_seq[0]}",
                 "decoder": {"name": decoder} if decoder else {},
                 "location": location}
        m = mitre(mitre_ids or [])
        if m:
            alert["rule"]["mitre"] = m
        if data:
            alert["data"] = data
        if full_log:
            alert["full_log"] = full_log
        if extra:
            alert.update(extra)
        ALERTS.parent.mkdir(parents=True, exist_ok=True)
        with ALERTS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert, ensure_ascii=False) + "\n")
    print(f"[alerta] {rule_id} n{level} {desc}", flush=True)


class Frequency:
    """Regra de frequencia do Wazuh: dispara ao atingir N eventos na janela (mesma origem)."""

    def __init__(self, frequency: int, timeframe: int, ignore: int = 0):
        self.f, self.t, self.ignore = frequency, timeframe, ignore
        self.hist: dict[str, deque] = defaultdict(deque)
        self.muted_until: dict[str, float] = {}
        self.fired: dict[str, int] = defaultdict(int)

    def hit(self, key: str) -> int:
        now = time.time()
        q = self.hist[key]
        q.append(now)
        while q and now - q[0] > self.t:
            q.popleft()
        if len(q) >= self.f and now >= self.muted_until.get(key, 0):
            q.clear()
            self.muted_until[key] = now + self.ignore
            self.fired[key] += 1
            return self.fired[key]
        return 0


# ------------------------------------------------------------------ firewall (syslog)
FW_FREQ = Frequency(20, 60)            # 100102: frequency=20 timeframe=60 same_source_ip
SYSLOG_RE = re.compile(r"^<\d+>(?:\w{3}\s+\d+\s[\d:]+\s)?(\S+)\s([\w.\-]+?)(?:\[\d+\])?:\s?(.*)$")
FW_PACKET = re.compile(r"(FW-[A-Z-]+)\s.*?SRC=(\S+)\s+DST=(\S+).*?PROTO=(\w+)")
FW_PORTS = re.compile(r"SPT=(\d+)\s+DPT=(\d+)")
FW_API = re.compile(r"(FW-API \w+)\s+SRC=(\S+)")


def handle_syslog(raw: str, sender: str) -> None:
    m = SYSLOG_RE.match(raw.strip())
    if not m or not m.group(2).startswith("lab-fw"):
        return
    msg = m.group(3)
    loc = sender
    if (api := FW_API.search(msg)) and "FW-API " in msg:
        action, src = api.groups()
        if action == "FW-API BLOCK":
            emit("100104", 8, f"Firewall do lab: IP {src} bloqueado (resposta a incidente)",
                 ["lab-fw", "firewall", "active_response"], MANAGER, {"action": action, "srcip": src},
                 raw, loc, decoder="lab-fw")
        elif action == "FW-API UNBLOCK":
            emit("100105", 3, f"Firewall do lab: IP {src} desbloqueado", ["lab-fw", "firewall"], MANAGER,
                 {"action": action, "srcip": src}, raw, loc, decoder="lab-fw")
        return
    p = FW_PACKET.search(msg)
    if not p:
        return
    action, src, dst, proto = p.groups()
    data = {"action": action, "srcip": src, "dstip": dst, "protocol": proto}
    if ports := FW_PORTS.search(msg):
        data["srcport"], data["dstport"] = ports.groups()
    if action.startswith("FW-BLOCKLIST"):
        emit("100103", 7, f"Firewall do lab: trafego de IP em quarentena (blocklist) {src}",
             ["lab-fw", "firewall"], MANAGER, data, raw, loc, decoder="lab-fw")
        return
    if action.startswith("FW-DROP"):
        emit("100101", 5, f"Firewall do lab: trafego bloqueado {src} -> {dst}:{data.get('dstport', '')} ({proto})",
             ["lab-fw", "firewall", "firewall_drop", "pci_dss_1.4"], MANAGER, data, raw, loc, decoder="lab-fw")
        if n := FW_FREQ.hit(src):
            emit("100102", 10, f"Firewall do lab: muitas conexoes bloqueadas da mesma origem ({src})",
                 ["lab-fw", "firewall", "multiple_drops"], MANAGER, data, raw, loc, ["T1046"], "lab-fw", firedtimes=n)


class SyslogHandler(socketserver.BaseRequestHandler):
    def handle(self):
        handle_syslog(self.request[0].decode("utf-8", "replace"), self.client_address[0])


# ------------------------------------------------------------------ Suricata (eve.json)
def suricata_rule(ev: dict) -> tuple[str, int, str, list[str]]:
    a = ev.get("alert", {})
    sev, sid, sig = int(a.get("severity", 3)), int(a.get("signature_id", 0)), a.get("signature", "")
    if sid == 9100001:
        return "100210", 10, f"Suricata (lab): multiplas tentativas de conexao SSH de {ev.get('src_ip')}", ["T1110"]
    if sid == 9100002:
        return "100211", 8, f"Suricata (lab): possivel varredura de portas na LAN a partir de {ev.get('src_ip')}", ["T1046"]
    if sev == 1:
        return "100200", 10, f"Suricata (sev. 1): {sig}", []
    if sev == 2:
        return "100201", 7, f"Suricata (sev. 2): {sig}", []
    return "100202", 4, f"Suricata (sev. 3): {sig}", []


def handle_eve(line: str, location: str) -> None:
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return
    if ev.get("event_type") != "alert":
        return
    rid, lvl, desc, mids = suricata_rule(ev)
    emit(rid, lvl, desc, ["ids", "suricata", "lab-ids"], MANAGER, ev, "", location, mids, "json")


# ------------------------------------------------------------------ sshd (auth.log)
FAIL = re.compile(r"sshd\[\d+\]: Failed (?:password|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port (\d+)")
INVALID = re.compile(r"sshd\[\d+\]: Invalid user (\S+) from (\S+) port (\d+)")
ACCEPT = re.compile(r"sshd\[\d+\]: Accepted \S+ for (\S+) from (\S+) port (\d+)")
F5763, F5712 = Frequency(8, 120, 60), Frequency(8, 120, 60)
SSH_GROUPS = ["syslog", "sshd", "authentication_failed", "invalid_login"]


def handle_auth(line: str) -> None:
    line = line.rstrip("\n")
    if m := INVALID.search(line):
        user, ip, port = m.groups()
        data = {"srcip": ip, "srcport": port, "srcuser": user}
        emit("5710", 5, "sshd: Attempt to login using a non-existent user",
             SSH_GROUPS, SERVER, data, line, AUTH_LOG.as_posix(), ["T1110.001", "T1021.004"], "sshd")
        if n := F5712.hit(ip):
            emit("5712", 10, "sshd: brute force trying to get access to the system. Non existent user.",
                 ["syslog", "sshd", "authentication_failures"], SERVER, data, line, AUTH_LOG.as_posix(),
                 ["T1110"], "sshd", firedtimes=n)
        return
    if m := FAIL.search(line):
        invalid, user, ip, port = m.groups()
        data = {"srcip": ip, "srcport": port, "dstuser": user}
        emit("5760", 5, "sshd: authentication failed.", ["syslog", "sshd", "authentication_failed"], SERVER,
             data, line, AUTH_LOG.as_posix(), ["T1110.001", "T1021.004"], "sshd")
        if n := F5763.hit(ip):
            emit("5763", 10, "sshd: brute force trying to get access to the system. Authentication failed.",
                 ["syslog", "sshd", "authentication_failures"], SERVER, data, line, AUTH_LOG.as_posix(),
                 ["T1110"], "sshd", firedtimes=n)
        return
    if m := ACCEPT.search(line):
        user, ip, port = m.groups()
        emit("5715", 3, "sshd: authentication success.", ["syslog", "sshd", "authentication_success"], SERVER,
             {"srcip": ip, "srcport": port, "dstuser": user}, line, AUTH_LOG.as_posix(), ["T1078", "T1021"], "sshd")


# ------------------------------------------------------------------ FIM
def snapshot() -> dict[str, tuple[int, str, str]]:
    snap = {}
    for base in FIM_DIRS:
        for p in base.rglob("*"):
            try:
                if not p.is_file() or p.is_symlink() or FIM_IGNORE.search(p.as_posix()):
                    continue
                st = p.stat()
                if st.st_size > 2_000_000:
                    continue
                data = p.read_bytes()
                text = data.decode("utf-8") if st.st_size < 20000 and b"\0" not in data else ""
                snap[p.as_posix()] = (st.st_size, hashlib.sha256(data).hexdigest(), text)
            except (OSError, UnicodeDecodeError):
                continue
    return snap


def fim_loop() -> None:
    old = snapshot()
    print(f"[fim] baseline com {len(old)} arquivos em /etc e /var/www", flush=True)
    while True:
        time.sleep(5)
        new = snapshot()
        for path in sorted(set(new) - set(old)):
            emit("554", 5, "File added to the system.", ["ossec", "syscheck", "syscheck_entry_added", "syscheck_file"],
                 SERVER, None, f"File '{path}' added", "syscheck", decoder="syscheck_new_entry",
                 extra={"syscheck": {"path": path, "event": "added", "size_after": str(new[path][0]),
                                     "sha256_after": new[path][1], "mode": "realtime"}})
        for path in sorted(set(old) & set(new)):
            if old[path][1] != new[path][1]:
                diff = "".join(difflib.unified_diff(old[path][2].splitlines(True), new[path][2].splitlines(True),
                                                    n=0))[-600:]
                emit("550", 7, "Integrity checksum changed.",
                     ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"], SERVER, None,
                     f"File '{path}' modified", "syscheck", ["T1565.001"], "syscheck_integrity_changed",
                     extra={"syscheck": {"path": path, "event": "modified", "size_before": str(old[path][0]),
                                         "size_after": str(new[path][0]), "sha256_before": old[path][1],
                                         "sha256_after": new[path][1], "changed_attributes": ["size", "sha256"],
                                         "diff": diff, "mode": "realtime"}})
        for path in sorted(set(old) - set(new)):
            emit("553", 7, "File deleted.", ["ossec", "syscheck", "syscheck_entry_deleted", "syscheck_file"], SERVER,
                 None, f"File '{path}' deleted", "syscheck", ["T1070.004", "T1485"], "syscheck_deleted",
                 extra={"syscheck": {"path": path, "event": "deleted", "mode": "realtime"}})
        old = new


# ------------------------------------------------------------------ tail generico
def tail(path: Path, handler, *args) -> None:
    pos = path.stat().st_size if path.exists() else 0
    while True:
        try:
            if path.exists():
                size = path.stat().st_size
                if size < pos:
                    pos = 0
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(pos)
                    for line in fh:
                        if line.endswith("\n"):
                            pos += len(line.encode("utf-8"))
                            handler(line, *args)
        except OSError:
            pass
        time.sleep(1)


# ------------------------------------------------------------------ API (agentes / active response)
TOKENS: set[str] = set()


def agent_active(ns: str) -> bool:
    """Maquina simulada ligada (namespace existe e a interface esta UP) = agente conectado."""
    r = subprocess.run(["ip", "netns", "exec", ns, "ip", "-br", "link", "show", "eth0"], capture_output=True, text=True)
    return r.returncode == 0 and " UP " in f" {r.stdout} "


class Api(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _authed(self) -> bool:
        tok = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if tok not in TOKENS:
            self._send(401, {"title": "Unauthorized"})
            return False
        return True

    def do_POST(self):  # noqa: N802
        if self.path.startswith("/security/user/authenticate"):
            tok = secrets.token_hex(16)
            TOKENS.add(tok)
            return self._send(200, {"data": {"token": tok}, "error": 0})
        self._send(404, {"error": 1})

    def do_GET(self):  # noqa: N802
        if not self._authed():
            return
        if self.path.startswith("/agents"):
            items = [{**MANAGER, "ip": "127.0.0.1", "status": "active", "version": "emulador"}]
            for ag, ns in ((SERVER, "srv"), (CLIENTE, "cli")):
                items.append({**ag, "status": "active" if agent_active(ns) else "disconnected",
                              "version": "simulado"})
            return self._send(200, {"data": {"affected_items": items, "total_affected_items": len(items)}})
        self._send(404, {"error": 1})

    def do_PUT(self):  # noqa: N802
        if not self._authed():
            return
        q = parse_qs(urlparse(self.path).query)
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        ip = body.get("alert", {}).get("data", {}).get("srcip")
        agents = q.get("agents_list", [""])[0].split(",")
        failed = []
        if body.get("command") == "!firewall-drop" and ip and "001" in agents:
            r = subprocess.run(["ip", "netns", "exec", "srv", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                               capture_output=True, text=True)
            line = f"{datetime.now(TZ):%Y/%m/%d %H:%M:%S} active-response/bin/firewall-drop: add {ip} (lab-server)"
            AR_LOG.parent.mkdir(parents=True, exist_ok=True)
            with AR_LOG.open("a") as fh:
                fh.write(line + "\n")
            if r.returncode == 0:
                emit("651", 3, "Host Blocked by firewall-drop Active Response", ["ossec", "active_response"],
                     SERVER, {"srcip": ip, "command": "add"}, line, "/var/ossec/logs/active-responses.log",
                     decoder="ar_log_json")
            else:
                failed.append({"error": r.stderr.strip()})
        else:
            failed.append({"error": "comando/agente nao suportado no emulador"})
        self._send(200, {"data": {"affected_items": [] if failed else agents, "total_failed_items": len(failed),
                                  "failed_items": failed}, "message": "AR enviado" if not failed else "falha"})

    def log_message(self, *a):
        pass


def start_api() -> None:
    cert, key = "/var/lib/lab-sim/api.crt", "/var/lib/lab-sim/api.key"
    if not os.path.exists(cert):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj",
                        "/CN=siem-emulador", "-keyout", key, "-out", cert], capture_output=True, check=True)
    srv = ThreadingHTTPServer(("172.30.0.10", 55000), Api)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def main() -> None:
    Path("/var/log/lab-sim").mkdir(parents=True, exist_ok=True)
    for f in EVE_FILES:
        f.touch(exist_ok=True)
    threads = [
        threading.Thread(target=socketserver.ThreadingUDPServer(("172.30.0.10", 514), SyslogHandler).serve_forever),
        threading.Thread(target=start_api),
        threading.Thread(target=fim_loop),
        threading.Thread(target=tail, args=(AUTH_LOG, handle_auth)),
    ] + [threading.Thread(target=tail, args=(f, handle_eve, f.as_posix())) for f in EVE_FILES]
    for t in threads:
        t.daemon = True
        t.start()
    print("[emulador] coletando: syslog 172.30.0.10:514, eve.json, auth.log, FIM /etc /var/www; API 55000", flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
