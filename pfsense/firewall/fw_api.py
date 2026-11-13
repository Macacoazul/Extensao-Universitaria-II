#!/usr/bin/env python3
"""API minima de bloqueio do firewall do lab (somente rede de gerencia).

POST /block   {"ip": "192.168.10.20", "timeout": "1h", "reason": "..."}
POST /unblock {"ip": "192.168.10.20"}
GET  /blocklist
GET  /health
Cabecalho obrigatorio: X-Token: <FW_API_TOKEN>

Salvaguardas: so aceita IPs dentro de FW_BLOCK_NETWORKS (padrao: LAN do lab)
e nunca bloqueia IPs listados em FW_PROTECTED (gateway, Wazuh, IA).
Tambem pode ser usado como CLI: fw_api.py --cli block <ip> [tempo].
"""
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("FW_API_TOKEN", "")
NETWORKS = [ipaddress.ip_network(n.strip()) for n in
            os.environ.get("FW_BLOCK_NETWORKS", os.environ.get("LAN_SUBNET", "192.168.10.0/24")).split(",") if n.strip()]
PROTECTED = {p.strip() for p in os.environ.get("FW_PROTECTED", "").split(",") if p.strip()}
LOG = "/var/log/lab-fw/firewall.log"
TIMEOUT_RE = re.compile(r"^\d+[smhd]$")


def audit(action: str, ip: str, detail: str) -> None:
    stamp = datetime.now(timezone.utc).astimezone().strftime("%b %d %H:%M:%S")
    with open(LOG, "a", encoding="utf-8") as fh:
        fh.write(f"{stamp} fw FW-API {action} SRC={ip} {detail}\n")


def validate(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if ip in PROTECTED:
        raise ValueError(f"{ip} esta na lista de IPs protegidos")
    if not any(addr in n for n in NETWORKS):
        raise ValueError(f"{ip} fora das redes permitidas {[str(n) for n in NETWORKS]}")
    return str(addr)


def nft(*args: str) -> str:
    out = subprocess.run(["nft", *args], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    return out.stdout


def block(ip: str, timeout: str = "1h", reason: str = "") -> dict:
    ip = validate(ip)
    timeout = timeout if TIMEOUT_RE.match(timeout or "") else "1h"
    nft("add", "element", "inet", "filter", "blocklist", "{", ip, "timeout", timeout, "}")
    audit("BLOCK", ip, f"TIMEOUT={timeout} REASON={reason[:120]!r}")
    return {"blocked": ip, "timeout": timeout}


def unblock(ip: str) -> dict:
    ip = str(ipaddress.ip_address(ip))
    nft("delete", "element", "inet", "filter", "blocklist", "{", ip, "}")
    audit("UNBLOCK", ip, "")
    return {"unblocked": ip}


def blocklist() -> list:
    data = json.loads(nft("-j", "list", "set", "inet", "filter", "blocklist"))
    for item in data.get("nftables", []):
        if "set" in item:
            elems = item["set"].get("elem", [])
            return [e if isinstance(e, str) else e.get("elem", {}).get("val") for e in elems]
    return []


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _auth(self) -> bool:
        if not TOKEN or self.headers.get("X-Token") != TOKEN:
            self._send(401, {"error": "token invalido"})
            return False
        return True

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            return self._send(200, {"status": "ok"})
        if not self._auth():
            return
        if self.path == "/blocklist":
            return self._send(200, {"blocklist": blocklist()})
        self._send(404, {"error": "rota inexistente"})

    def do_POST(self):  # noqa: N802
        if not self._auth():
            return
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path == "/block":
                return self._send(200, block(body["ip"], body.get("timeout", "1h"), body.get("reason", "")))
            if self.path == "/unblock":
                return self._send(200, unblock(body["ip"]))
            self._send(404, {"error": "rota inexistente"})
        except (KeyError, ValueError) as exc:
            self._send(400, {"error": str(exc)})
        except RuntimeError as exc:
            self._send(500, {"error": str(exc)})

    def log_message(self, fmt, *args):  # silencia log padrao no stdout
        return


def main() -> None:
    if len(sys.argv) >= 4 and sys.argv[1] == "--cli":
        action, ip = sys.argv[2], sys.argv[3]
        try:
            result = block(ip, sys.argv[4] if len(sys.argv) > 4 else "1h", "manual") if action == "block" else unblock(ip)
            print(json.dumps(result))
        except (ValueError, RuntimeError) as exc:
            print(f"erro: {exc}", file=sys.stderr)
            sys.exit(1)
        return
    bind = os.environ.get("FW_MGMT_IP", "0.0.0.0")
    ThreadingHTTPServer((bind, 8088), Handler).serve_forever()


if __name__ == "__main__":
    main()
