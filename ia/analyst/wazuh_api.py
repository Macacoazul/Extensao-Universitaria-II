"""Cliente minimo da API do Wazuh (agentes e active response)."""
from __future__ import annotations

import logging
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # certificado autoassinado do lab
log = logging.getLogger(__name__)


class WazuhAPI:
    def __init__(self, url: str, user: str, password: str):
        self.url, self.user, self.password = url, user, password
        self._token, self._exp = None, 0.0

    def _headers(self) -> dict:
        if not self._token or time.time() > self._exp:
            r = requests.post(f"{self.url}/security/user/authenticate", auth=(self.user, self.password),
                              verify=False, timeout=15)
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            self._exp = time.time() + 600
        return {"Authorization": f"Bearer {self._token}"}

    def agents(self) -> list[dict]:
        r = requests.get(f"{self.url}/agents", headers=self._headers(), verify=False, timeout=15,
                         params={"select": "id,name,ip,status,version,lastKeepAlive", "limit": 500})
        r.raise_for_status()
        return r.json().get("data", {}).get("affected_items", [])

    def agent_id(self, name: str) -> str | None:
        for a in self.agents():
            if a.get("name") == name:
                return a.get("id")
        return None

    def firewall_drop(self, agent_id: str, srcip: str) -> dict:
        """Executa o script firewall-drop (iptables) no agente para bloquear srcip."""
        body = {"command": "!firewall-drop", "arguments": [], "alert": {"data": {"srcip": srcip}}}
        r = requests.put(f"{self.url}/active-response", headers=self._headers(), verify=False, timeout=20,
                         params={"agents_list": agent_id}, json=body)
        r.raise_for_status()
        return r.json()
