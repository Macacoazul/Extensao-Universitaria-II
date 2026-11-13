"""Site externo ficticio (198.51.100.10, faixa de documentacao RFC 5737).

Serve a mesma resposta usada pelo teste publico testmynids.org/uid/index.html
("uid=0(root) gid=0(root) groups=0(root)"), que dispara a assinatura do IDS
GPL ATTACK_RESPONSE id check returned root. Nao ha nenhum conteudo malicioso.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (b"uid=0(root) gid=0(root) groups=0(root)\n" if self.path.startswith("/uid")
                else b"<html><body><h1>Site externo ficticio do ambiente experimental</h1></body></html>\n")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain" if self.path.startswith("/uid") else "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        # mostra o IP de origem visto pelo "site externo": com NAT deve ser o IP WAN do firewall
        print(f"[site-externo] requisicao de {self.client_address[0]}: {self.requestline}", flush=True)


HTTPServer(("0.0.0.0", 80), H).serve_forever()
