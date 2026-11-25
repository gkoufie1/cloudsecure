#!/bin/bash
set -euo pipefail
mkdir -p /opt/cloudsecure
cat >/opt/cloudsecure/app.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import json

ROUTES = {
    '/': {'service': 'CloudSecure', 'synthetic': True},
    '/health': {'status': 'ok'},
    '/api/transactions': {'transactions': [{'id': 'demo-001', 'status': 'approved', 'amount': 25}]},
}

class App(BaseHTTPRequestHandler):
    server_version = 'CloudSecure'
    sys_version = ''

    def send_json(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ROUTES:
            self.send_json(200, ROUTES[path])
        else:
            self.send_json(404, {'error': 'not found'})

ThreadingHTTPServer(('127.0.0.1', 8080), App).serve_forever()
PY
cat >/etc/systemd/system/cloudsecure.service <<'UNIT'
[Unit]
Description=CloudSecure synthetic demo
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/cloudsecure/app.py
DynamicUser=yes
NoNewPrivileges=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now cloudsecure
