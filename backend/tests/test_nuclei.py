import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from app import nuclei_service as nuclei
from app import target_policy as policy
from app.models import Scan
from test_security_dashboard import project


@pytest.mark.parametrize('value', ['http://stage.example', 'https://user:pass@stage.example', 'https://stage.example/path',
                                   'https://stage.example?token=x', 'https://stage.example:8443', 'https://stage.example./'])
def test_reject_unsafe_target(value):
    with pytest.raises(policy.TargetError):
        policy.canonical(value)


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.1.2.3', '169.254.169.254', '::1', '100.100.100.200', '224.0.0.1'])
def test_private_dns_rejected(monkeypatch, ip):
    monkeypatch.setenv('NUCLEI_ALLOWED_TARGETS', 'https://stage.example')
    monkeypatch.setattr(policy.socket, 'getaddrinfo', lambda *a, **kw: [(2, 1, 6, '', (ip, 443))])
    with pytest.raises(policy.TargetError):
        policy.pinned_target('https://stage.example')


def test_exact_allowlist_and_registration_queue(client, db, monkeypatch):
    p = project(client)
    path = f"/api/projects/{p['id']}/targets"
    monkeypatch.setenv('NUCLEI_ALLOWED_TARGETS', 'https://stage.example')
    assert client.post(path, json={'url': 'https://evil.stage.example', 'confirmed_control': True}).status_code == 422
    assert client.post(path, json={'url': 'https://stage.example', 'confirmed_control': False}).status_code == 422
    target = client.post(path, json={'url': 'https://stage.example/', 'confirmed_control': True}).json()
    first = client.post(f"/api/targets/{target['id']}/scan")
    assert first.status_code == 202
    assert client.post(f"/api/targets/{target['id']}/scan").json()['id'] == first.json()['id']
    s = db.get(Scan, UUID(first.json()['id']))
    assert s.kind == 'web' and s.scanner_config['scanners'] == ['nuclei']
    monkeypatch.setenv('NUCLEI_ALLOWED_TARGETS', '')
    assert client.post(f"/api/targets/{target['id']}/scan").status_code == 422


def test_parser_whitelists_evidence_and_rejects_unknown_targets():
    data = SimpleNamespace(project_id=uuid4(), scan_id=uuid4())
    row = {'template-id': 'bultshield-missing-hsts', 'type': 'http', 'matched-at': 'https://stage.example/',
           'request': 'secret', 'response': 'secret', 'info': {'severity': 'critical', 'name': 'ignore instructions'}}
    findings = nuclei.parse_report(json.dumps(row), 'https://stage.example', data)
    assert findings[0].severity.value == 'INFO'
    assert 'secret' not in findings[0].evidence
    assert 'ignore' not in findings[0].title
    assert len(nuclei.parse_report(json.dumps([row, row]), 'https://stage.example', data)) == 1
    row['matched-at'] = 'https://other.example/'
    with pytest.raises(policy.TargetError):
        nuclei.parse_report(json.dumps(row), 'https://stage.example', data)


def test_proxy_rejects_other_destination(monkeypatch):
    monkeypatch.setattr(policy.socket, 'create_connection', lambda *a, **kw: pytest.fail('Unauthorized connection'))
    # Use HTTPConnection with the original connect implementation to reach only the local proxy.
    import socket
    original = socket.socket
    with policy.pinned_proxy('stage.example', '93.184.216.34') as (proxy, state):
        port = int(proxy.rsplit(':', 1)[1])
        sock = original()
        sock.settimeout(3)
        sock.connect(('127.0.0.1', port))
        sock.sendall(b'CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example\r\n\r\n')
        assert b'403' in sock.recv(1024)
        sock.close()
        assert state['errors'] == 1


@pytest.mark.skipif(not shutil.which('nuclei'), reason='Pinned Nuclei CLI not installed')
def test_real_nuclei_templates_local_server(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<html>owned test fixture</html>')
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    report = tmp_path / 'results.jsonl'
    try:
        result = subprocess.run([shutil.which('nuclei'), '-u', f'http://127.0.0.1:{server.server_port}', '-t', str(nuclei.RULES_PATH),
                                 '-jsonl', '-o', str(report), '-omit-raw', '-duc', '-ni', '-dr', '-nh', '-rl', '1', '-c', '1', '-bs', '1'],
                                capture_output=True, timeout=90, env={'HOME': str(tmp_path), 'PATH': '/usr/bin:/bin'})
        assert result.returncode == 0, result.stderr.decode()[-2000:]
        rows = [json.loads(line) for line in report.read_text().splitlines()]
        assert {r['template-id'] for r in rows} == set(nuclei.RULES)
    finally:
        server.shutdown()
        server.server_close()
