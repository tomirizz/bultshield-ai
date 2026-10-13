"""scripts/collect_evidence.py: собирает настоящие ответы системы и честно пишет, что не удалось."""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts' / 'collect_evidence.py'
SCANS = [
    {'id': 'aaaaaaaa-0000-4000-8000-000000000001', 'kind': 'image', 'status': 'COMPLETED', 'created_at': '2026-10-13T10:00:00Z',
     'error_message': None, 'error_code': None, 'scanner_results': {}},
    {'id': 'bbbbbbbb-0000-4000-8000-000000000002', 'kind': 'static', 'status': 'FAILED', 'created_at': '2026-10-09T10:00:00Z',
     'error_message': 'Проверка завершилась ошибкой', 'error_code': 'SCANNER_FAILED',
     'scanner_results': {'gitleaks': {'status': 'FAILED', 'error': 'gitleaks не найден'}, 'trivy': {'status': 'COMPLETED'}}},
    {'id': 'cccccccc-0000-4000-8000-000000000003', 'kind': 'verification', 'status': 'COMPLETED', 'created_at': '2026-10-09T09:00:00Z',
     'error_message': None, 'error_code': None, 'scanner_results': {}},
]


def server(explanations=(202, {'id': 'j1', 'status': 'QUEUED'}), report_status=200):
    class Api(BaseHTTPRequestHandler):
        def _send(self, status, body):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self._send(*explanations)

        def do_GET(self):
            if self.path.startswith('/api/scans'):
                return self._send(200, SCANS)
            if self.path.endswith('/explanations'):
                return self._send(200, {'job': {'status': 'COMPLETED'}, 'llm': {'status': 'COMPLETED'}})
            if '/report' in self.path:
                return self._send(report_status, {'verdict': {'result': 'FINDINGS'}, 'id': self.path})
            self._send(404, {})

        def log_message(self, *args):
            pass

    httpd = HTTPServer(('127.0.0.1', 0), Api)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def run(url, out, *extra):
    return subprocess.run([sys.executable, str(SCRIPT), '--url', url, '--out', str(out), '--skip-sandbox', '--llm-wait', '5', *extra],
                          capture_output=True, text=True, timeout=60)


def test_collects_reports_failures_and_model_state(tmp_path):
    httpd = server()
    result = run(f'http://127.0.0.1:{httpd.server_port}', tmp_path)
    httpd.shutdown()
    assert result.returncode == 0, result.stderr
    names = sorted(p.name for p in (tmp_path / 'examples').iterdir())
    assert names == ['image-COMPLETED-aaaaaaaa.json', 'static-FAILED-bbbbbbbb.json']   # служебная проверка исправления не выгружается
    failed = (tmp_path / 'evidence' / 'failed-scans.txt').read_text()
    assert 'bbbbbbbb' in failed and 'gitleaks не найден' in failed and 'aaaaaaaa' not in failed
    assert json.loads((tmp_path / 'evidence' / 'llm-explanations.txt').read_text())['job']['status'] == 'COMPLETED'
    summary = (tmp_path / 'evidence' / 'summary.txt').read_text()
    assert 'ОТЧЁТ:' in summary and 'FAILED-ПРОВЕРКИ:' in summary and 'ПОЯСНЕНИЯ МОДЕЛИ:' in summary


def test_disconnected_model_and_unreadable_reports_are_written_down_not_hidden(tmp_path):
    httpd = server(explanations=(409, {'detail': 'Модель не подключена: ИИ-пояснения выключены.'}), report_status=500)
    result = run(f'http://127.0.0.1:{httpd.server_port}', tmp_path)
    httpd.shutdown()
    assert result.returncode == 0, result.stderr
    summary = (tmp_path / 'evidence' / 'summary.txt').read_text()
    assert 'не получен (500)' in summary and 'задание не создано (409)' in summary and 'Модель не подключена' in summary
    assert not (tmp_path / 'examples').exists()


def test_unreachable_server_is_reported_and_no_result_is_invented(tmp_path):
    result = run('http://127.0.0.1:9', tmp_path)
    assert result.returncode == 0 and 'НЕ ВЫПОЛНЕНО' in result.stdout
    assert 'Это не значит, что проблем нет' in (tmp_path / 'evidence' / 'summary.txt').read_text()
    assert not (tmp_path / 'examples').exists()


def test_address_is_required(tmp_path):
    result = subprocess.run([sys.executable, str(SCRIPT), '--out', str(tmp_path)], capture_output=True, text=True, timeout=30,
                            env={'PATH': '/usr/bin:/bin'})
    assert result.returncode != 0 and 'Укажите адрес' in result.stderr
