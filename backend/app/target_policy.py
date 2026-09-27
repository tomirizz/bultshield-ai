"""Exact origin allowlist and pinned-IP transport; no arbitrary-target proxy."""
import ipaddress
import os
import select
import socket
import ssl
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class TargetError(RuntimeError):
    pass


def canonical(value):
    try:
        u = urlsplit(value.strip())
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('', '/') or u.port not in (None, 443):
            raise ValueError()
        host = u.hostname.encode('idna').decode('ascii').lower()
        if host.endswith('.') or '.' not in host or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-.' for c in host):
            raise ValueError()
        return 'https://' + host
    except (ValueError, UnicodeError, AttributeError):
        raise TargetError('Укажите HTTPS origin без пути, параметров, пароля и нестандартного порта.') from None


def allowed_origins():
    return {canonical(v) for v in os.environ.get('NUCLEI_ALLOWED_TARGETS', '').split(',') if v.strip()}


def allowed_target(value):
    origin = canonical(value)
    if origin not in allowed_origins():
        raise TargetError('Этот адрес не включён оператором в NUCLEI_ALLOWED_TARGETS. Добавление через форму не расширяет allowlist.')
    return origin


def pinned_target(value):
    origin = allowed_target(value)
    host = urlsplit(origin).hostname
    try:
        ips = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
        if not ips or any(not ipaddress.ip_address(ip).is_global or ipaddress.ip_address(ip).is_multicast for ip in ips):
            raise TargetError('Внутренние, локальные и служебные адреса сканировать нельзя.')
    except socket.gaierror:
        raise TargetError('Не удалось проверить адрес staging-сервиса.') from None
    return origin, host, ips[0]


def preflight(host, ip):
    # Validate reachability and TLS without following redirects, executing JS or reading the body.
    with socket.create_connection((ip, 443), timeout=10) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as connection:
            connection.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: BultShield-Staging-Check\r\n\r\n'.encode())
            first = connection.recv(4096).split(b'\r\n', 1)[0]
            if not first.startswith((b'HTTP/1.1 2', b'HTTP/1.0 2')):
                raise TargetError('Staging должен возвращать успешный ответ по указанному HTTPS origin без перенаправлений.')


@contextmanager
def pinned_proxy(host, ip):
    """CONNECT only to the exact authorized host/IP; reject every other destination."""
    state = {'connections': 0, 'errors': 0}
    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_CONNECT(self):
            if self.path.lower() != host + ':443':
                state['errors'] += 1
                self.send_error(403)
                return
            try:
                with socket.create_connection((ip, 443), timeout=10) as upstream:
                    state['connections'] += 1
                    self.send_response(200)
                    self.end_headers()
                    deadline, total = time.monotonic() + 30, 0
                    while time.monotonic() < deadline:
                        readable, _, _ = select.select([self.connection, upstream], [], [], 1)
                        for source in readable:
                            chunk = source.recv(65536)
                            if not chunk:
                                return
                            total += len(chunk)
                            if total > 2 * 1024 * 1024:
                                raise TargetError('Response limit')
                            (upstream if source is self.connection else self.connection).sendall(chunk)
            except Exception:
                state['errors'] += 1

        def do_GET(self):
            state['errors'] += 1
            self.send_error(403)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
