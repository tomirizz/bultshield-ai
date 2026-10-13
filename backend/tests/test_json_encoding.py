"""JSON opened directly in Safari must explicitly declare its UTF-8 encoding."""
from app.config import get_settings
from app.main import create_app
from fastapi.testclient import TestClient


def test_russian_api_response_declares_utf8(client):
    name = 'Проверка безопасности — қазақша'
    result = client.post('/api/projects', json={'name': name})
    assert result.status_code == 201
    assert name.encode('utf-8') in result.content
    assert result.headers['content-type'] == 'application/json; charset=utf-8'
    assert result.json()['name'] == name


def test_russian_auth_error_declares_utf8(client, monkeypatch):
    monkeypatch.setattr(get_settings(), 'auth_enabled', True)
    result = client.get('/api/projects')
    assert result.status_code == 401
    assert result.json()['detail'] == 'Войдите через GitHub.'
    assert result.headers['content-type'] == 'application/json; charset=utf-8'
    assert result.headers['x-content-type-options'] == 'nosniff'


def test_html_keeps_its_content_type(monkeypatch, tmp_path):
    (tmp_path / 'index.html').write_text('<!doctype html><title>Проверка</title>')
    monkeypatch.setattr(get_settings(), 'frontend_dist', tmp_path)
    with TestClient(create_app()) as client:
        result = client.get('/')
    assert result.status_code == 200
    assert result.headers['content-type'] == 'text/html; charset=utf-8'
