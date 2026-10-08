import json
import urllib.error

import pytest
from app.npm_registry import MAX_BYTES, RegistryError, fetch_versions


class Response:
    def __init__(self, body):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.body if limit < 0 else self.body[:limit]


def opener_for(body, seen=None):
    def opener(request, timeout):
        if seen is not None:
            seen.append((request.full_url, request.get_header('Accept'), timeout))
        return Response(body)
    return opener


def test_versions_and_deprecations_are_extracted():
    body = {'versions': {'4.17.21': {}, '4.18.0': {'deprecated': 'Bad release.'}, '4.18.1': {'deprecated': ''}}}
    seen = []
    versions, deprecated = fetch_versions('lodash', opener=opener_for(body, seen))
    assert versions == ['4.17.21', '4.18.0', '4.18.1'] and deprecated == ['4.18.0']
    assert seen == [('https://registry.npmjs.org/lodash', 'application/vnd.npm.install-v1+json', 20)]


def test_scoped_package_name_is_encoded():
    seen = []
    fetch_versions('@types/node', opener=opener_for({'versions': {'1.0.0': {}}}, seen))
    assert seen[0][0] == 'https://registry.npmjs.org/@types%2Fnode'


@pytest.mark.parametrize('name', ['', '--registry=evil', '../etc', 'a b', 'UPPER', 'a/b', None, 'x' * 215])
def test_unsafe_names_never_reach_the_network(name):
    def opener(request, timeout):
        raise AssertionError('сетевой запрос не должен выполняться')
    with pytest.raises(RegistryError):
        fetch_versions(name, opener=opener)


@pytest.mark.parametrize('body', [b'not json', b'[]', json.dumps({'versions': {}}).encode(),
                                  json.dumps({'versions': ['1.0.0']}).encode(), b'null'])
def test_unexpected_answers_are_errors_not_empty_lists(body):
    with pytest.raises(RegistryError):
        fetch_versions('lodash', opener=opener_for(body))


def test_network_failure_is_an_error():
    def opener(request, timeout):
        raise urllib.error.URLError('no route')
    with pytest.raises(RegistryError, match='недоступен'):
        fetch_versions('lodash', opener=opener)


def test_oversized_answer_is_rejected():
    with pytest.raises(RegistryError, match='лимит'):
        fetch_versions('lodash', opener=opener_for(b'x' * (MAX_BYTES + 10)))
