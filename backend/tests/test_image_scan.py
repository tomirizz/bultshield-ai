import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from app import image_scan
from app.image_scan import (
    ImageRef,
    ImageScanError,
    parse_reference,
    resolve_digest,
    run_image_scan,
)

FIXTURE = Path(__file__).parent / 'fixtures' / 'trivy_image_report.json'
DIGEST = 'sha256:1566a7c1278013df557f3a960691911f1b4708c7015238c44ad0e16ada5bfb4e'
OTHER = 'sha256:' + 'b' * 64
LOCAL = 'localhost:5001/bultshield-demo-app:main'

FAKE_TRIVY = """#!/bin/sh
dir=$(dirname "$0")
echo "$1" >> "$dir/calls.txt"
env > "$dir/env-$1.txt"
echo "$@" > "$dir/args-$1.txt"
mode=$(cat "$dir/mode")
cache=""; out=""; prev=""
for arg in "$@"; do
  [ "$prev" = "--cache-dir" ] && cache="$arg"
  [ "$prev" = "--output" ] && out="$arg"
  prev="$arg"
done
if [ "$1" = "fs" ]; then
  mkdir -p "$cache/db"
  cp "$dir/metadata.json" "$cache/db/metadata.json"
  exit 0
fi
[ "$mode" = "exit1" ] && exit 1
[ "$mode" = "slow" ] && sleep 30
printf '2026-10-06T00:00:00Z\\tINFO\\tVulnerability scanning is enabled\\n'
printf '2026-10-06T00:00:00Z\\tWARN\\tUsing severities from other vendors for some vulnerabilities.\\n'
[ "$mode" = "warn" ] && printf '2026-10-06T00:00:00Z\\tWARN\\tsomething went wrong\\n'
cp "$dir/report.json" "$out"
"""


def report(digests=(f'localhost:5001/bultshield-demo-app@{DIGEST}',)):
    data = json.loads(FIXTURE.read_text())
    data['Metadata']['RepoDigests'] = list(digests)
    return data


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    fake = bin_dir / 'trivy'
    fake.write_text(FAKE_TRIVY)
    fake.chmod(0o755)
    monkeypatch.setattr(Path, 'home', lambda: home)
    monkeypatch.setattr(image_scan.shutil, 'which', lambda name: str(fake))
    monkeypatch.setenv('IMAGE_ALLOWED_REGISTRIES', 'localhost:5001, ghcr.io')
    monkeypatch.setenv('DATABASE_URL', 'PRIVATE_SOURCE')
    monkeypatch.setenv('GITHUB_CLIENT_SECRET', 'PRIVATE_SOURCE')

    def prepare(mode='ok', data=None, age_hours=0, raw=None):
        (bin_dir / 'mode').write_text(mode)
        stamp = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat()
        (bin_dir / 'metadata.json').write_text(json.dumps({'UpdatedAt': stamp}))
        (bin_dir / 'report.json').write_text(raw if raw is not None else json.dumps(data or report()))
        return bin_dir

    prepare()
    return prepare


@pytest.mark.parametrize('text,host,path,tag,digest', [
    (LOCAL, 'localhost:5001', 'bultshield-demo-app', 'main', None),
    ('ghcr.io/tomirizz/bultshield-demo-app:v1.2', 'ghcr.io', 'tomirizz/bultshield-demo-app', 'v1.2', None),
    (f'ghcr.io/tomirizz/app@{DIGEST}', 'ghcr.io', 'tomirizz/app', None, DIGEST),
])
def test_valid_references(text, host, path, tag, digest):
    ref = parse_reference(text, allowed={'localhost:5001', 'ghcr.io'})
    assert (ref.host, ref.path, ref.tag, ref.digest) == (host, path, tag, digest)
    assert ref.text == text


@pytest.mark.parametrize('text', [
    '', 'app:main', 'ghcr.io/app', 'ghcr.io/Owner/app:main', ' ghcr.io/app:main', 'ghcr.io/app:main ',
    '--flag', '-ghcr.io/app:main', 'ghcr.io/../app:main', 'https://ghcr.io/app:main', 'ghcr.io/app:-x',
    'ghcr.io/app:main;rm', 'ghcr.io/app@sha256:abc', 'ghcr.io/' + 'a' * 300 + ':main', 'ghcr.io//app:main',
    'ghcr.io/app:main@' + DIGEST, None, 42,
])
def test_invalid_references_are_rejected(text):
    with pytest.raises(ImageScanError):
        parse_reference(text, allowed={'ghcr.io'})


def test_registry_must_be_explicit():
    with pytest.raises(ImageScanError, match='явно'):
        parse_reference('owner/app:main', allowed={'owner'})


def test_registry_must_be_allowed_and_default_is_disabled(monkeypatch):
    with pytest.raises(ImageScanError, match='разрешённых'):
        parse_reference('evil.example.com/app:main', allowed={'ghcr.io'})
    monkeypatch.delenv('IMAGE_ALLOWED_REGISTRIES', raising=False)
    with pytest.raises(ImageScanError, match='разрешённых'):
        parse_reference('ghcr.io/owner/app:main')


def test_resolve_digest_cases():
    tagged = ImageRef('localhost:5001', 'app', 'main', None)
    assert resolve_digest(tagged, [f'localhost:5001/app@{DIGEST}']) == DIGEST
    assert resolve_digest(tagged, ['other.io/app@' + OTHER, f'localhost:5001/app@{DIGEST}']) == DIGEST
    for digests in ([], ['other.io/app@' + OTHER], [f'localhost:5001/app@{DIGEST}', f'localhost:5001/app@{OTHER}']):
        with pytest.raises(ImageScanError):
            resolve_digest(tagged, digests)
    pinned = ImageRef('localhost:5001', 'app', None, DIGEST)
    assert resolve_digest(pinned, []) == DIGEST
    with pytest.raises(ImageScanError, match='не совпадает'):
        resolve_digest(pinned, [f'localhost:5001/app@{OTHER}'])


def test_successful_scan_returns_digest_and_findings(sandbox):
    bin_dir = sandbox()
    result = run_image_scan(LOCAL)
    assert result.digest == DIGEST
    assert result.report.summary['by_origin'] == {'os': 4, 'app': 7, 'base-tooling': 3}
    assert result.summary['scope'] == 'registry_image' and result.summary['digest'] == DIGEST
    assert (bin_dir / 'calls.txt').read_text().split() == ['fs', 'image']
    args = (bin_dir / 'args-image.txt').read_text().split()
    assert args[-1] == LOCAL
    for expected in ('--image-src', 'remote', '--skip-db-update', '--scanners', 'vuln', '--ignorefile'):
        assert expected in args
    assert args[args.index('--platform') + 1] == 'linux/amd64'


def test_scanner_does_not_receive_worker_secrets(sandbox):
    bin_dir = sandbox()
    run_image_scan(LOCAL)
    for name in ('env-fs.txt', 'env-image.txt'):
        assert 'PRIVATE_SOURCE' not in (bin_dir / name).read_text()


def test_unexpected_warning_means_incomplete_scan(sandbox):
    sandbox(mode='warn')
    with pytest.raises(ImageScanError, match='неполной'):
        run_image_scan(LOCAL)


def test_nonzero_exit_is_an_error(sandbox):
    sandbox(mode='exit1')
    with pytest.raises(ImageScanError, match='ошибкой'):
        run_image_scan(LOCAL)


def test_stale_database_stops_before_scanning(sandbox):
    bin_dir = sandbox(age_hours=48)
    with pytest.raises(ImageScanError, match='устарела'):
        run_image_scan(LOCAL)
    assert (bin_dir / 'calls.txt').read_text().split() == ['fs']


def test_broken_report_is_an_error_not_clean(sandbox):
    sandbox(raw='not json')
    with pytest.raises(ImageScanError):
        run_image_scan(LOCAL)
    empty = report()
    empty['Results'] = []
    sandbox(data=empty)
    with pytest.raises(ImageScanError, match='не определён'):
        run_image_scan(LOCAL)


def test_missing_digest_in_report_is_an_error(sandbox):
    sandbox(data=report(digests=()))
    with pytest.raises(ImageScanError, match='digest'):
        run_image_scan(LOCAL)


def test_timeout_kills_the_process(sandbox, monkeypatch):
    sandbox(mode='slow')
    monkeypatch.setenv('TRIVY_TIMEOUT_SECONDS', '1')
    started = time.monotonic()
    with pytest.raises(ImageScanError, match='лимит'):
        run_image_scan(LOCAL)
    assert time.monotonic() - started < 10


def test_missing_trivy_and_bad_platform(sandbox, monkeypatch):
    with pytest.raises(ImageScanError, match='платформа'):
        run_image_scan(LOCAL, platform='linux/amd64; rm')
    monkeypatch.setattr(image_scan.shutil, 'which', lambda name: None)
    with pytest.raises(ImageScanError, match='не установлен'):
        run_image_scan(LOCAL)
