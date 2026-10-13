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


@pytest.mark.parametrize('repository', ['node', 'library/node', 'docker.io/library/node', 'index.docker.io/library/node'])
def test_docker_hub_familiar_names_resolve_to_the_same_repository(repository):
    # Real Trivy 0.74 remote output for docker.io/library/node:22.14.0-alpine uses node@sha256:...
    ref = ImageRef('docker.io', 'library/node', '22.14.0-alpine', None)
    assert resolve_digest(ref, [f'{repository}@{DIGEST}']) == DIGEST


def test_docker_hub_normalization_preserves_repository_and_digest_identity():
    ref = ImageRef('docker.io', 'library/node', '22.14.0-alpine', None)
    for repositories in ([f'other/node@{DIGEST}'], [f'evil.example/library/node@{DIGEST}'],
                         [f'node@{DIGEST}', f'docker.io/library/node@{OTHER}']):
        with pytest.raises(ImageScanError):
            resolve_digest(ref, repositories)
    with pytest.raises(ImageScanError, match='не совпадает'):
        resolve_digest(ImageRef('docker.io', 'library/node', None, DIGEST), [f'node@{OTHER}'])


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
    bin_dir = sandbox(age_hours=72)
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


# --- скан локального образа из tar-архива (используется песочницей) ---

def archive_file(tmp_path, size=16):
    path = tmp_path / 'candidate.tar'
    path.write_bytes(b'x' * size)
    return path


def test_archive_scan_reads_tar_and_collects_packages(sandbox, tmp_path):
    data = report()
    for result in data['Results']:
        if result['Class'] == 'lang-pkgs':
            result['Packages'] = [{'Name': 'lodash', 'Version': '4.18.1', 'FilePath': 'app/node_modules/lodash/package.json'},
                                  {'Name': 'npm', 'Version': '11.0.0', 'FilePath': 'usr/local/lib/node_modules/npm/package.json'},
                                  {'Name': 7}]
    bin_dir = sandbox(data=data)
    path = archive_file(tmp_path)
    result = image_scan.run_archive_scan(path)
    args = (bin_dir / 'args-image.txt').read_text()
    assert f'--input {path}' in args and '--list-all-pkgs' in args and '--skip-db-update' in args
    assert '--image-src' not in args and '--platform' not in args
    assert result.archive == str(path)
    assert result.report.summary['packages'] == [
        {'name': 'lodash', 'version': '4.18.1', 'path': 'app/node_modules/lodash/package.json', 'origin': 'app'},
        {'name': 'npm', 'version': '11.0.0', 'path': 'usr/local/lib/node_modules/npm/package.json', 'origin': 'base-tooling'}]


def test_registry_scan_collects_packages_to_tell_clean_from_unseen(sandbox):
    bin_dir = sandbox()
    result = run_image_scan(LOCAL)
    assert 'packages' in result.report.summary
    assert '--list-all-pkgs' in (bin_dir / 'args-image.txt').read_text()


@pytest.mark.parametrize('make', [
    lambda tmp: tmp / 'missing.tar',
    lambda tmp: Path('relative.tar'),
    lambda tmp: archive_file(tmp, 0),
    lambda tmp: tmp,
    lambda tmp: 42,
])
def test_archive_scan_rejects_bad_archive(sandbox, tmp_path, make):
    with pytest.raises(ImageScanError):
        image_scan.run_archive_scan(make(tmp_path))


def test_archive_scan_rejects_wrong_suffix(sandbox, tmp_path):
    path = tmp_path / 'image.zip'
    path.write_bytes(b'x')
    with pytest.raises(ImageScanError):
        image_scan.run_archive_scan(path)


def test_archive_scan_fails_when_trivy_warns(sandbox, tmp_path):
    sandbox(mode='warn')
    with pytest.raises(ImageScanError, match='неполной'):
        image_scan.run_archive_scan(archive_file(tmp_path))


def test_archive_scan_fails_on_stale_database(sandbox, tmp_path):
    sandbox(age_hours=72)
    with pytest.raises(ImageScanError, match='устарела'):
        image_scan.run_archive_scan(archive_file(tmp_path))


def test_database_slightly_older_than_a_day_is_still_accepted(sandbox, tmp_path):
    # Реальный случай: база собрана 24 ч 2 мин назад, новая сборка ещё не опубликована.
    sandbox(age_hours=24.04)
    assert image_scan.run_archive_scan(archive_file(tmp_path)).db_updated_at


def test_database_age_limit_is_configurable(sandbox, tmp_path, monkeypatch):
    sandbox(age_hours=30)
    monkeypatch.setenv('IMAGE_DB_MAX_AGE_HOURS', '24')
    with pytest.raises(ImageScanError, match='устарела'):
        image_scan.run_archive_scan(archive_file(tmp_path))
    monkeypatch.setenv('IMAGE_DB_MAX_AGE_HOURS', '36')
    assert image_scan.run_archive_scan(archive_file(tmp_path))


@pytest.mark.parametrize('value', ['0', '169', 'abc', '-5', ''])
def test_invalid_database_age_limit_is_an_error(sandbox, tmp_path, monkeypatch, value):
    monkeypatch.setenv('IMAGE_DB_MAX_AGE_HOURS', value)
    with pytest.raises(ImageScanError, match='IMAGE_DB_MAX_AGE_HOURS'):
        image_scan.run_archive_scan(archive_file(tmp_path))
