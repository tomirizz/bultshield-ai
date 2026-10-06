import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from app import image_pipeline
from app.image_pipeline import normalize_image_findings, run_image_pipeline
from app.image_report import parse_image_report
from app.image_scan import ImageScanError, ImageScanResult
from app.models import Category, FindingStatus, Scanner, ScanStatus

FIXTURE = Path(__file__).parent / 'fixtures' / 'trivy_image_report.json'
DIGEST = 'sha256:1566a7c1278013df557f3a960691911f1b4708c7015238c44ad0e16ada5bfb4e'
OTHER = 'sha256:' + 'b' * 64
REFERENCE = 'localhost:5001/bultshield-demo-app:main'


def scan_result():
    report = parse_image_report(json.loads(FIXTURE.read_text()))
    return ImageScanResult(REFERENCE, DIGEST, 'linux/amd64', '2026-10-06T07:04:23Z', report)


def normalized(digest=DIGEST, results=None, scan_id=None):
    results = scan_result().report.findings if results is None else results
    return normalize_image_findings(results, project_id=uuid4(), repository_id=uuid4(), scan_id=scan_id or uuid4(),
                                    image=REFERENCE, digest=digest)


def test_every_finding_is_normalized_to_the_common_format():
    findings = normalized()
    assert len(findings) == 14
    assert all(f.scanner == Scanner.TRIVY and f.category == Category.DEPENDENCY for f in findings)
    assert all(f.status == FindingStatus.OPEN and f.evidence == '[REDACTED]' for f in findings)
    assert all(f.extra['image_digest'] == DIGEST and f.extra['source'] == 'image' for f in findings)
    assert len({f.fingerprint for f in findings}) == 14


def test_app_findings_have_no_manual_reason_and_others_do():
    findings = normalized()
    app = [f for f in findings if f.extra['origin'] == 'app']
    others = [f for f in findings if f.extra['origin'] != 'app']
    assert len(app) == 7 and all(f.extra['manual_reason'] is None and 'Обновление пакета' in f.description for f in app)
    assert len(others) == 7 and all(f.extra['manual_reason'] and 'недоступно' in f.description for f in others)
    assert {f.file for f in app} == {'app/node_modules/lodash/package.json'}


def test_fingerprint_depends_on_image_digest():
    first = {f.fingerprint for f in normalized(DIGEST)}
    second = {f.fingerprint for f in normalized(OTHER)}
    assert first.isdisjoint(second)


def test_same_scan_report_gives_same_fingerprints_and_duplicates_collapse():
    results = scan_result().report.findings
    scan_id = uuid4()
    once = normalized(results=results, scan_id=scan_id)
    twice = normalized(results=results * 2, scan_id=scan_id)
    assert len(twice) == len(once) == 14


def test_no_raw_scanner_text_is_stored():
    data = json.loads(FIXTURE.read_text())
    data['Results'][1]['Vulnerabilities'][0]['Title'] = 'PRIVATE_SOURCE'
    results = parse_image_report(data).findings
    stored = json.dumps([[f.title, f.description, f.evidence, f.extra] for f in normalized(results=results)])
    assert 'PRIVATE_SOURCE' not in stored


class Recorder:
    def __init__(self):
        self.progress, self.stored = [], []

    def on_progress(self, data, status, commit_sha=None, step=None, scanner_result=None):
        self.progress.append((status, step, scanner_result))

    def on_store(self, data, findings, summaries, verification=None):
        self.stored.append((findings, summaries))


def job(config=None):
    return SimpleNamespace(job_id=uuid4(), scan_id=uuid4(), project_id=uuid4(), repository_id=uuid4(),
                           config={'image': {'reference': REFERENCE}} if config is None else config)


def test_pipeline_stores_findings_and_digest(monkeypatch):
    monkeypatch.setattr(image_pipeline, 'run_image_scan', lambda reference: scan_result())
    recorder = Recorder()
    run_image_pipeline(job(), recorder.on_progress, recorder.on_store)
    (findings, summaries), = recorder.stored
    assert len(findings) == 14
    summary = summaries['trivy']
    assert summary['status'] == 'COMPLETED' and summary['digest'] == DIGEST and summary['finding_count'] == 14
    assert summary['by_origin'] == {'os': 4, 'app': 7, 'base-tooling': 3}
    assert recorder.progress[0][0] == ScanStatus.SCANNING and recorder.progress[-1][1] == 'store'


def test_scanner_failure_is_stored_as_failed_not_as_clean(monkeypatch):
    def fail(reference):
        raise ImageScanError('Trivy завершился с ошибкой (1); проверка неполная.')
    monkeypatch.setattr(image_pipeline, 'run_image_scan', fail)
    recorder = Recorder()
    run_image_pipeline(job(), recorder.on_progress, recorder.on_store)
    (findings, summaries), = recorder.stored
    assert findings == []
    assert summaries['trivy']['status'] == 'FAILED' and summaries['trivy']['error_code'] == 'SCANNER_FAILED'
    assert 'finding_count' not in summaries['trivy']


@pytest.mark.parametrize('config', [{}, {'image': {}}, {'image': {'reference': 'not a reference'}}])
def test_missing_or_invalid_reference_fails_the_scan(config):
    recorder = Recorder()
    run_image_pipeline(job(config), recorder.on_progress, recorder.on_store)
    (findings, summaries), = recorder.stored
    assert findings == [] and summaries['trivy']['status'] == 'FAILED'
