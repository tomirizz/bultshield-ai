import json
from types import SimpleNamespace

import pytest
from app import sandbox
from app.image_report import ImageReport
from app.image_scan import ImageScanError
from app.sandbox import (
    BREAKS_APP,
    FIX_VERIFIED,
    INCONCLUSIVE,
    NEW_FINDINGS,
    STILL_DETECTED,
    FixCandidate,
    SandboxConfig,
    verify_fix,
)

# Поддельный docker: не запускает контейнеры, а пишет вызовы в calls.txt и имитирует нужный исход (файл mode).
FAKE_DOCKER = """#!/bin/sh
dir=$(dirname "$0")
echo "$@" >> "$dir/calls.txt"
mode=$(cat "$dir/mode")
case "$1" in
  info) [ "$mode" = nodaemon ] && { echo "Cannot connect to the Docker daemon" >&2; exit 1; }; exit 0 ;;
  inspect) [ "$mode" = crash ] && echo false || echo true; exit 0 ;;
  rm|rmi) exit 0 ;;
  logs) echo "Error: Cannot find module 'lodash-broken'"; exit 0 ;;
  exec) [ "$mode" = health_fail ] && exit 1; exit 0 ;;
  build)
    [ "$mode" = build_fail ] && { echo "ERROR: process npm ci exited with code 1" >&2; exit 1; }
    [ "$mode" = build_net ] && { echo "npm error code EAI_AGAIN" >&2; exit 1; }
    echo sha256:abc; exit 0 ;;
  save)
    out=""; prev=""
    for a in "$@"; do [ "$prev" = "-o" ] && out="$a"; prev="$a"; done
    [ "$mode" = save_fail ] && exit 1
    echo tar > "$out"; exit 0 ;;
  run)
    case " $* " in
      *" -d "*) echo containerid; exit 0 ;;
    esac
    work=""; prev=""
    for a in "$@"; do [ "$prev" = "-v" ] && work="${a%%:*}"; prev="$a"; last="$a"; done
    case " $* " in
      *" npm install "*)
        [ "$mode" = install_eresolve ] && { echo "npm error code ERESOLVE" >&2; exit 1; }
        [ "$mode" = install_net ] && { echo "npm error code ETIMEDOUT" >&2; exit 1; }
        [ "$mode" = install_slow ] && sleep 30
        [ "$mode" = install_noop ] && exit 0
        case "$last" in
          *@*) ver="${last##*@}" ;;
          *) ver="" ;;
        esac
        [ "$mode" = override_ignored ] && [ -z "$ver" ] && exit 0
        if [ -n "$ver" ]; then
          for f in package.json package-lock.json; do
            sed "s/4\\.17\\.15/$ver/" "$work/$f" > "$work/$f.new" && mv "$work/$f.new" "$work/$f"
          done
        fi
        if grep -q '"overrides"' "$work/package.json"; then
          # имитируем пересборку lock-файла после добавления overrides
          sed "s/8\\.3\\.2/11.1.1/" "$work/package-lock.json" > "$work/lock.new" && mv "$work/lock.new" "$work/package-lock.json"
        elif [ -z "$ver" ]; then
          echo "overrides не добавлены" >&2; exit 1
        fi
        mkdir -p "$work/node_modules"; echo x > "$work/node_modules/marker"
        exit 0 ;;
      *" npm test"*)
        [ "$mode" = test_fail ] && { echo "not ok 1 - summarize"; exit 1; }
        exit 0 ;;
    esac
    exit 0 ;;
esac
exit 0
"""

MANIFEST = {'name': 'demo', 'version': '1.0.0', 'scripts': {'test': 'node --test'}, 'dependencies': {'lodash': '4.17.15'}}
LOCK = '{"packages": {"node_modules/lodash": {"version": "4.17.15"}}}\n'


def finding(rule, package='lodash', origin='app'):
    return {'rule_id': rule, 'package': package, 'origin': origin, 'severity': 'HIGH'}


BASELINE = [finding('CVE-2020-8203'), finding('CVE-2021-23337'), finding('CVE-2025-0001', 'debian-pkg', 'os')]


def good_packages(version='4.18.1'):
    return [{'name': 'lodash', 'version': version, 'path': 'app/node_modules/lodash/package.json', 'origin': 'app'}]


def rescan_of(findings, packages='default'):
    packages = good_packages() if packages == 'default' else packages
    summary = {} if packages is None else {'packages': packages}
    return lambda archive: SimpleNamespace(report=ImageReport(findings, summary), db_updated_at='2026-10-08T00:00:00Z')


@pytest.fixture
def lab(tmp_path, monkeypatch):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    fake = bin_dir / 'docker'
    fake.write_text(FAKE_DOCKER)
    fake.chmod(0o755)
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'package.json').write_text(json.dumps(MANIFEST, indent=2) + '\n')
    (project / 'package-lock.json').write_text(LOCK)
    (project / 'Dockerfile').write_text('FROM node:24-slim\n')
    (project / '.git').mkdir()
    (project / '.git' / 'config').write_text('secret')
    monkeypatch.setattr(sandbox.shutil, 'which', lambda name: str(fake))
    monkeypatch.setenv('PATH', '/usr/bin:/bin')
    config = SandboxConfig(work_root=tmp_path / 'sbx', health_timeout=1)

    def run(mode='ok', scan=None, candidate=None, baseline=None, cfg=None):
        (bin_dir / 'mode').write_text(mode)
        return verify_fix(project, candidate or FixCandidate('lodash', '4.18.1'), BASELINE if baseline is None else baseline,
                          config=cfg or config, scan=scan or rescan_of([finding('CVE-2025-0001', 'debian-pkg', 'os')]))

    run.bin_dir = bin_dir
    run.config = config
    run.calls = lambda: (bin_dir / 'calls.txt').read_text().splitlines() if (bin_dir / 'calls.txt').exists() else []
    run.project = project
    run.work_root = tmp_path / 'sbx'
    return run


def names(result):
    return [step['name'] for step in result.steps]


def test_verified_fix_runs_every_step_in_isolation(lab):
    result = lab()
    assert result.outcome == FIX_VERIFIED, result.reason
    assert names(result) == ['docker', 'install', 'tests', 'build', 'start', 'health', 'save', 'rescan']
    assert {s['status'] for s in result.steps} == {'passed'}
    assert [f['rule_id'] for f in result.resolved] == ['CVE-2020-8203', 'CVE-2021-23337']
    assert result.remaining == [] and result.introduced == []
    assert '-    "lodash": "4.17.15"' in result.diff and '+    "lodash": "4.18.1"' in result.diff
    assert 'a/package-lock.json' in result.diff
    assert 'не опубликован' in result.reason
    install, tests = (next(c for c in lab.calls() if marker in c) for marker in ('npm install', 'npm test'))
    assert '--ignore-scripts' in install and '--network none' not in install and 'lodash@4.18.1' in install
    assert '--network none' in tests and '--cap-drop ALL' in tests and 'no-new-privileges' in tests
    app = next(c for c in lab.calls() if c.startswith('run -d'))
    assert '--network none' in app and '--read-only' in app and '--cap-drop ALL' in app and '--memory 256m' in app


def test_original_project_is_untouched_and_workspace_is_cleaned(lab):
    before = (lab.project / 'package.json').read_text()
    lab()
    assert (lab.project / 'package.json').read_text() == before
    assert not (lab.project / 'node_modules').exists()
    assert list(lab.work_root.iterdir()) == []
    calls = lab.calls()
    assert sum(c.startswith('rm -f') for c in calls) == 3 and any(c.startswith('rmi -f') for c in calls)


def test_git_directory_is_not_copied_into_build_context(lab, monkeypatch):
    seen = {}
    original = sandbox._pipeline

    def spy(docker, work, *args, **kwargs):
        seen['git'] = (work / '.git').exists()
        seen['ignore'] = (work / '.dockerignore').read_text()
        return original(docker, work, *args, **kwargs)

    monkeypatch.setattr(sandbox, '_pipeline', spy)
    lab()
    assert seen == {'git': False, 'ignore': 'node_modules\n.git\n'}


def test_still_vulnerable_is_detected_by_finding_not_by_count(lab):
    # Одна находка закрыта, другая осталась: общее число изменилось, но исправление неполное.
    result = lab(scan=rescan_of([finding('CVE-2021-23337')]))
    assert result.outcome == STILL_DETECTED
    assert [f['rule_id'] for f in result.remaining] == ['CVE-2021-23337']
    assert [f['rule_id'] for f in result.resolved] == ['CVE-2020-8203']
    assert 'остались' in result.reason


def test_new_findings_are_not_reported_as_verified(lab):
    result = lab(scan=rescan_of([finding('CVE-2099-0001', 'other-lib')]))
    assert result.outcome == NEW_FINDINGS
    assert result.introduced == [{'rule_id': 'CVE-2099-0001', 'package': 'other-lib'}]


def test_os_findings_do_not_affect_the_verdict(lab):
    assert lab(scan=rescan_of([finding('CVE-2030-1', 'libc', 'os')])).outcome == FIX_VERIFIED


def test_resolves_limits_what_counts_as_target(lab):
    candidate = FixCandidate('lodash', '4.18.1', resolves=('CVE-2020-8203',))
    result = lab(candidate=candidate, scan=rescan_of([finding('CVE-2021-23337')]))
    assert result.outcome == FIX_VERIFIED
    assert [f['rule_id'] for f in result.resolved] == ['CVE-2020-8203']


@pytest.mark.parametrize('packages', [None, [], good_packages('4.17.15'),
                                      [{'name': 'lodash', 'version': '4.18.1', 'path': 'x/lodash', 'origin': 'other'}]])
def test_empty_scan_without_proof_the_app_was_seen_is_inconclusive(lab, packages):
    result = lab(scan=rescan_of([], packages))
    assert result.outcome == INCONCLUSIVE
    assert result.failed_step == 'rescan' and 'не принят за «чисто»' in result.reason


def test_scanner_failure_is_inconclusive(lab):
    def broken(archive):
        raise ImageScanError('Trivy превысил лимит 600 секунд.')

    result = lab(scan=broken)
    assert result.outcome == INCONCLUSIVE and result.failed_step == 'rescan'
    assert 'не означает, что уязвимостей нет' in result.reason
    assert result.steps[-1]['status'] == 'failed' and result.diff


def test_missing_docker_is_inconclusive(lab, monkeypatch):
    monkeypatch.setattr(sandbox.shutil, 'which', lambda name: None)
    result = lab()
    assert result.outcome == INCONCLUSIVE and 'Docker не установлен' in result.reason


def test_stopped_docker_daemon_is_inconclusive(lab):
    result = lab('nodaemon')
    assert result.outcome == INCONCLUSIVE and result.failed_step == 'docker'
    assert names(result) == ['docker']


def test_dependency_conflict_breaks_the_app(lab):
    result = lab('install_eresolve')
    assert result.outcome == BREAKS_APP and result.failed_step == 'install'
    assert 'ERESOLVE' in result.steps[-1]['log_tail']


def test_network_trouble_during_install_is_inconclusive_not_breaking(lab):
    result = lab('install_net')
    assert result.outcome == INCONCLUSIVE and result.failed_step == 'install'


def test_update_that_changes_nothing_is_inconclusive(lab):
    result = lab('install_noop')
    assert result.outcome == INCONCLUSIVE and 'не применилось' in result.reason


def test_install_timeout_is_inconclusive(lab, tmp_path):
    cfg = SandboxConfig(work_root=tmp_path / 'sbx', install_timeout=1)
    result = lab('install_slow', cfg=cfg)
    assert result.outcome == INCONCLUSIVE and result.steps[-1]['status'] == 'timeout'


def test_failing_tests_break_the_app_and_stop_the_pipeline(lab):
    result = lab('test_fail')
    assert result.outcome == BREAKS_APP and result.failed_step == 'tests'
    assert 'not ok 1' in result.steps[-1]['log_tail'] and result.diff
    assert not any(c.startswith('build') for c in lab.calls())


def test_build_failure_breaks_but_network_failure_does_not(lab):
    broken = lab('build_fail')
    assert broken.outcome == BREAKS_APP and broken.failed_step == 'build'
    assert lab('build_net').outcome == INCONCLUSIVE


def test_unhealthy_app_breaks_with_container_log(lab):
    result = lab('health_fail')
    assert result.outcome == BREAKS_APP and result.failed_step == 'health'
    assert "Cannot find module 'lodash-broken'" in result.steps[-1]['log_tail']


def test_crashed_container_breaks_quickly(lab):
    result = lab('crash')
    assert result.outcome == BREAKS_APP and result.failed_step == 'health'


def test_save_failure_is_inconclusive(lab):
    result = lab('save_fail')
    assert result.outcome == INCONCLUSIVE and result.failed_step == 'save'


@pytest.mark.parametrize('prepare,text', [
    (lambda p: (p / 'package-lock.json').unlink(), 'lock'),
    (lambda p: (p / 'package.json').write_text(
        json.dumps({**MANIFEST, 'scripts': {'test': 'echo "Error: no test specified" && exit 1'}})), 'test'),
    (lambda p: (p / 'package.json').write_text(json.dumps({**MANIFEST, 'scripts': {}})), 'test'),
    (lambda p: (p / 'package.json').write_text('{broken'), 'package.json'),
])
def test_unsuitable_project_is_inconclusive_before_docker_is_touched(lab, prepare, text):
    prepare(lab.project)
    result = lab()
    assert result.outcome == INCONCLUSIVE and text in result.reason
    assert lab.calls() == []


def test_nothing_to_verify_without_matching_baseline_findings(lab):
    result = lab(baseline=[finding('CVE-2025-0001', 'debian-pkg', 'os')])
    assert result.outcome == INCONCLUSIVE and 'проверять нечего' in result.reason
    assert lab.calls() == []


def test_missing_project_directory(lab):
    import shutil
    shutil.rmtree(lab.project)
    assert lab().outcome == INCONCLUSIVE


@pytest.mark.parametrize('package,target', [
    ('--version', '4.18.1'), ('lodash;rm -rf /', '4.18.1'), ('lodash', '4.18'), ('lodash', '^4.18.1'), ('lodash', '4.18.1; ls'),
    ('', '1.0.0'), ('Lodash', '1.0.0'), ('a' * 215, '1.0.0'),
])
def test_candidate_rejects_unsafe_values(package, target):
    with pytest.raises(ValueError):
        FixCandidate(package, target)


def test_scoped_package_is_accepted():
    assert FixCandidate('@types/node', '22.1.0').package == '@types/node'


@pytest.mark.parametrize('kwargs', [{'node_image': '-v /:/host'}, {'node_image': 'node:24 --privileged'}, {'platform': 'linux/amd64;x'},
                                    {'port': 0}, {'port': 70000}, {'health_path': 'health'}, {'health_path': '/a b'}])
def test_config_rejects_unsafe_values(kwargs):
    with pytest.raises(ValueError):
        SandboxConfig(**kwargs)


def test_result_is_json_serializable(lab):
    json.dumps(lab().as_dict())


# --- транзитивные зависимости: обновление через overrides ---

TRANSITIVE_MANIFEST = {'name': 'demo', 'version': '1.0.0', 'scripts': {'test': 'node --test'},
                       'dependencies': {'request': '2.88.2'}}
TRANSITIVE_LOCK = ('{"lockfileVersion": 3, "packages": {"node_modules/request": {"version": "2.88.2"},'
                   ' "node_modules/uuid": {"version": "8.3.2"}}}\n')
UUID_BASELINE = [finding('CVE-2026-41907', 'uuid')]
UUID_CANDIDATE = FixCandidate('uuid', '11.1.1')


@pytest.fixture
def transitive(lab):
    (lab.project / 'package.json').write_text(json.dumps(TRANSITIVE_MANIFEST, indent=4) + '\n')
    (lab.project / 'package-lock.json').write_text(TRANSITIVE_LOCK)

    def run(mode='ok', packages='default', findings=()):
        wanted = [{'name': 'uuid', 'version': '11.1.1', 'path': 'app/node_modules/uuid/package.json', 'origin': 'app'}]
        return lab(mode, candidate=UUID_CANDIDATE, baseline=UUID_BASELINE,
                   scan=rescan_of(list(findings), wanted if packages == 'default' else packages))

    run.lab = lab
    return run


def test_transitive_dependency_is_fixed_with_overrides(transitive):
    result = transitive()
    assert result.outcome == FIX_VERIFIED, result.reason
    assert result.method == 'override'
    # индекс отступа исходного файла (4 пробела) сохраняется, пакет не становится прямой зависимостью
    assert '+    "overrides": {' in result.diff and '+        "uuid": "11.1.1"' in result.diff
    install = next(c for c in transitive.lab.calls() if 'npm install' in c)
    assert install.endswith('npm install --ignore-scripts --no-audit --no-fund')
    assert '--save-exact' not in install and 'uuid@' not in install


def test_direct_dependency_reports_direct_method(lab):
    assert lab().method == 'direct'


def test_override_that_breaks_tests_is_reported_as_breaking(transitive):
    result = transitive('test_fail')
    assert result.outcome == BREAKS_APP and result.failed_step == 'tests' and result.method == 'override'
    assert '"overrides"' in result.diff


def test_override_that_npm_ignored_is_not_verified(transitive):
    result = transitive('override_ignored')
    assert result.outcome == INCONCLUSIVE and result.failed_step == 'install'
    assert 'package-lock.json не изменился' in result.reason
    assert not any(c.startswith('build') for c in transitive.lab.calls())


def test_package_missing_from_lock_is_inconclusive(lab):
    (lab.project / 'package.json').write_text(json.dumps(TRANSITIVE_MANIFEST) + '\n')
    (lab.project / 'package-lock.json').write_text('{"lockfileVersion": 3, "packages": {"node_modules/request": {}}}')
    result = lab(candidate=UUID_CANDIDATE, baseline=UUID_BASELINE)
    assert result.outcome == INCONCLUSIVE and 'нет ни в package.json' in result.reason
    assert lab.calls() == []


def test_old_lock_format_is_inconclusive(lab):
    (lab.project / 'package.json').write_text(json.dumps(TRANSITIVE_MANIFEST) + '\n')
    (lab.project / 'package-lock.json').write_text('{"lockfileVersion": 1, "dependencies": {"uuid": {}}}')
    result = lab(candidate=UUID_CANDIDATE, baseline=UUID_BASELINE)
    assert result.outcome == INCONCLUSIVE and 'старого формата' in result.reason


def test_nested_override_is_left_to_a_human(transitive):
    manifest = {**TRANSITIVE_MANIFEST, 'overrides': {'uuid': {'.': '8.0.0'}}}
    (transitive.lab.project / 'package.json').write_text(json.dumps(manifest) + '\n')
    result = transitive()
    assert result.outcome == INCONCLUSIVE and 'overrides' in result.reason and result.failed_step == 'install'


def test_existing_overrides_are_kept(transitive):
    manifest = {**TRANSITIVE_MANIFEST, 'overrides': {'minimist': '1.2.8'}}
    (transitive.lab.project / 'package.json').write_text(json.dumps(manifest, indent=2) + '\n')
    result = transitive()
    assert result.outcome == FIX_VERIFIED
    # прежний override сохранён (к нему лишь добавилась запятая), новый добавлен рядом
    assert '+    "minimist": "1.2.8",' in result.diff and '+    "uuid": "11.1.1"' in result.diff


# --- несколько обновлений вместе (один будущий PR) ---

MIXED_MANIFEST = {'name': 'demo', 'version': '1.0.0', 'scripts': {'test': 'node --test'},
                  'dependencies': {'lodash': '4.17.15', 'request': '2.88.2'}}
MIXED_LOCK = ('{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.15"},'
              ' "node_modules/request": {"version": "2.88.2"}, "node_modules/uuid": {"version": "8.3.2"}}}\n')
MIXED_BASELINE = [finding('CVE-2020-8203'), finding('CVE-2026-41907', 'uuid')]
BOTH = [FixCandidate('lodash', '4.18.1'), FixCandidate('uuid', '11.1.1')]
BOTH_PACKAGES = good_packages() + [{'name': 'uuid', 'version': '11.1.1', 'path': 'app/node_modules/uuid/package.json',
                                    'origin': 'app'}]


@pytest.fixture
def mixed(lab):
    (lab.project / 'package.json').write_text(json.dumps(MIXED_MANIFEST, indent=2) + '\n')
    (lab.project / 'package-lock.json').write_text(MIXED_LOCK)

    def run(mode='ok', packages=None, findings=(), candidates=None, baseline=None):
        batch = candidates or BOTH
        (lab.bin_dir / 'mode').write_text(mode)
        seen = BOTH_PACKAGES if packages is None else packages
        return sandbox.verify_fixes(lab.project, batch, MIXED_BASELINE if baseline is None else baseline,
                                    config=lab.config, scan=rescan_of(list(findings), seen))

    run.lab = lab
    return run


def test_several_fixes_are_verified_together_in_one_pass(mixed):
    result = mixed()
    assert result.outcome == FIX_VERIFIED, result.reason
    assert result.method == 'mixed'
    assert result.candidates == [{'package': 'lodash', 'target': '4.18.1', 'method': 'direct'},
                                 {'package': 'uuid', 'target': '11.1.1', 'method': 'override'}]
    assert sorted(f['package'] for f in result.resolved) == ['lodash', 'uuid']
    calls = mixed.lab.calls()
    installs = [c for c in calls if 'npm install' in c]
    assert len(installs) == 1 and 'lodash@4.18.1' in installs[0] and '--save-exact' in installs[0]
    assert 'uuid@' not in installs[0]
    assert sum(c.startswith('build') for c in calls) == 1 and sum(c.startswith('save') for c in calls) == 1
    assert '+    "lodash": "4.18.1"' in result.diff or '"lodash": "4.18.1"' in result.diff
    assert '"overrides"' in result.diff


def test_files_for_a_pull_request_are_returned_only_when_verified(mixed, lab):
    result = mixed()
    assert sorted(result.files) == ['package-lock.json', 'package.json']
    assert json.loads(result.files['package.json'])['dependencies']['lodash'] == '4.18.1'
    assert json.loads(result.files['package.json'])['overrides'] == {'uuid': '11.1.1'}
    assert result.as_dict()['files'] == ['package-lock.json', 'package.json']
    broken = mixed('test_fail')
    assert broken.outcome == BREAKS_APP and broken.files == {}


def test_one_unseen_package_makes_the_whole_batch_inconclusive(mixed):
    result = mixed(packages=good_packages())
    assert result.outcome == INCONCLUSIVE and 'uuid 11.1.1' in result.reason and 'lodash 4.18.1' not in result.reason


def test_one_remaining_finding_fails_the_batch(mixed):
    result = mixed(findings=[finding('CVE-2026-41907', 'uuid')])
    assert result.outcome == STILL_DETECTED
    assert [f['package'] for f in result.remaining] == ['uuid'] and [f['package'] for f in result.resolved] == ['lodash']


def test_candidate_without_findings_stops_before_docker(mixed):
    result = mixed(baseline=[finding('CVE-2020-8203')])
    assert result.outcome == INCONCLUSIVE and 'uuid' in result.reason and mixed.lab.calls() == []


@pytest.mark.parametrize('batch', [[], [FixCandidate('lodash', '4.18.1'), FixCandidate('lodash', '4.18.0')],
                                   [FixCandidate(f'pkg{n}', '1.0.0') for n in range(11)]])
def test_batch_size_and_duplicates_are_validated(lab, batch):
    with pytest.raises(ValueError):
        sandbox.verify_fixes(lab.project, batch, BASELINE)
