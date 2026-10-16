"""Requirements guards: complete scanner constraints, no unnecessary model call, source identity."""
import pytest
from app import fix_runs
from app.dependency_fix import candidate_versions, plan_update
from app.fix_agent import run_fix_agent
from app.llm import FakeProvider
from app.llm_plan import make_planner
from app.models import Scan
from test_fix_agent import Verifier, app_finding
from test_fix_runs import allow_local_registry as allow_local_registry
from test_fix_runs import check as check
from test_fix_runs import git
from test_gitleaks import worker_db as worker_db  # noqa: F401
from test_llm import Counting, cfg


@pytest.mark.parametrize('default', ['1.0.1', '1.0.3', '1.0.9', '1.0.0'])
def test_default_cannot_bypass_scanner_registry_or_deprecation(default):
    candidates = candidate_versions('1.0.0', [('CVE-1', '1.0.2')], ['1.0.0', '1.0.1', '1.0.2', '1.0.3'],
                                    deprecated=['1.0.3'], default=default)
    assert [c['version'] for c in candidates] == ['1.0.2']


def test_plan_checks_all_fix_branches_when_constraints_cross_a_major():
    plan = plan_update('pkg', '1.0.0', [('CVE-A', '1.5.0, 2.5.0'), ('CVE-B', '2.0.0')],
                       ['1.0.0', '1.5.0', '2.0.0', '2.5.0'])
    assert plan.target == '2.5.0'


def test_obvious_patch_uses_no_model_even_with_multiple_candidates(db, check):
    model = Counting(FakeProvider())
    planner = make_planner(db, check, provider=model, settings=cfg())
    result = run_fix_agent('/p', [app_finding('minimist', '1.2.0', 'CVE-2021-44906', '1.2.6')],
                           registry=lambda package: (['1.2.0', '1.2.6', '1.2.8'], []), verify=Verifier(), planner=planner)
    assert model.calls == 0
    assert result.packages[0].target == '1.2.6'
    assert result.packages[0].llm_plan['status'] == 'SKIPPED'


def test_source_commit_must_match_known_image_revision(db, check):
    scan = db.get(Scan, check)
    scan.commit_sha = 'a' * 40
    db.commit()
    with pytest.raises(fix_runs.FixRunError, match='коммит'):
        fix_runs.create_run(db, check, 'b' * 40)


def test_explicit_commit_cannot_override_the_real_checkout(db, check, tmp_path):
    git(tmp_path, 'init', '-q')
    (tmp_path / 'file.txt').write_text('source')
    git(tmp_path, 'add', '.')
    git(tmp_path, 'commit', '-q', '-m', 'source')
    with pytest.raises(fix_runs.FixRunError, match='коммит'):
        fix_runs.execute_run(db, check, tmp_path, commit_sha='b' * 40)
