"""Выбор версии обновления моделью: набор версий задаёт код, ответ проверяется, версию проверяет песочница, при отказе действуют правила."""
import json
from types import SimpleNamespace

import pytest
from app import fix_runs
from app.dependency_fix import MAX_CANDIDATES, candidate_versions, covers, plan_update
from app.fix_agent import FIX_PASSED, FIX_PROPOSED, run_fix_agent
from app.github_pr import FixSet, build_pr_body
from app.llm import FakeProvider
from app.llm_explain import InvalidResponse
from app.llm_plan import PROMPT_VERSION, choose_version, make_planner, parse_plan, plan_request
from app.models import Finding, LLMCall
from app.sandbox import BREAKS_APP, FIX_VERIFIED, INCONCLUSIVE, STILL_DETECTED
from sqlalchemy import select
from test_fix_agent import Verifier, app_finding
from test_fix_runs import allow_local_registry as allow_local_registry
from test_fix_runs import check as check
from test_fix_runs import report_of
from test_gitleaks import worker_db as worker_db  # noqa: F401
from test_llm import SECRET, Counting, cfg

VERSIONS = ['4.17.15', '4.17.19', '4.17.21', '4.17.23', '4.18.0', '4.18.1', '4.18.2', '5.0.0', '5.1.0', '5.2.0-beta.1']
PAIRS = [('CVE-2021-23337', '4.17.21'), ('CVE-2020-8203', '4.17.19'), ('NSWG-ECO-516', '>=4.17.19')]
CANDIDATES = [{'version': '4.17.21', 'major_change': False}, {'version': '4.18.2', 'major_change': False},
              {'version': '5.0.0', 'major_change': True}]
FINDINGS = [{'rule_id': 'CVE-2021-23337', 'severity': 'HIGH', 'fixed_version': '4.17.21'},
            {'rule_id': 'CVE-2020-8203', 'severity': 'HIGH', 'fixed_version': '4.17.19'}]
REPLY = {'target': '4.17.21', 'reason': 'Версия 4.17.21 закрывает находки и остаётся в мажорной ветке установленной версии.',
         'risk': 'Совместимость проверит песочница, поведение пакета могло слегка измениться.', 'needs_review': False}


# ---- набор версий: его определяет код ----

def test_covers_follows_scanner_fix_data():
    assert covers((4, 17, 21), '4.17.21') and covers((4, 18, 2), '4.17.21') and not covers((4, 17, 20), '4.17.21')
    assert covers((5, 0, 0), '4.17.21')                      # более новая мажорная ветка: исправление ожидается в ней
    assert covers((4, 17, 25), '4.17.21, 5.1.0') and not covers((5, 0, 9), '4.17.21, 5.1.0') and covers((5, 1, 0), '4.17.21, 5.1.0')
    assert covers((4, 17, 19), '>=4.17.19') and not covers((4, 17, 18), '>=4.17.19')
    assert not covers((9, 9, 9), '') and not covers((9, 9, 9), 'unknown, 1.2.3')   # формат не поддержан: версию не предлагаем


def test_candidates_are_stable_new_not_deprecated_and_fix_every_finding():
    found = candidate_versions('4.17.15', PAIRS, VERSIONS, ['4.18.1'], default='4.17.21')
    assert [c['version'] for c in found] == ['4.17.21', '4.18.2', '5.0.0', '5.1.0']
    assert [c['major_change'] for c in found] == [False, False, True, True]
    versions = [c['version'] for c in found]
    assert '4.17.15' not in versions and '4.18.1' not in versions and not any('beta' in v for v in versions)


def test_default_of_the_rules_is_always_a_candidate():
    plan = plan_update('lodash', '4.17.15', PAIRS, VERSIONS, ['4.18.1'])
    assert plan.target in [c['version'] for c in candidate_versions('4.17.15', PAIRS, VERSIONS, ['4.18.1'], default=plan.target)]
    found = candidate_versions('4.17.15', [('CVE-1', '4.99.0')], ['4.17.15', '4.17.16'], default='4.17.16')   # правила ослабили условие
    assert [c['version'] for c in found] == ['4.17.16']


def test_findings_without_a_fix_do_not_restrict_the_set():
    found = candidate_versions('1.0.0', [('CVE-1', '1.0.5'), ('CVE-2', '')], ['1.0.0', '1.0.5', '1.0.6'], default='1.0.5')
    assert [c['version'] for c in found] == ['1.0.5', '1.0.6']


def test_set_is_capped_and_unknown_inputs_give_nothing():
    many = [f'1.{i}.0' for i in range(30)] + [f'{m}.0.0' for m in range(2, 12)]
    found = candidate_versions('1.0.0', [('CVE-1', '1.1.0')], many, default='1.1.0')
    assert len(found) <= MAX_CANDIDATES and '1.1.0' in [c['version'] for c in found]
    assert candidate_versions('not-a-version', PAIRS, VERSIONS) == [] and candidate_versions('1.0.0', PAIRS, None) == []


# ---- что уходит модели и как проверяется ответ ----

def test_request_has_only_package_versions_findings_and_candidates():
    dirty = [{'rule_id': 'CVE-2021-23337', 'severity': 'HIGH', 'fixed_version': '4.17.21', 'title': SECRET, 'file': '/srv/app/index.js'}]
    text = plan_request('lodash', '4.17.15', dirty, CANDIDATES, '4.17.21')
    data = json.loads(text)
    assert data['kind'] == 'plan' and data['candidates'] == CANDIDATES and data['default'] == '4.17.21'
    assert data['findings'] == [{'id': 'CVE-2021-23337', 'severity': 'HIGH', 'fixed_in': '4.17.21'}]
    assert SECRET not in text and '/srv/app' not in text


def test_valid_answer_is_accepted():
    request = plan_request('lodash', '4.17.15', FINDINGS, CANDIDATES, '4.17.21')
    assert parse_plan(json.dumps(REPLY, ensure_ascii=False), request, CANDIDATES) == REPLY
    fenced = '```json\n' + json.dumps(REPLY, ensure_ascii=False) + '\n```'
    assert parse_plan(fenced, request, CANDIDATES)['target'] == '4.17.21'


@pytest.mark.parametrize('change,code', [
    ({'target': '4.17.20'}, 'target_not_allowed'),                       # версии нет в наборе (в том числе выдуманной)
    ({'target': '9.9.9'}, 'target_not_allowed'),
    ({'needs_review': 'yes'}, 'schema'),                                  # булево значение должно быть настоящим
    ({'extra': 'x'}, 'schema'),
    ({'reason': 'коротко'}, 'schema'),
    ({'reason': 'Подробности: https://example.org/advisory — версия 4.17.21 подходит и закрывает находки.'}, 'contains_link'),
    ({'risk': 'Ключ доступа ' + SECRET + ' попал в текст ответа модели, это очень плохо.'}, 'secret_in_response'),
    ({'reason': 'This version fixes the reported vulnerabilities in the package completely.'}, 'wrong_language'),
    ({'reason': 'Версия 4.17.21 лучше, но есть и версия 7.7.7, которую тоже стоит рассмотреть всерьёз.'}, 'invented_version'),
    ({'risk': 'Исправляет также CVE-2099-0001, которого нет в данных, и ещё всякое важное.'}, 'invented_cve'),
])
def test_bad_answers_are_rejected(change, code):
    request = plan_request('lodash', '4.17.15', FINDINGS, CANDIDATES, '4.17.21')
    with pytest.raises(InvalidResponse) as caught:
        parse_plan(json.dumps({**REPLY, **change}, ensure_ascii=False), request, CANDIDATES)
    assert caught.value.code == code


@pytest.mark.parametrize('text', ['Конечно! Вот ответ.', '[]', '{"target": 5}'])
def test_not_json_and_wrong_shapes_are_rejected(text):
    with pytest.raises(InvalidResponse):
        parse_plan(text, plan_request('lodash', '4.17.15', FINDINGS, CANDIDATES, '4.17.21'), CANDIDATES)


# ---- обращение к модели: учёт, повтор, лимиты ----

def stored(db):
    db.expire_all()
    return db.scalars(select(LLMCall).where(LLMCall.subject_key.like('plan:%')).order_by(LLMCall.created_at)).all()


def choose(db, check, provider=None, settings=None, candidates=CANDIDATES):
    return choose_version(db, check, 'lodash', '4.17.15', FINDINGS, candidates, '4.17.21',
                          provider=provider or FakeProvider(), settings=settings or cfg())


def test_choice_is_received_validated_and_stored(db, check):
    provider = Counting(FakeProvider())
    result = choose(db, check, provider=provider)
    assert result['status'] == 'COMPLETED' and result['target'] == '4.17.21' and result['reused'] is False
    (row,) = stored(db)
    assert row.status == 'COMPLETED' and row.prompt_version == PROMPT_VERSION and row.subject_key == 'plan:lodash@4.17.15'
    assert row.request['kind'] == 'plan' and row.finding_ids == [] and row.input_tokens > 0 and row.output_tokens > 0


def test_same_question_is_not_paid_for_twice(db, check):
    provider = Counting(FakeProvider())
    first = choose(db, check, provider=provider)
    second = choose(db, check, provider=provider)
    assert provider.calls == 1 and second['reused'] is True and second['target'] == first['target'] and len(stored(db)) == 1


def test_a_different_candidate_set_asks_again(db, check):
    provider = Counting(FakeProvider())
    choose(db, check, provider=provider)
    choose(db, check, provider=provider, candidates=CANDIDATES[:2])
    assert provider.calls == 2


def test_not_configured_sends_nothing_and_stores_nothing(db, check):
    result = choose_version(db, check, 'lodash', '4.17.15', FINDINGS, CANDIDATES, '4.17.21', settings=cfg(llm_provider='disabled'))
    assert result['status'] == 'NOT_CONFIGURED' and result['target'] is None and stored(db) == []


def test_unavailable_model_is_one_attempt_and_no_choice(db, check):
    provider = Counting(FakeProvider('unavailable'))
    result = choose(db, check, provider=provider)
    assert result['status'] == 'UNAVAILABLE' and result['target'] is None and provider.calls == 1
    assert [r.status for r in stored(db)] == ['UNAVAILABLE']


def test_unparsable_answer_gets_one_retry_with_the_reason(db, check):
    provider = Counting(FakeProvider('garbage'))
    result = choose(db, check, provider=provider)
    assert result['status'] == 'INVALID_RESPONSE' and provider.calls == 2           # ровно один повтор
    assert 'Предыдущий ответ отклонён' in provider.requests[1][1] and 'Предыдущий ответ отклонён' not in provider.requests[0][1]
    assert [r.status for r in stored(db)] == ['INVALID_RESPONSE', 'INVALID_RESPONSE']
    assert result['input_tokens'] > 0 and result['cost_usd'] == 0.0


def test_invented_version_is_rejected_after_one_retry(db, check):
    provider = Counting(FakeProvider('invented_version'))
    result = choose(db, check, provider=provider)
    assert result['status'] == 'INVALID_RESPONSE' and result['target'] is None and provider.calls == 2
    assert all(r.error_code == 'target_not_allowed' for r in stored(db))


@pytest.mark.parametrize('mode,code', [('english', 'wrong_language'), ('link', 'contains_link'), ('leak', 'secret_in_response')])
def test_content_failures_are_not_retried(db, check, mode, code):
    provider = Counting(FakeProvider(mode))
    result = choose(db, check, provider=provider)
    assert result['status'] == 'INVALID_RESPONSE' and provider.calls == 1 and stored(db)[0].error_code == code
    assert SECRET not in json.dumps([r.error_message for r in stored(db)])


def test_daily_limit_stops_requests(db, check):
    provider = Counting(FakeProvider())
    result = choose(db, check, provider=provider, settings=cfg(llm_daily_call_limit=0))
    assert result['status'] == 'LIMIT_EXCEEDED' and provider.calls == 0 and stored(db)[0].status == 'LIMIT_EXCEEDED'


def test_planner_stops_asking_after_the_model_is_unavailable(db, check):
    provider = Counting(FakeProvider('unavailable'))
    planner = make_planner(db, check, provider=provider, settings=cfg())
    first = planner('lodash', '4.17.15', FINDINGS, CANDIDATES, '4.17.21')
    second = planner('qs', '6.5.5', FINDINGS, CANDIDATES, '4.17.21')
    assert first['status'] == second['status'] == 'UNAVAILABLE' and provider.calls == 1


# ---- агент: выбор модели, проверка, возврат к правилам ----

PKG = [app_finding('lodash', '4.17.15', 'CVE-2021-23337', '4.17.21'), app_finding('lodash', '4.17.15', 'CVE-2020-8203', '4.17.19')]
REGISTRY = lambda package: (['4.17.15', '4.17.19', '4.17.21', '4.17.23', '4.18.2', '5.0.0'], [])  # noqa: E731


def reply(target, needs_review=False, status='COMPLETED'):
    return {'status': status, 'message': None, 'target': target, 'reason': f'Версия {target} подходит и закрывает находки.',
            'risk': 'Совместимость проверит песочница.', 'needs_review': needs_review, 'model': 'm', 'input_tokens': 10,
            'output_tokens': 5, 'cost_usd': 0.0, 'reused': False}


class Planner:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def __call__(self, package, installed, findings, candidates, default):
        self.calls.append((package, installed, [c['version'] for c in candidates], default))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


class PerVersion(Verifier):
    """Исход зависит от версии: так проверяется, что песочница может отклонить выбор модели."""

    def __init__(self, outcomes):
        super().__init__()
        self.outcomes = outcomes

    def __call__(self, project, candidate, baseline, **kwargs):
        self.outcome = self.outcomes.get(candidate.target, FIX_VERIFIED)
        return super().__call__(project, candidate, baseline, **kwargs)


def agent(planner, verify=None, **kwargs):
    verify = verify or Verifier()
    result = run_fix_agent('/p', PKG, registry=REGISTRY, verify=verify, verify_many=verify, planner=planner, **kwargs)
    return result, verify


def test_without_a_planner_nothing_changes():
    result, verify = agent(None)
    (item,) = result.packages
    assert item.target == '4.17.21' and item.llm_plan is None and [c[1].target for c in verify.calls] == ['4.17.21']


def test_model_choice_is_verified_and_used():
    planner = Planner(reply('4.18.2'))
    result, verify = agent(planner)
    (item,) = result.packages
    assert planner.calls == [('lodash', '4.17.15', ['4.17.21', '4.18.2', '5.0.0'], '4.17.21')]
    assert item.target == '4.18.2' and item.status == FIX_PASSED and not item.major_change and not item.needs_review
    assert item.llm_plan['accepted'] is True and item.llm_plan['final_target'] == '4.18.2' and item.llm_plan['default'] == '4.17.21'
    assert [c[1].target for c in verify.calls] == ['4.18.2'] and 'выбрала модель' in item.reason
    assert item.plan['target'] == '4.17.21'                                       # решение правил сохраняется рядом


@pytest.mark.parametrize('outcome', [STILL_DETECTED, BREAKS_APP, 'NEW_FINDINGS'])
def test_choice_that_fails_the_sandbox_falls_back_to_the_rules(outcome):
    planner = Planner(reply('4.18.2'))
    verify = PerVersion({'4.18.2': outcome})
    (item,) = agent(planner, verify)[0].packages
    assert [c[1].target for c in verify.calls] == ['4.18.2', '4.17.21']          # сначала версия модели, затем версия правил
    assert item.target == '4.17.21' and item.status == FIX_PASSED and 'выбрала модель' not in item.reason
    assert item.llm_plan['accepted'] is False and item.llm_plan['rejected_outcome'] == outcome and item.llm_plan['final_target'] == '4.17.21'


def test_choice_that_fails_and_rules_that_fail_too_is_manual():
    verify = PerVersion({'4.18.2': BREAKS_APP, '4.17.21': BREAKS_APP})
    (item,) = agent(Planner(reply('4.18.2')), verify)[0].packages
    assert item.status != FIX_PASSED and item.target == '4.17.21'


def test_inconclusive_check_keeps_the_proposal_unverified_and_does_not_retry():
    verify = PerVersion({'4.18.2': INCONCLUSIVE})
    (item,) = agent(Planner(reply('4.18.2')), verify)[0].packages
    assert item.status == FIX_PROPOSED and item.target == '4.18.2' and len(verify.calls) == 1 and item.llm_plan['accepted'] is None


def test_model_agreeing_with_the_rules_costs_one_check():
    (item,) = agent(Planner(reply('4.17.21')))[0].packages
    assert item.target == '4.17.21' and item.llm_plan['accepted'] is True


def test_model_can_only_raise_caution():
    (item,) = agent(Planner(reply('4.18.2', needs_review=True)))[0].packages
    assert item.status == FIX_PASSED and item.needs_review is True and 'просмотр человеком' in item.reason
    (item,) = agent(Planner(reply('4.17.21', needs_review=False)))[0].packages
    assert item.needs_review is False


def test_major_update_chosen_by_the_model_still_needs_review():
    (item,) = agent(Planner(reply('5.0.0')))[0].packages
    assert item.target == '5.0.0' and item.major_change is True and item.needs_review is True


@pytest.mark.parametrize('answer', [reply(None, status='UNAVAILABLE'), reply(None, status='INVALID_RESPONSE'),
                                    reply(None, status='LIMIT_EXCEEDED'), RuntimeError('база недоступна /srv/secret')])
def test_no_usable_choice_means_the_rules_decide(answer):
    result, verify = agent(Planner(answer))
    (item,) = result.packages
    assert item.target == '4.17.21' and item.status == FIX_PASSED and [c[1].target for c in verify.calls] == ['4.17.21']
    assert item.llm_plan['accepted'] is None and 'secret' not in json.dumps(item.llm_plan)


def test_planner_is_not_asked_when_there_is_nothing_to_choose():
    planner = Planner(reply('4.17.21'))
    one = run_fix_agent('/p', PKG, registry=lambda p: (['4.17.15', '4.17.21'], []), verify=Verifier(), planner=planner)
    assert planner.calls == [] and one.packages[0].llm_plan['status'] == 'SKIPPED' and one.packages[0].target == '4.17.21'


def test_not_configured_model_leaves_no_trace_in_the_result(db, check):
    planner = make_planner(db, check, settings=cfg(llm_provider='disabled'))
    (item,) = run_fix_agent('/p', PKG, registry=REGISTRY, verify=Verifier(), planner=planner).packages
    assert item.llm_plan is None and item.target == '4.17.21'


def test_packages_without_a_proposal_never_reach_the_model():
    planner = Planner(reply('1.0.0'))
    run_fix_agent('/p', [app_finding('request', '2.88.2', 'CVE-2023-28155', None)], registry=REGISTRY, verify=Verifier(), planner=planner)
    assert planner.calls == []


# ---- отчёт и PR ----

def test_report_shows_who_chose_each_version_and_explanations_ignore_plan_calls(db, check):
    planner = make_planner(db, check, provider=FakeProvider('prefer_latest'), settings=cfg())
    result = run_fix_agent('/p', PKG, registry=REGISTRY, verify=Verifier(), planner=planner)
    run = fix_runs.create_run(db, check, 'a' * 40)
    rows = db.scalars(select(Finding).where(Finding.scan_id == check)).all()
    fix_runs.complete_run(db, run.id, result, rows)
    report = report_of(db, check)
    (choice,) = report['fix_run']['version_choices']
    assert choice['package'] == 'lodash' and choice['model_target'] == '4.18.2' and choice['rule_target'] == '4.17.21'
    assert choice['final_target'] == '4.18.2' and choice['chosen_by'] == 'model' and choice['agreed_with_rules'] is False
    assert choice['input_tokens'] > 0 and choice['reason'] and report['assumptions'] == []
    assert report['llm']['status'] == 'NOT_RUN' and report['llm']['explained'] == 0          # выбор версии — не пояснение находок
    assert report['llm']['input_tokens'] > 0                                                  # но токены учтены


def test_pr_lists_the_models_choices_as_an_assumption_and_cleans_its_text():
    fix = FixSet(packages=[{'package': 'lodash', 'from': '4.17.15', 'to': '4.18.2', 'method': 'direct', 'resolves': ['CVE-2021-23337']}],
                 files={'package.json': '{}'}, original={'package.json': '{}'},
                 choices=[{'package': 'lodash', 'from': '4.17.15', 'to': '4.18.2', 'rule_to': '4.17.21',
                           'reason': 'см. https://evil.example/x **жирный** <script>', 'risk': 'Риск мал.'}])
    body = build_pr_body(fix)
    assert '### Выбор версий моделью (предположение)' in body and 'автоматический план предлагал 4.17.21' in body
    assert 'evil.example' not in body and '<script>' not in body and 'проверена в песочнице' in body
    assert '### Выбор версий моделью' not in build_pr_body(FixSet(fix.packages, fix.files, fix.original))


def test_fix_set_takes_choices_only_for_accepted_model_choices():
    from app.fix_agent import AgentResult
    from app.github_pr import fix_set_from_agent
    result, _ = agent(Planner(reply('4.18.2')))
    result.combined = {'packages': ['lodash'], 'outcome': 'FIX_VERIFIED', 'candidates': [{'package': 'lodash', 'method': 'direct'}]}
    result.combined_result = SimpleNamespace(files={'package.json': '{}'}, original={'package.json': '{}'})
    assert isinstance(result, AgentResult)
    (choice,) = fix_set_from_agent(result).choices
    assert choice['to'] == '4.18.2' and choice['rule_to'] == '4.17.21'
    declined, _ = agent(Planner(reply('4.18.2')), PerVersion({'4.18.2': BREAKS_APP}))
    declined.combined, declined.combined_result = result.combined, result.combined_result
    assert fix_set_from_agent(declined).choices == []
