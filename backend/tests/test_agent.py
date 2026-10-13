import uuid

import pytest
from app.security_agent import Plan, execute_tool
from fastapi import HTTPException
from pydantic import ValidationError


def test_agent_cannot_invent_shell_tools():
    with pytest.raises(ValidationError):
        Plan(tool='exec_shell', finding_id='')
    with pytest.raises(ValidationError):
        Plan(tool='top_issues', finding_id='', command='curl')


def test_agent_write_requires_user_opt_in():
    result = execute_tool(None, uuid.uuid4(), {'tool': 'generate_fix', 'finding_id': ''}, False)
    assert 'action_required' in result


def test_agent_finding_from_other_project_is_rejected(db):
    with pytest.raises(HTTPException) as error:
        execute_tool(db, uuid.uuid4(), {'tool': 'get_finding', 'finding_id': str(uuid.uuid4())}, False)
    assert error.value.status_code == 404


def test_compact_finding_keeps_issue_specific_guidance():
    from types import SimpleNamespace

    from app.models import Category, Scanner, Severity
    from app.security_agent import compact_finding
    finding = SimpleNamespace(category=Category.CONFIGURATION, rule_id='DS-0002', file='Dockerfile',
                              scanner=Scanner.TRIVY, severity=Severity.HIGH, cve=None, cwe=None, line_start=3)
    assert 'USER' in compact_finding(finding)['trusted_guidance']
