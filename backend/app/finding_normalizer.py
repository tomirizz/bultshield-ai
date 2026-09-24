import hashlib
import json
from uuid import UUID

from .models import (
    Category,
    Finding,
    FindingStatus,
    Scanner,
    Severity,
)


def normalize_gitleaks(
    results: list[dict],
    *,
    project_id: UUID,
    repository_id: UUID,
    scan_id: UUID,
    commit_sha: str,
) -> list[Finding]:
    findings = []
    seen = set()

    for result in results:
        rule_id = result["RuleID"]
        filename = result["File"]

        start_line = result["StartLine"]
        end_line = result["EndLine"]
        start_column = result["StartColumn"]
        end_column = result["EndColumn"]

        # Некоторые правила находят файл целиком, без номера строки.
        line_start = start_line if start_line > 0 else None
        line_end = (end_line or start_line) if line_start else None

        if line_end is not None and line_end < line_start:
            raise ValueError("Некорректный диапазон строк Gitleaks.")

        # Отпечаток описывает расположение находки.
        # Значение секрета в него не входит.
        identity = {
            "repository_id": str(repository_id),
            "scanner": Scanner.GITLEAKS.value,
            "rule_id": rule_id,
            "file": filename,
            "line_start": line_start,
            "line_end": line_end,
            "column_start": start_column,
            "column_end": end_column,
        }

        fingerprint = hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

        # Одинаковая находка сохраняется один раз за сканирование.
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        findings.append(
            Finding(
                project_id=project_id,
                scan_id=scan_id,
                scanner=Scanner.GITLEAKS,
                category=Category.SECRET,
                title=f"Возможный секрет: {rule_id}"[:300],
                description=result["Description"],
                severity=Severity.HIGH,
                original_severity=None,
                file=filename,
                line_start=line_start,
                line_end=line_end,
                rule_id=rule_id,
                cwe=None,
                cve=None,
                evidence="[REDACTED]",
                status=FindingStatus.OPEN,
                fingerprint=fingerprint,
                extra={
                    "repository_id": str(repository_id),
                    "commit_sha": commit_sha,
                    "scanner_version": "8.30.1",
                    "scan_scope": "branch_snapshot",
                    "column_start": start_column,
                    "column_end": end_column,
                    "secret_redacted": True,
                    "severity_source": "bultshield_mvp_policy",
                    "credential_validity": "not_checked",
                },
            )
        )

    return findings


def normalize_semgrep(results, *, project_id, repository_id, scan_id, commit_sha):
    from .scanner_catalog import RULES, RULES_SHA256, SEMGREP_VERSION

    findings = []
    seen = set()
    for result in results:
        rule = RULES[result['rule_id']]
        identity = {
            'repository_id': str(repository_id), 'scanner': Scanner.SEMGREP.value,
            'rule_id': result['rule_id'], 'file': result['file'],
            'line_start': result['start_line'], 'line_end': result['end_line'],
            'column_start': result['start_col'], 'column_end': result['end_col'],
        }
        fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(Finding(
            project_id=project_id, scan_id=scan_id, scanner=Scanner.SEMGREP,
            category=Category.CODE, title=rule['metadata']['title'], description=rule['message'],
            severity={'ERROR': Severity.HIGH, 'WARNING': Severity.MEDIUM, 'INFO': Severity.INFO}[rule['severity']],
            original_severity=rule['severity'], file=result['file'],
            line_start=result['start_line'], line_end=result['end_line'], rule_id=result['rule_id'],
            cwe=rule['metadata']['cwe'], cve=None, evidence='[REDACTED]',
            status=FindingStatus.OPEN, fingerprint=fingerprint,
            extra={
                'repository_id': str(repository_id), 'commit_sha': commit_sha,
                'scanner_version': SEMGREP_VERSION, 'rules_sha256': RULES_SHA256,
                'scan_scope': 'branch_snapshot', 'column_start': result['start_col'], 'column_end': result['end_col'],
                'source_redacted': True, 'severity_source': 'bultshield_rule_policy',
                'review_required': True,
            },
        ))
    return findings
