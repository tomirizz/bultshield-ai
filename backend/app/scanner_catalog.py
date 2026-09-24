"""Pinned, local-only scanner policy shared by the API and worker."""
import hashlib
import json
from pathlib import Path

SEMGREP_VERSION = "1.178.0"
RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "semgrep.yaml"
RULES_BYTES = RULES_PATH.read_bytes()
RULES_SHA256 = hashlib.sha256(RULES_BYTES).hexdigest()
RULES = {rule["id"]: rule for rule in json.loads(RULES_BYTES)["rules"]}
TRIVY_VERSION = "0.74.0"
SCANNERS = ("gitleaks", "semgrep", "trivy")


def scan_configuration(branch):
    return {
        "scanners": list(SCANNERS), "scope": "branch_snapshot", "branch": branch,
        "gitleaks_version": "8.30.1", "semgrep_version": SEMGREP_VERSION,
        "semgrep_rules_sha256": RULES_SHA256, "semgrep_rule_count": len(RULES),
        "trivy_version": TRIVY_VERSION, "trivy_scanners": ["vuln", "misconfig"],
        "trivy_checks": "embedded", "trivy_db_max_age_hours": 24,
        "semgrep_languages": ["python", "javascript", "typescript"],
        "max_file_bytes": 2 * 1024 * 1024, "max_total_bytes": 50 * 1024 * 1024,
        "archive_depth": 0, "decode_depth": 0,
    }
