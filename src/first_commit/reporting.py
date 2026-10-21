import json
from collections.abc import Mapping

from first_commit import __version__
from first_commit.fixes import CONTRIBUTOR_RULES, SETUP_RULES, fix_for
from first_commit.models import Finding, Result
from first_commit.setup_command import setup_command

NEXT_ACTION = "Next action: run "
DOCTOR_SCOPE = "doctor"
SETUP_RECOVERY_RULES = frozenset((*SETUP_RULES, *CONTRIBUTOR_RULES))


def next_action_line(result: Result, *, setup_hook: bool = True) -> str | None:
    if result.scope != DOCTOR_SCOPE:
        return None
    for finding in result.findings:
        if finding.rule_id in SETUP_RECOVERY_RULES:
            return NEXT_ACTION + setup_command(setup_hook=setup_hook)
    return None


def _finding_value(finding: Finding, *, setup_hook: bool) -> dict[str, object]:
    value: dict[str, object] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "path": finding.path,
        "summary": finding.summary,
    }
    if finding.line is not None:
        value["line"] = finding.line
    fix = fix_for(finding, setup_hook=setup_hook)
    if fix is not None:
        value["fix"] = fix
    return value


def _versioned(value: Mapping[str, object]) -> dict[str, object]:
    return {"schema_version": 1, "tool_version": __version__, **value}


def _dumps(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def json_value(result: Result, *, setup_hook: bool = True) -> dict[str, object]:
    return _versioned(
        {
            "scope": result.scope,
            "passed": result.passed,
            "findings": [
                _finding_value(item, setup_hook=setup_hook) for item in result.findings
            ],
        }
    )


def print_json(payload: Mapping[str, object]) -> None:
    print(_dumps(_versioned(payload)))


def render_human(result: Result, *, setup_hook: bool = True) -> str:
    if not result.findings:
        return f"ok - {result.scope} policy passed"
    lines = []
    for finding in result.findings:
        location = json.dumps(finding.path, ensure_ascii=True)
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append(f"{finding.rule_id} {location}: {finding.summary}")
        fix = fix_for(finding, setup_hook=setup_hook)
        if fix is not None:
            lines.append("  fix: " + fix)
    if result.passed:
        lines.append(f"ok - {result.scope} policy passed (warnings only)")
    else:
        lines.append(f"{len(result.findings)} policy finding(s)")
    return "\n".join(lines)
