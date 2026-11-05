import json
from collections.abc import Mapping, Sequence

from first_commit import __version__
from first_commit.fixes import CONTRIBUTOR_RULES, SETUP_RULES, fix_for
from first_commit.models import Finding, Result
from first_commit.policy_fields import DEFAULT_LIMITS
from first_commit.setup_command import setup_command

NEXT_ACTION = "Next action: run "
NOT_SHOWN = (
    "At least {count:,} more finding{s} {were} not shown; each check shows at most "
    f"{DEFAULT_LIMITS['max_findings']:,}."
)
DOCTOR_SCOPE = "doctor"
SETUP_RECOVERY_RULES = frozenset((*SETUP_RULES, *CONTRIBUTOR_RULES))


def next_action_line(
    result: Result, *, setup_hook: bool = True, main_worktree: str | None = None
) -> str | None:
    if result.scope != DOCTOR_SCOPE:
        return None
    for finding in result.findings:
        if finding.rule_id in SETUP_RECOVERY_RULES:
            if main_worktree is not None:
                return f"Next action: commit from the main worktree at {main_worktree}"
            return NEXT_ACTION + setup_command(setup_hook=setup_hook)
    return None


def _finding_value(
    finding: Finding, *, setup_hook: bool, main_worktree: str | None
) -> dict[str, object]:
    value: dict[str, object] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "path": finding.path,
        "summary": finding.summary,
    }
    if finding.line is not None:
        value["line"] = finding.line
    if finding.commit is not None:
        value["commit"] = finding.commit
    fix = fix_for(finding, setup_hook=setup_hook, main_worktree=main_worktree)
    if fix is not None:
        value["fix"] = fix
    return value


def not_shown_line(result: Result) -> str | None:
    if not result.not_shown:
        return None
    plural = result.not_shown != 1
    return NOT_SHOWN.format(
        count=result.not_shown,
        s="s" if plural else "",
        were="were" if plural else "was",
    )


def _versioned(value: Mapping[str, object]) -> dict[str, object]:
    return {"schema_version": 1, "tool_version": __version__, **value}


def _dumps(value: Mapping[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def json_value(
    result: Result, *, setup_hook: bool = True, main_worktree: str | None = None
) -> dict[str, object]:
    value: dict[str, object] = {
        "scope": result.scope,
        "passed": result.passed,
        "findings": [
            _finding_value(item, setup_hook=setup_hook, main_worktree=main_worktree)
            for item in result.findings
        ],
    }
    if result.not_shown:
        value["not_shown"] = result.not_shown
    return _versioned(value)


def print_json(payload: Mapping[str, object]) -> None:
    print(_dumps(_versioned(payload)))


def print_object(value: Mapping[str, object]) -> None:
    print(_dumps(value))


def print_error(code: str, message: str, commands: Sequence[str]) -> None:
    print_object({"error": {"code": code, "message": message, "next": list(commands)}})


def render_human(
    result: Result, *, setup_hook: bool = True, main_worktree: str | None = None
) -> str:
    if not result.findings:
        return f"ok - {result.scope} policy passed"
    lines = []
    for finding in result.findings:
        location = json.dumps(finding.path, ensure_ascii=True)
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append(f"{finding.rule_id} {location}: {finding.summary}")
        fix = fix_for(finding, setup_hook=setup_hook, main_worktree=main_worktree)
        if fix is not None:
            lines.append("  fix: " + fix)
    hidden = not_shown_line(result)
    if hidden is not None:
        lines.append(hidden)
    if result.passed:
        lines.append(f"ok - {result.scope} policy passed (warnings only)")
    else:
        lines.append(f"{len(result.findings)} policy finding(s)")
    return "\n".join(lines)
