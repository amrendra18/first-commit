import argparse
import json
import platform
import subprocess
import time
from pathlib import Path

from verify_lib.core import (
    GITLEAKS_DOWNLOADED,
    GITLEAKS_REUSED,
    FeatureResult,
    Run,
)
from verify_lib.interpreter import PROJECT
from verify_lib.prepare import redact

FACT_TIMEOUT_SECONDS = 30


def _git(root: Path, *arguments: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        timeout=FACT_TIMEOUT_SECONDS,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def _python_version(python: str) -> str:
    try:
        result = subprocess.run(
            [python, "-c", "import platform; print(platform.python_version())"],
            capture_output=True,
            text=True,
            timeout=FACT_TIMEOUT_SECONDS,
            check=False,
        )
    except OSError:
        return ""
    return result.stdout.strip()


def run_facts(python: str, root: Path = PROJECT) -> dict[str, str]:
    head = _git(root, "rev-parse", "HEAD")
    status = _git(root, "status", "--porcelain") if head else None
    return {
        "head": head or "unknown (not a Git work tree)",
        "dirty": "unknown" if status is None else ("yes" if status else "no"),
        "python": _python_version(python) or "unknown",
        "python path": python,
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
    }


def fact_lines(facts: dict[str, str]) -> list[str]:
    return [
        f"- HEAD: {facts['head']} (dirty: {facts['dirty']})",
        f"- Python: {facts['python']} ({facts['python path']})",
        f"- platform: {facts['platform']}",
    ]


def gitleaks_counts(results: dict[str, FeatureResult]) -> dict[str, int]:
    logs = [entry.log for entry in results.values()]
    return {
        "downloaded": sum(len(GITLEAKS_DOWNLOADED.findall(log)) for log in logs),
        "reused": sum(len(GITLEAKS_REUSED.findall(log)) for log in logs),
    }


def preflight_line(run: Run) -> str:
    features = ", ".join(run.features_without_preflight) or "no feature"
    return (
        f"- preflight: off (SetupRequest preflight=False) in {features}, because "
        "the snapshot is not on GitHub; github runs setup with the real preflight, "
        "and first-run and the clone features run setup as a person does. The "
        "GitHub address maps to the snapshot clone through the scratch HOME's Git "
        "config"
    )


def write_evidence(
    evidence: Path, run: Run, results: dict[str, FeatureResult], meta: dict[str, object]
) -> None:
    (evidence / "logs").mkdir(parents=True, exist_ok=True)
    facts = meta["facts"]
    if not isinstance(facts, dict):
        raise TypeError("meta['facts'] must be the run_facts mapping")
    gitleaks = gitleaks_counts(results)
    features = {}
    for name, entry in results.items():
        (evidence / "logs" / f"{name}.log").write_text(redact(entry.log, run), "utf-8")
        features[name] = {
            "state": entry.state,
            "observed": [redact(line, run) for line in entry.observed],
            "reason": redact(entry.reason, run),
        }
    summary = {
        **meta,
        "gitleaks": gitleaks,
        "preflight_off": run.features_without_preflight,
        "removed_path_folders": run.removed_path_folders,
        "features": features,
    }
    (evidence / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", "utf-8"
    )
    lines = [
        f"# scripts/verify {meta['level']}",
        "",
        f"- started: {meta['started']}",
        f"- seconds: {meta['seconds']}",
        *fact_lines(facts),
        f"- snapshot commit: {meta['revision']}",
        f"- planted defect: {meta['plant'] or 'none'}",
        preflight_line(run),
        "- PATH folders removed for holding first-commit: "
        + (", ".join(run.removed_path_folders) or "none"),
        (
            "- Gitleaks, from setup's own output lines: "
            f"downloaded {gitleaks['downloaded']}, reused {gitleaks['reused']}"
        ),
        f"- cleanup: {meta['cleanup']}",
        "",
        "| # | feature | state | proof or reason |",
        "|---|---|---|---|",
    ]
    for number, (name, feature) in enumerate(features.items(), 1):
        state = feature["state"]
        detail = (
            "; ".join(feature["observed"]) if state == "proven" else feature["reason"]
        )
        lines.append(f"| {number} | {name} | {state} | {detail} |")
    (evidence / "summary.md").write_text("\n".join(lines) + "\n", "utf-8")


def finish(
    run: Run,
    results: dict[str, FeatureResult],
    options: argparse.Namespace,
    started: float,
) -> int:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(started))
    evidence = PROJECT / ".local/verify" / stamp
    cleanup = (
        "temporary folder removed"
        if not run.work.exists()
        else f"problem: {run.work} left"
    )
    seconds = round(time.time() - started, 1)
    write_evidence(
        evidence,
        run,
        results,
        {
            "level": options.feature or options.level,
            "started": stamp,
            "seconds": seconds,
            "revision": run.revision,
            "plant": options.plant,
            "cleanup": cleanup,
            "facts": run_facts(run.python),
        },
    )
    passed = bool(results) and all(
        entry.state == "proven" or (entry.state == "skipped" and entry.optional)
        for entry in results.values()
    )
    print(f"cleanup: {cleanup}")
    print(f"time: {seconds} seconds")
    print(f"evidence: {evidence.relative_to(PROJECT)}")
    return 0 if passed else 1
