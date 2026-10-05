"""Coldline.

===================

File:              tests/security/assessed_run.py
Component:         Security tooling — Assessed-module runner
Purpose:           Run the assessed contract module under pytest with a junit report and require
                    every registered assessed case to have executed and passed.
Interacts With:    tests/contract/test_security_contract.py, pyproject.toml
                    (`poe security-contract`, `poe verify`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Closed inventories, skipped is not passed, trusted comparison outside the
                    process under test
Tools:             Python 3.12, pytest (as a subprocess), junit XML

The assessed module imports the student's application code (the settings module, through
the in-process harness the inherited rows use, and the worker image through the stack)
into the pytest process that judges it. Code that runs at import time there could
reassign ``pytest.mark.assessed`` to a skip, deselect, or otherwise keep an assessed case
from running, and a green pytest exit would then say nothing. So ``poe security-contract``
does not call pytest directly: this module does, with a junit report in a temporary
directory, and then compares the report against the registered inventory of the module's
cases in a process the student's code never enters. Every registered case must appear
exactly once and have ``passed``; a case that is missing, skipped, errored or failed, and
a case the inventory does not know, is named and fails the step, whatever pytest's own
exit code was. pytest's output is passed through, so the student still reads the rows'
own messages.

The inventory is static text, keyed by the module's path: the case names as junit
reports them (the function name, with the parameter id in brackets). The parametrized
rows derive their ids the same way the module does, from the supplied response names, so
the two cannot drift apart silently; a unit test also keeps the function names in step
with the module's source.

``python -m tests.security.assessed_run tests/contract/test_security_contract.py`` is the
command; extra arguments are passed to pytest unchanged (``-k`` is refused, because a
deselection is what this runner exists to catch).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path

from adapters.model.deterministic import REJECTED_RESPONSES

TASK_ROOT = Path(__file__).resolve().parents[2]
PYTEST_TIMEOUT_SECONDS = 3600
# The live interactions the contract module makes, by the id its parametrized rows carry:
# the N-01 note with the valid answer, the default note with the pii-echo answer, and the
# N-01 note with each refused answer (the inherited Task 4.3 and 4.4 rows).
INTERACTION_IDS: tuple[str, ...] = ("n01-valid", "pii-echo", *REJECTED_RESPONSES)
SECURITY_MODULE = "tests/contract/test_security_contract.py"
# Every assessed case the module collects, as junit names it, in the module's order. A
# module not listed here cannot be run through this runner.
REGISTERED_CASES: dict[str, tuple[str, ...]] = {
    SECURITY_MODULE: (
        "test_config_reads_the_key_through_the_secret_provider_and_holds_no_literal",
        "test_the_fix_changes_one_function_of_one_file_and_adds_no_import",
        "test_a_scenario_completes_and_the_worker_authenticated_with_the_current_version",
        *(
            f"test_bad_responses_still_end_needs_review[{response}]"
            for response in REJECTED_RESPONSES
        ),
        *(
            f"test_the_audit_trail_still_reconstructs_one_interaction[{interaction}]"
            for interaction in INTERACTION_IDS
        ),
        "test_pii_scan_still_finds_no_marked_value_from_n01_or_pii_echo",
        "test_the_task_2_access_rule_still_protects_the_summary_route",
        "test_a_replacement_takes_effect_without_a_restart_and_the_previous_version_is_rejected",
        "test_no_output_contains_any_versions_value",
        "test_gate_thresholds_fail_any_secret_and_a_high_vulnerability",
        "test_the_clean_tree_scan_passes_with_the_thresholds_and_writes_both_reports",
        "test_the_seeded_secret_fails_the_scan_on_a_gitleaks_finding",
        "test_the_seeded_vulnerable_dependency_fails_the_scan_on_a_trivy_finding",
        "test_the_gitleaks_entry_names_the_rule_and_single_path_of_the_suppressed_finding",
        "test_every_starting_checkpoint_finding_has_one_triage_value",
        "test_the_fixed_finding_names_the_one_changed_file_and_a_finding_is_gone_from_it",
        "test_submission_answers_use_the_allowed_values",
    ),
}
REFUSED_OPTIONS: frozenset[str] = frozenset({"-k", "--deselect", "-m"})


class AssessedRunError(RuntimeError):
    """Report that the run could not be made or read, as opposed to a verdict about it."""


def outcomes_of(report: Path) -> dict[str, str]:
    """Return each junit case's outcome by its name: passed, failed, error, or skipped.

    A name that appears twice is an error: one outcome per registered case is required.
    """
    if not report.is_file():
        raise AssessedRunError(f"pytest wrote no junit report at {report}")
    outcomes: dict[str, str] = {}
    for case in ET.parse(report).iter("testcase"):
        name = case.attrib.get("name", "")
        if name in outcomes:
            raise AssessedRunError(f"the junit report names {name!r} twice")
        if case.find("error") is not None:
            outcomes[name] = "error"
        elif case.find("failure") is not None:
            outcomes[name] = "failed"
        elif case.find("skipped") is not None:
            outcomes[name] = "skipped"
        else:
            outcomes[name] = "passed"
    return outcomes


def compare(module: str, outcomes: dict[str, str]) -> list[str]:
    """Return why the report is not every registered case of ``module``, each passed."""
    registered = REGISTERED_CASES.get(module)
    if registered is None:
        raise AssessedRunError(
            f"{module} is not a registered assessed module; choose one of "
            f"{', '.join(REGISTERED_CASES)}"
        )
    findings: list[str] = []
    for name in registered:
        outcome = outcomes.get(name)
        if outcome is None:
            findings.append(f"{name} did not run (missing from the report)")
        elif outcome != "passed":
            findings.append(f"{name} {outcome}")
    for name in outcomes:
        if name not in registered:
            findings.append(
                f"{name} is not a registered case of {module}; the inventory in "
                "tests/security/assessed_run.py must list every case"
            )
    return findings


def refused_option(argument: str) -> bool:
    """Return whether a pytest argument would deselect cases (``-k``, ``-m``, ``--deselect``)."""
    return argument in REFUSED_OPTIONS or any(
        argument.startswith(f"{option}=") for option in REFUSED_OPTIONS
    )


def run(module: str, extra: Sequence[str] = (), *, root: Path = TASK_ROOT) -> tuple[int, list[str]]:
    """Run one assessed module under pytest and compare its junit report; return (exit, findings).

    pytest's exit code is returned as it was, so a failing row still exits 1; the
    findings are what the inventory comparison adds. A refused option (``-k``, ``-m``,
    ``--deselect``) is a tooling error: this runner exists to refuse a deselection.
    """
    for argument in extra:
        if refused_option(argument):
            raise AssessedRunError(
                f"{argument} is not permitted here: every assessed case must run"
            )
    with tempfile.TemporaryDirectory(prefix="coldline-assessed-") as temporary:
        report = Path(temporary) / "assessed.xml"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", module, *extra, f"--junitxml={report}"],
            cwd=root,
            check=False,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )
        if completed.returncode not in {0, 1} and not report.is_file():
            raise AssessedRunError(
                f"pytest exited {completed.returncode} running {module} and wrote no report: "
                "the run did not happen as asked"
            )
        findings = compare(module, outcomes_of(report))
    return completed.returncode, findings


def main(argv: Sequence[str] | None = None) -> int:
    """Run the module named first, pass the rest to pytest, and require every case passed."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0].startswith("-"):
        print("assessed-run: name the assessed module to run first", file=sys.stderr)
        return 2
    module = Path(arguments[0]).as_posix()
    try:
        returncode, findings = run(module, arguments[1:])
    except AssessedRunError as exc:
        print(f"assessed-run: {exc}", file=sys.stderr)
        return 2
    registered = len(REGISTERED_CASES[module])
    if findings:
        print(
            f"assessed-run: {module}: {len(findings)} of {registered} registered cases did not "
            "execute and pass:",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return returncode or 1
    print(f"assessed-run: {module}: all {registered} registered cases executed and passed.")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
