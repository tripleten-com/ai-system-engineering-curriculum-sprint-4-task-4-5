"""Coldline.

===================

File:              tests/contract/submission_validation.py
Component:         Contract tests — Submission Validation
Purpose:           Validate the Task 4.5 answer sheet (the triage map and the two finding ids) and
                    the permitted paths: four fixed files plus the one file the fixed finding
                    names, resolved from the scan of the starting checkpoint.
Interacts With:    Published interfaces and repository boundaries, tests/security/repository.py,
                    tests/security/scanners.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Compatibility, ownership, export safety, a permitted file no check hardcodes
Tools:             Python 3.12, pytest

Two entrypoints share this module. ``poe answers`` runs it with ``--format-only`` and
checks the answer sheet alone: one plain YAML mapping whose ``answers`` carries ``triage``
(a non-empty map from finding ids of the form ``F-nn`` to ``valid``, ``false_positive`` or
``accepted``), ``fixed_finding`` and ``suppressed_finding`` (each a finding id that is one
of the map's keys, and not the same id), and that the sheet is not a copy of the fictional
sample. ``poe submission`` (inside ``poe verify``) runs it in full, which adds the
permitted-path boundary: the diff from the merge base touches only
``src/worker/config.py``, ``security/gate.yaml``, ``.gitleaks.toml``, ``submission.yaml``
and the one file named by the finding in ``answers.fixed_finding``. That fifth path is
never written here: it is resolved by scanning the starting checkpoint (the merge base
exported from Git) with the supplied scanners and reading the named finding's file out
of that scan's own output, so no file in this repository says which file the fix goes in.
Nothing here judges which triage values or which fixed finding are right: that is the
protected answer check's job, after the submission on the platform.
"""

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from tests.security import repository

# The four files every Task 4.5 pull request may change. The fifth, the fix file, is resolved
# per sheet by `permitted_paths`.
ALLOWED_PATHS = frozenset(
    {
        "src/worker/config.py",
        "security/gate.yaml",
        ".gitleaks.toml",
        "submission.yaml",
    }
)
ALLOWED_PREFIXES: tuple[str, ...] = ()
ANSWER_FIELDS = ("triage", "fixed_finding", "suppressed_finding")
TRIAGE_VALUES = ("valid", "false_positive", "accepted")
# The scan's ids are two digits wide (tests/security/scanners.py, ID_DIGITS); the published
# shape admits a third for a recorded re-pin that widens the id everywhere at once.
FINDING_ID = re.compile(r"^F-\d{2,3}$")


_JSON_YAML_TAGS = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
    }
)


class _RestrictedYamlLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Load the Task's small YAML profile without YAML-only conveniences."""

    def compose_node(self, parent: object, index: object) -> yaml.Node:
        # A prior anchor is already rejected below, but deny aliases directly too.
        if self.check_event(yaml.AliasEvent):
            event = self.get_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML aliases are not permitted",
                event.start_mark,
            )
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML anchors are not permitted",
                event.start_mark,
            )
        return super().compose_node(parent, index)

    def construct_object(self, node: yaml.Node, deep: bool = False) -> object:
        if node.tag not in _JSON_YAML_TAGS:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "non-JSON YAML tags are not permitted",
                node.start_mark,
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML merge keys are not permitted",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML mapping keys must be strings",
                    key_node.start_mark,
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate YAML key: {key}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


class SubmissionError(ValueError):
    """Report one actionable public-verification failure."""


def main(
    root: Path | None = None,
    *,
    changed_paths: list[str] | None = None,
    format_only: bool = False,
    permitted: frozenset[str] | None = None,
) -> int:
    """Validate the answer sheet, and unless ``format_only``, the permitted-path boundary.

    The optional arguments keep this entrypoint testable without changing the
    process working directory, creating a temporary Git repository, or running a scan:
    ``permitted`` replaces the resolution of the fifth path.
    """
    task_root = Path.cwd() if root is None else root
    try:
        validate_submission(
            task_root / "submission.yaml",
            task_root / "docs/contracts/submission.schema.json",
            sample_path=task_root / "submission-sample.yaml",
            task_root=task_root,
        )
        if not format_only:
            changed = _changed_paths(task_root) if changed_paths is None else changed_paths
            allowed = permitted_paths(task_root, changed) if permitted is None else permitted
            validate_changed_paths(changed, allowed)
    except (SubmissionError, RuntimeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    if format_only:
        print("Task 4.5 answer format check passed.")
    else:
        print("Task 4.5 answer and permitted-path verification passed.")
    return 0


def validate_submission(
    submission_path: Path,
    schema_path: Path,
    *,
    sample_path: Path | None = None,
    task_root: Path | None = None,
) -> None:
    """Validate YAML shape, placeholders, the schema, the id references, and sample-copy behavior.

    ``task_root`` names the repository that owns the published contracts. It defaults
    to the answer sheet's own directory, which is correct for a student checkout. A
    curriculum-owned evaluator validating a sheet stored elsewhere passes the trusted
    Task root explicitly.
    """
    submission = _load_one_document(submission_path)
    answers = submission.get("answers") if isinstance(submission, dict) else None
    if not isinstance(answers, dict):
        raise SubmissionError("answers must be one mapping")

    # The blank sheet names the field left empty, before the schema reports a pattern.
    for field in ANSWER_FIELDS:
        value = answers.get(field)
        if field in answers and isinstance(value, str) and not value.strip():
            raise SubmissionError(f"answers.{field} is incomplete")
        if field in answers and isinstance(value, dict) and not value:
            raise SubmissionError(f"answers.{field} is incomplete")
        if field in answers and value is None:
            raise SubmissionError(f"answers.{field} is incomplete")

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(submission), key=lambda error: list(error.path)
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "submission"
        raise SubmissionError(f"{location}: {error.message}")

    triage = answers["triage"]
    for field in ("fixed_finding", "suppressed_finding"):
        if answers[field] not in triage:
            raise SubmissionError(
                f"answers.{field} names {answers[field]}, which is not a key of answers.triage; "
                "every finding you name has a triage value"
            )
    if answers["fixed_finding"] == answers["suppressed_finding"]:
        raise SubmissionError(
            "answers.fixed_finding and answers.suppressed_finding name one finding; the fixed "
            "finding and the suppressed finding are two"
        )

    if sample_path is not None and submission == _load_one_document(sample_path):
        raise SubmissionError("submission must not copy the fictional sample answers")


def permitted_paths(root: Path, changed: list[str]) -> frozenset[str]:
    """Return the permitted paths for this checkout: the four fixed files plus the fix file.

    The fifth path is resolved only when a path beyond the four has changed: the starting
    checkpoint is scanned with the supplied scanners (``tests/security/scanners.py``), and
    the file the finding in ``answers.fixed_finding`` names in that scan's output is the one
    more file the diff may touch. A sheet that names no finding, or a finding the starting
    checkpoint does not report, permits no fifth path.
    """
    extra = sorted(set(changed) - ALLOWED_PATHS)
    if not extra:
        return ALLOWED_PATHS
    submission = _load_one_document(root / "submission.yaml")
    answers = submission.get("answers") if isinstance(submission, dict) else None
    fixed = answers.get("fixed_finding") if isinstance(answers, dict) else None
    if not isinstance(fixed, str) or not FINDING_ID.match(fixed):
        raise SubmissionError(
            f"protected path changed: {', '.join(extra)} (answers.fixed_finding names no "
            "finding, so no file beyond the four fixed permitted files may change)"
        )
    from tests.security import scanners

    try:
        baseline = scanners.scan_baseline(root)
    except scanners.ScanError as exc:
        raise RuntimeError(
            f"the starting checkpoint could not be scanned to resolve the fix file: {exc}"
        ) from exc
    path = baseline.path_of(fixed)
    if path is None:
        raise SubmissionError(
            f"protected path changed: {', '.join(extra)} (answers.fixed_finding names {fixed}, "
            "which the scan of the starting checkpoint does not report, so no file beyond the "
            "four fixed permitted files may change)"
        )
    return ALLOWED_PATHS | {path}


def validate_changed_paths(paths: list[str], permitted: frozenset[str] = ALLOWED_PATHS) -> None:
    """Reject changed paths outside the permitted surfaces."""
    normalized = {PurePosixPath(path.replace("\\", "/")).as_posix() for path in paths}
    protected = sorted(
        path for path in normalized - permitted if not path.startswith(ALLOWED_PREFIXES)
    )
    if protected:
        raise SubmissionError(f"protected path changed: {', '.join(protected)}")


def _changed_paths(root: Path) -> list[str]:
    """Return changes since the commit this checkout branched from."""
    try:
        return repository.changed_paths(root)
    except repository.RepositoryError as exc:
        raise RuntimeError("Git history is unavailable for protected-path validation") from exc


def _load_one_document(path: Path) -> dict[str, Any]:
    """Load exactly one plain JSON-compatible YAML mapping.

    A file that is not UTF-8 is reported the same way as one that is not the
    restricted YAML profile: as a public verification failure, not a traceback.
    """
    try:
        documents = list(
            yaml.load_all(path.read_text(encoding="utf-8"), Loader=_RestrictedYamlLoader)
        )
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise SubmissionError(f"{path.name} must contain UTF-8 restricted YAML") from exc
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise SubmissionError(f"{path.name} must contain exactly one YAML mapping")
    return documents[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the Task 4.5 submission.")
    parser.add_argument(
        "--format-only",
        action="store_true",
        help="check the answer sheet's format only (what `poe answers` runs)",
    )
    arguments = parser.parse_args()
    raise SystemExit(main(format_only=arguments.format_only))
