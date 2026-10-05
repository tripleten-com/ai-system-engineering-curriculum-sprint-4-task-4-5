"""Coldline.

===================

File:              tests/contract/test_submission.py
Component:         Contract tests — Test Submission
Purpose:           Tests for the public answer and path checks for this Task's submission.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest
"""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.contract.submission_validation import (
    ALLOWED_PATHS,
    ANSWER_FIELDS,
    TRIAGE_VALUES,
    SubmissionError,
    _load_one_document,
    main,
    validate_changed_paths,
    validate_submission,
)

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "docs/contracts/submission.schema.json"
TEMPLATE = ROOT / "tests/fixtures/submission-template.yaml"
PERMITTED = ["src/worker/config.py", "security/gate.yaml", ".gitleaks.toml", "submission.yaml"]
# Invented finding ids for the format tests. None names a finding any scan of this
# repository reports, and every allowed triage value appears, so the fixtures show the
# shape and nothing about any finding.
IDS = ("F-80", "F-81", "F-82")


def valid_answers(**overrides: Any) -> dict[str, object]:
    """Return a complete answer sheet in the published shape.

    Fictional format example: these values show the shape and state no result. The ids
    are invented and each triage value appears once, in the schema's order; the fixed
    and the suppressed finding are the first two keys. Copying any of this answers nothing.
    """
    answers: dict[str, Any] = {
        "triage": dict(zip(IDS, TRIAGE_VALUES, strict=True)),
        "fixed_finding": IDS[0],
        "suppressed_finding": IDS[1],
    }
    answers.update(overrides)
    return {"answers": answers}


def own_answers() -> dict[str, object]:
    """Return a complete sheet that is not the published sample."""
    return valid_answers()


def _task_root(tmp_path: Path, submission_text: str) -> Path:
    """Stage a minimal Task root the public verifier can validate."""
    (tmp_path / "docs/contracts").mkdir(parents=True)
    (tmp_path / "submission.yaml").write_text(submission_text, encoding="utf-8")
    (tmp_path / "submission-sample.yaml").write_text(
        (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/contracts/submission.schema.json").write_text(
        SCHEMA.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tmp_path


def test_a_complete_sheet_is_well_formed(tmp_path: Path) -> None:
    """The public schema accepts a complete sheet without judging its correctness."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_blank_template_fails_with_field_address(tmp_path: Path) -> None:
    """An untouched answer sheet must identify the first incomplete field."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="answers.triage is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"triage": {"F-80": "fixed"}}, "triage"),
        ({"triage": {"F-80": "Valid"}}, "triage"),
        ({"triage": {"80": "valid"}}, "triage"),
        ({"triage": {"F-8": "valid"}}, "triage"),
        ({"triage": {"F-8000": "valid"}}, "triage"),
        ({"triage": ["F-80"]}, "triage"),
        ({"fixed_finding": "80"}, "fixed_finding"),
        ({"fixed_finding": "f-80"}, "fixed_finding"),
        ({"suppressed_finding": "F-8"}, "suppressed_finding"),
        ({"suppressed_finding": 81}, "suppressed_finding"),
    ],
    ids=[
        "unlisted-triage-value",
        "capitalised-triage-value",
        "triage-key-without-prefix",
        "triage-key-too-short",
        "triage-key-too-long",
        "triage-not-a-map",
        "fixed-without-prefix",
        "fixed-lowercase",
        "suppressed-too-short",
        "suppressed-not-a-string",
    ],
)
def test_values_outside_the_published_contract_are_rejected(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    """The public schema must name the field it rejected, and reject the right ones."""
    sheet = valid_answers()
    answers = sheet["answers"]
    assert isinstance(answers, dict)
    answers.update(overrides)
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    with pytest.raises(SubmissionError, match=message):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("field", ANSWER_FIELDS)
def test_a_missing_or_blank_field_is_named(tmp_path: Path, field: str) -> None:
    """Each of the three answers is required, and a blank one is named as incomplete."""
    answers = dict(valid_answers()["answers"])  # type: ignore[arg-type]
    del answers[field]
    root = _task_root(tmp_path, yaml.safe_dump({"answers": answers}))
    with pytest.raises(SubmissionError, match=field):
        validate_submission(root / "submission.yaml", SCHEMA)

    blank = dict(valid_answers()["answers"])  # type: ignore[arg-type]
    blank[field] = {} if field == "triage" else ""
    root = _task_root(tmp_path / "blank", yaml.safe_dump({"answers": blank}))
    with pytest.raises(SubmissionError, match=f"answers.{field} is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_the_two_named_findings_must_be_triaged_and_differ(tmp_path: Path) -> None:
    """A named finding outside the triage map, or one id for both, is a format error."""
    root = _task_root(tmp_path / "a", yaml.safe_dump(valid_answers(fixed_finding="F-83")))
    with pytest.raises(SubmissionError, match="not a key of answers.triage"):
        validate_submission(root / "submission.yaml", SCHEMA)

    root = _task_root(tmp_path / "b", yaml.safe_dump(valid_answers(suppressed_finding="F-83")))
    with pytest.raises(SubmissionError, match="not a key of answers.triage"):
        validate_submission(root / "submission.yaml", SCHEMA)

    root = _task_root(tmp_path / "c", yaml.safe_dump(valid_answers(suppressed_finding=IDS[0])))
    with pytest.raises(SubmissionError, match="name one finding"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "field",
    ["gate_verified", "instructor_approved", "scan_clean", "notes"],
)
def test_no_self_attestation_or_report_field_is_accepted(tmp_path: Path, field: str) -> None:
    """Reject a self-approval, a pass boolean, or a report field."""
    answers = valid_answers()
    mapping = answers["answers"]
    assert isinstance(mapping, dict)
    mapping[field] = True
    root = _task_root(tmp_path, yaml.safe_dump(answers))

    with pytest.raises(SubmissionError, match="Additional properties"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_missing_answers_mapping_is_rejected(tmp_path: Path) -> None:
    """The answers mapping is required, not merely tolerated."""
    root = _task_root(tmp_path, "task: 4.5\n")

    with pytest.raises(SubmissionError, match="answers must be one mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_exact_sample_copy_is_rejected(tmp_path: Path) -> None:
    """The published sample must not be accepted as a student submission."""
    root = _task_root(tmp_path, (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="fictional sample"):
        validate_submission(
            root / "submission.yaml",
            SCHEMA,
            sample_path=root / "submission-sample.yaml",
        )


def test_public_entrypoint_reports_an_incomplete_answer_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catch a verifier entrypoint that skips the real submission contract."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=[], format_only=True) == 1
    assert "answers.triage is incomplete" in capsys.readouterr().err


def test_public_entrypoint_rejects_the_sample_and_accepts_a_complete_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`poe answers` applies the sample-copy check; a complete sheet of its own passes."""
    copied = _task_root(tmp_path / "copied", (ROOT / "submission-sample.yaml").read_text("utf-8"))
    assert main(copied, changed_paths=[], format_only=True) == 1
    assert "fictional sample" in capsys.readouterr().err

    own = _task_root(tmp_path / "own", yaml.safe_dump(own_answers()))
    assert main(own, changed_paths=[], format_only=True) == 0
    assert main(own, changed_paths=list(PERMITTED)) == 0


def test_public_entrypoint_reports_a_protected_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A change to a supplied scanner file is named, not silently accepted."""
    root = _task_root(tmp_path, yaml.safe_dump(own_answers()))

    assert main(root, changed_paths=["security/semgrep-rules.yaml"], permitted=ALLOWED_PATHS) == 1
    assert "protected path changed: security/semgrep-rules.yaml" in capsys.readouterr().err


def test_the_fifth_path_is_permitted_only_when_resolved() -> None:
    """The four fixed files always pass; a fifth passes only as the resolved fix file."""
    validate_changed_paths(list(PERMITTED))
    validate_changed_paths(
        [*PERMITTED, "src/example/module.py"], ALLOWED_PATHS | {"src/example/module.py"}
    )

    with pytest.raises(SubmissionError, match="protected path changed: src/example/module.py"):
        validate_changed_paths([*PERMITTED, "src/example/module.py"])
    for protected in (
        "security/semgrep-rules.yaml",
        "security/scanners.yaml",
        ".semgrepignore",
        ".github/workflows/security.yml",
        ".github/workflows/task.yml",
        "src/adapters/secrets/localstack.py",
        "src/adapters/model/provider_keys.py",
        "src/worker/bootstrap.py",
        "src/worker/use_cases.py",
        "src/api/initialize.py",
        "docs/security/gate-policy.md",
        "docs/fidelity/SecretProvider.md",
        "tests/security/scanners.py",
        "tests/contract/test_security_contract.py",
        "tests/student/test_redaction.py",
        "compose.yaml",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "submission-sample.yaml",
    ):
        with pytest.raises(SubmissionError, match="protected path changed"):
            validate_changed_paths([protected])


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "answers: {value: first, value: second}\n",
        "answers: &answer {value: fictional}\n",
        "answers: *missing\n",
        "answers: {<<: {value: fictional}}\n",
        "answers: {value: 2026-09-04}\n",
        "answers: {value: !custom fictional}\n",
        "answers: {1: fictional}\n",
    ],
    ids=["duplicate-key", "anchor", "alias", "merge-key", "date", "custom-tag", "non-string-key"],
)
def test_non_json_yaml_constructs_are_rejected(tmp_path: Path, unsafe_text: str) -> None:
    """Reject restricted syntax before schema validation can mask a parser defect."""
    submission = tmp_path / "submission.yaml"
    submission.write_text(unsafe_text, encoding="utf-8")

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_multiple_yaml_documents_are_rejected(tmp_path: Path) -> None:
    """A second document cannot supply or replace the answer mapping."""
    submission = tmp_path / "submission.yaml"
    submission.write_text("answers: {}\n---\nanswers: {}\n", encoding="utf-8")

    with pytest.raises(SubmissionError, match="exactly one YAML mapping"):
        _load_one_document(submission)


def test_a_sheet_that_is_not_utf_8_is_a_submission_error(tmp_path: Path) -> None:
    """A sheet saved in another encoding gets the public error, not a Python traceback."""
    submission = tmp_path / "submission.yaml"
    submission.write_bytes("answers: {fixed_finding: F-80}\n".encode("utf-16"))

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_the_schema_names_the_three_triage_values_and_the_id_form() -> None:
    """The schema's enum is the policy's three values and its ids have the scan's form."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    answers = schema["properties"]["answers"]

    assert tuple(answers["required"]) == ANSWER_FIELDS
    assert tuple(answers["properties"]["triage"]["additionalProperties"]["enum"]) == TRIAGE_VALUES
    assert answers["properties"]["triage"]["minProperties"] == 1
    pattern = schema["$defs"]["finding_id"]["pattern"]
    assert answers["properties"]["triage"]["propertyNames"]["pattern"] == pattern
    assert pattern == "^F-[0-9]{2,3}$"


def test_the_template_fixture_is_a_blank_sheet_with_the_three_fields() -> None:
    """The fixture is the blank shape: an empty map and two empty strings."""
    document = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

    assert document == {"answers": {"triage": {}, "fixed_finding": "", "suppressed_finding": ""}}


def test_the_sample_shows_every_triage_value_under_invented_ids() -> None:
    """The sample covers every allowed value and names ids no scan of this tree reports."""
    document = yaml.safe_load((ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))
    triage = document["answers"]["triage"]

    assert sorted(triage.values()) == sorted(TRIAGE_VALUES)
    assert all(key.startswith("F-9") for key in triage)
    assert document["answers"]["fixed_finding"] in triage
    assert document["answers"]["suppressed_finding"] in triage
