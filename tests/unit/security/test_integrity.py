"""Coldline.

===================

File:              tests/unit/security/test_integrity.py
Component:         Unit tests — Verification integrity snapshot
Purpose:           Prove the snapshot names every file changed, added, or removed while `poe
                    verify` ran, covers the four fixed permitted files first and the trusted
                    material after them, and skips the caches.
Interacts With:    tests/security/integrity.py, pyproject.toml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Trusted bookends, content hashes, tamper evidence
Tools:             Python 3.12, pytest

The tests build a small tree shaped like the Task's trusted paths under ``tmp_path`` and
point the snapshot at a file beside it, so nothing here touches the real checkout or the
system temporary directory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.security import integrity

TRUSTED_TREE = {
    "pyproject.toml": "[tool.poe.tasks]\nverify = []\n",
    "uv.lock": "version = 1\n",
    "src/worker/config.py": "class WorkerSettings:\n    pass\n",
    "security/gate.yaml": "secrets: none\n",
    ".gitleaks.toml": "[extend]\nuseDefault = true\n",
    "submission.yaml": "answers: {}\n",
    # Invented application modules; nothing here names a file of the shipped tree.
    "src/example/module.py": "def example_function():\n    return None\n",
    "src/example/other.py": "EXAMPLES = ()\n",
    "security/scanners.yaml": "scanners: {}\n",
    "security/semgrep-rules.yaml": "rules: []\n",
    ".semgrepignore": ".git/\n",
    ".github/workflows/security.yml": "name: Security gate\n",
    "tests/contract/test_security_contract.py": "def test_row():\n    pass\n",
    "tests/security/scanners.py": "SCANNERS = ()\n",
    "tests/student/test_redaction.py": "def test_student():\n    pass\n",
    "tests/fixtures/credentials/test-values.yaml": "values: {}\n",
    "tests/fixtures/example/values.yaml": "fixtures: {}\n",
    "schemas/exception-summary.schema.json": "{}\n",
    "docs/security/gate-policy.md": "# policy\n",
    "docs/contracts/submission.schema.json": "{}\n",
    "config/auth.yaml": "auth: {}\n",
    "infra/corpus/documents.jsonl": "{}\n",
}
EXPECTED_ORDER = [
    "src/worker/config.py",
    "security/gate.yaml",
    ".gitleaks.toml",
    "submission.yaml",
    "src/example/module.py",
    "src/example/other.py",
    "security/scanners.yaml",
    "security/semgrep-rules.yaml",
    ".semgrepignore",
    ".github/workflows/security.yml",
    "tests/contract/test_security_contract.py",
    "tests/security/scanners.py",
    "tests/student/test_redaction.py",
    "tests/fixtures/credentials/test-values.yaml",
    "tests/fixtures/example/values.yaml",
    "schemas/exception-summary.schema.json",
    "docs/security/gate-policy.md",
    "docs/contracts/submission.schema.json",
    "config/auth.yaml",
    "infra/corpus/documents.jsonl",
    "pyproject.toml",
    "uv.lock",
]


def _tree(root: Path) -> None:
    """Write the small trusted tree, plus noise the snapshot must ignore."""
    for relative, text in TRUSTED_TREE.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    cache = root / "tests/security/__pycache__"
    cache.mkdir()
    (cache / "scanners.cpython-312.pyc").write_bytes(b"\x00")
    (root / "README.md").write_text("not covered\n", encoding="utf-8")
    (root / "reports/security").mkdir(parents=True)
    (root / "reports/security/scan.sarif").write_text("{}\n", encoding="utf-8")


def test_the_snapshot_covers_the_trusted_paths_and_skips_caches_and_reports(tmp_path: Path) -> None:
    """Every file under the trusted paths is hashed; caches, the README and the reports are not."""
    _tree(tmp_path)

    files = [path.as_posix() for path in integrity.trusted_files(tmp_path)]

    assert files == EXPECTED_ORDER
    digests = integrity.snapshot(tmp_path)
    assert set(digests) == set(files)
    assert all(len(digest) == 64 for digest in digests.values())


def test_the_trusted_paths_name_the_four_fixed_permitted_files_first() -> None:
    """The snapshot starts with the Task's four fixed files, then src/ whole, then the material."""
    assert integrity.TRUSTED_PATHS[:4] == (
        "src/worker/config.py",
        "security/gate.yaml",
        ".gitleaks.toml",
        "submission.yaml",
    )
    assert integrity.TRUSTED_PATHS[4] == "src/"
    for trusted in (
        "security/",
        ".semgrepignore",
        ".github/workflows/security.yml",
        "tests/contract/",
        "tests/security/",
        "tests/student/",
        "tests/fixtures/",
        "schemas/",
        "docs/security/",
        "docs/contracts/submission.schema.json",
        "config/auth.yaml",
        "infra/corpus/documents.jsonl",
        "pyproject.toml",
        "uv.lock",
    ):
        assert trusted in integrity.TRUSTED_PATHS, trusted
    assert len(integrity.TRUSTED_PATHS) == len(set(integrity.TRUSTED_PATHS))
    assert not any(entry.startswith("reports") for entry in integrity.TRUSTED_PATHS)


def test_a_file_covered_twice_is_hashed_once(tmp_path: Path) -> None:
    """The settings module (named, and under src/) and the credential values appear once."""
    _tree(tmp_path)

    files = [path.as_posix() for path in integrity.trusted_files(tmp_path)]

    assert files.count("src/worker/config.py") == 1
    assert files.count("tests/fixtures/credentials/test-values.yaml") == 1
    assert len(files) == len(set(files))


def test_compare_names_changed_added_and_removed_files() -> None:
    """One finding per file, in path order, saying which of the three happened."""
    before = {"a.py": "1", "b.py": "2", "c.py": "3"}
    after = {"a.py": "1", "b.py": "9", "d.py": "4"}

    assert integrity.compare(before, after) == [
        "b.py changed during verification",
        "c.py was removed during verification",
        "d.py was added during verification",
    ]
    assert integrity.compare(before, dict(before)) == []


def test_a_changed_application_module_is_named_wherever_under_src_it_is(tmp_path: Path) -> None:
    """Record, rewrite an application module behind the checks, check: it is named."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-snapshot.json"
    integrity.record(tmp_path, snapshot)

    (tmp_path / "src/example/module.py").write_text(
        "def example_function():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "security/gate.yaml").write_text("secrets: any\n", encoding="utf-8")

    assert integrity.check(tmp_path, snapshot) == [
        "security/gate.yaml changed during verification",
        "src/example/module.py changed during verification",
    ]
    assert not snapshot.exists(), "the snapshot is consumed by the check"


def test_an_unchanged_tree_passes_and_the_snapshot_is_consumed(tmp_path: Path) -> None:
    """Record then check with nothing in between: no findings, and the snapshot is gone."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-clean.json"

    integrity.record(tmp_path, snapshot)
    (tmp_path / "reports/security/scan.sarif").write_text('{"written": true}\n', encoding="utf-8")
    assert integrity.check(tmp_path, snapshot) == [], "the reports the run writes are not covered"
    assert not snapshot.exists()


def test_a_missing_foreign_or_malformed_snapshot_is_a_tooling_error(tmp_path: Path) -> None:
    """No snapshot, another checkout's snapshot, or an unreadable one: an error, not a pass."""
    _tree(tmp_path)
    snapshot = tmp_path.parent / f"{tmp_path.name}-errors.json"

    with pytest.raises(integrity.IntegrityError, match="no integrity snapshot"):
        integrity.check(tmp_path, snapshot)

    other = tmp_path / "other"
    other.mkdir()
    _tree(other)
    integrity.record(other, snapshot)
    with pytest.raises(integrity.IntegrityError, match="was recorded for"):
        integrity.check(tmp_path, snapshot)

    snapshot.write_text("{not json", encoding="utf-8")
    with pytest.raises(integrity.IntegrityError, match="could not be read"):
        integrity.check(tmp_path, snapshot)
    snapshot.write_text('{"root": "x", "files": "nope"}', encoding="utf-8")
    with pytest.raises(integrity.IntegrityError, match="no file digests"):
        integrity.check(tmp_path, snapshot)


def test_the_snapshot_lives_outside_the_repository_per_checkout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The default path is in the system temporary directory and differs per checkout root."""
    monkeypatch.delenv(integrity.SNAPSHOT_VARIABLE, raising=False)
    first = integrity.snapshot_path(tmp_path / "one")
    second = integrity.snapshot_path(tmp_path / "two")

    assert first != second
    assert first.parent == second.parent
    assert not first.is_relative_to(tmp_path)
    assert first.name.startswith("coldline-verify-") and first.suffix == ".json"

    monkeypatch.setenv(integrity.SNAPSHOT_VARIABLE, str(tmp_path / "override.json"))
    assert integrity.snapshot_path(tmp_path / "one") == tmp_path / "override.json"


def test_the_command_line_records_then_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`record` exits 0 with the count; `check` exits 1 naming a change, 2 without a snapshot."""
    _tree(tmp_path)
    monkeypatch.setenv(integrity.SNAPSHOT_VARIABLE, str(tmp_path.parent / f"{tmp_path.name}.json"))

    assert integrity.main(["check", "--root", str(tmp_path)]) == 2
    assert "no integrity snapshot" in capsys.readouterr().err

    assert integrity.main(["record", "--root", str(tmp_path)]) == 0
    assert f"recorded {len(EXPECTED_ORDER)} trusted files" in capsys.readouterr().out
    (tmp_path / "tests/security/scanners.py").write_text("SCANNERS = ('x',)\n", encoding="utf-8")
    assert integrity.main(["check", "--root", str(tmp_path)]) == 1
    assert "- tests/security/scanners.py changed during verification" in capsys.readouterr().err

    assert integrity.main(["record", "--root", str(tmp_path)]) == 0
    assert integrity.main(["check", "--root", str(tmp_path)]) == 0
    assert "every trusted file is as it was" in capsys.readouterr().out
