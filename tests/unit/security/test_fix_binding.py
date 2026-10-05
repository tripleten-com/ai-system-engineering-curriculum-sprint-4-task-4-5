"""Coldline.

===================

File:              tests/unit/security/test_fix_binding.py
Component:         Unit tests — Bounded diff of the fix file
Purpose:           Prove the check accepts a change to one function's body and names a second
                    changed function, no changed function (a comment or a suppression marker), a
                    forbidden builtin or a dunder name in the changed function, a new import, a
                    changed module-level statement or class head, a changed signature, a new
                    reach door, a second file, a non-Python file, and a file the starting
                    checkpoint did not have; over synthetic pairs and over a temporary Git
                    repository.
Interacts With:    tests/security/fix_binding.py, tests/security/repository.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A bounded AST diff, a check that knows no finding
Tools:             Python 3.12, pytest, Git

The module under test here is a synthetic one with two functions, a constant and a class;
nothing reads the shipped fix file or names a finding. The door the probe's baseline opens
and its fix closes (an attribute reached by name) is one no scan of the shipped tree
reports, so the probe demonstrates the shape of a bounded fix and nothing about any finding.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tests.security import fix_binding

BASELINE = '''"""Probe module."""

import re

LIMIT = 3
_PATTERN = re.compile(r"(\\d+)")


def first(text: str) -> int:
    """Return the first number, through an attribute reached by name."""
    match = _PATTERN.search(text)
    if match is None:
        return 0
    return int(getattr(match, "group")(1))


def second(value: int) -> int:
    """Return twice the value."""
    return value * 2


class Holder:
    """A class with one method."""

    def method(self, value: int) -> int:
        """Return the value plus the limit."""
        return value + LIMIT
'''
FIXED = BASELINE.replace(
    '    return int(getattr(match, "group")(1))\n', "    return int(match.group(1))\n"
)
GIT_IDENTITY = ("-c", "user.name=Fix Binding Test", "-c", "user.email=fix@localhost")


def _findings(current: str, baseline: str = BASELINE) -> list[str]:
    return fix_binding.diff_findings(baseline, current, "src/probe.py")


def test_one_functions_body_may_change_and_a_reach_door_may_close() -> None:
    """Closing the probe's door inside one function is the bounded fix; comments may change."""
    assert _findings(FIXED) == []
    assert _findings(FIXED.replace('"""Probe module."""', '"""Probe module, revised."""')) != []
    commented = FIXED.replace("LIMIT = 3\n", "LIMIT = 3  # the bound\n")
    assert _findings(commented) == []


def test_a_candidate_file_with_no_changed_function_body_is_not_a_fix() -> None:
    """A file that differs in no function body as syntax is named, whatever else changed.

    A candidate exists because Git reports the file changed; a comment, a scanner
    suppression marker on the flagged line, or a reflowed statement leaves every function
    the same syntax tree, and a scan that honours the marker would report the finding gone
    without a fix. The check does not honour it: exactly one function body must differ.
    """
    [finding] = _findings(BASELINE)
    assert "no function body differs from the starting checkpoint's copy" in finding
    suppressed = BASELINE.replace(
        '    return int(getattr(match, "group")(1))\n',
        '    return int(getattr(match, "group")(1))  # nosemgrep\n',
    )
    [finding] = _findings(suppressed)
    assert "no function body differs" in finding and "suppression marker" in finding
    reflowed = BASELINE.replace("LIMIT = 3\n", "LIMIT = (\n    3\n)\n")
    [finding] = _findings(reflowed)
    assert "no function body differs" in finding


@pytest.mark.parametrize(
    "body, name",
    [
        ("    evaluator = eval\n    return int(evaluator(match.group(1)))\n", "eval"),
        ('    reader = getattr\n    return int(reader(match, "group")(1))\n', "getattr"),
        ("    return int(__import__('builtins').eval(match.group(1)))\n", "__import__"),
        ("    namespace = globals()\n    return int(match.group(1))\n", "globals"),
        ("    code = compile('1', 'x', 'eval')\n    return int(match.group(1))\n", "compile"),
        ("    exec('pass')\n    return int(match.group(1))\n", "exec"),
        (
            "    open('tests/security/probe.py', 'w').write('x')\n    return int(match.group(1))\n",
            "open",
        ),
        ("    writer = open\n    return int(match.group(1))\n", "open"),
        ("    setattr(match, 'x', 1)\n    return int(match.group(1))\n", "setattr"),
        ("    delattr(match, 'x')\n    return int(match.group(1))\n", "delattr"),
        ("    scope = vars()\n    return int(match.group(1))\n", "vars"),
        ("    scope = locals()\n    return int(match.group(1))\n", "locals"),
        ("    input()\n    return int(match.group(1))\n", "input"),
        ("    breakpoint()\n    return int(match.group(1))\n", "breakpoint"),
        ("    return int(match.group(1)) + len(re.open)\n", "open"),
    ],
    ids=[
        "eval-handed-on",
        "getattr-handed-on",
        "import",
        "globals",
        "compile",
        "exec",
        "open-write",
        "open-handed-on",
        "setattr",
        "delattr",
        "vars",
        "locals",
        "input",
        "breakpoint",
        "open-attribute",
    ],
)
def test_a_forbidden_builtin_in_the_changed_function_is_named(body: str, name: str) -> None:
    """The changed function holds none of the thirteen builtins, called or handed on.

    The baseline's own door (`getattr`) is not subtracted: a fix that keeps it under
    another name, or that swaps `eval` for `getattr`, is not a fix of that function. A
    function exercised by the unit tests that writes a file (`open(...).write(...)`)
    could replace the assessed module between the integrity bookends; it is named, by
    line, without the path it would write.
    """
    current = BASELINE.replace('    return int(getattr(match, "group")(1))\n', body)
    findings = _findings(current)
    assert any(f"`{name}` in `first`, the one changed function" in f for f in findings), findings
    assert all("probe.py" not in finding for finding in findings)


@pytest.mark.parametrize(
    "body, name",
    [
        ("    return int(match.__class__(match.group(1)))\n", "__class__"),
        ("    return int(__builtins__['int'](match.group(1)))\n", "__builtins__"),
        ("    return int(first.__globals__['int'](match.group(1)))\n", "__globals__"),
        ("    def __call__(self):\n        return 1\n    return int(match.group(1))\n", "__call__"),
        ("    def inner(__x__):\n        return __x__\n    return int(match.group(1))\n", "__x__"),
    ],
    ids=["attribute", "name", "globals", "definition", "parameter"],
)
def test_a_dunder_name_in_the_changed_function_is_named(body: str, name: str) -> None:
    """The changed function spells no dunder name: name, attribute, definition or parameter."""
    current = BASELINE.replace('    return int(getattr(match, "group")(1))\n', body)
    findings = _findings(current)
    assert any(f"the dunder name `{name}` in `first`" in f for f in findings), findings


def test_a_method_body_may_change_as_the_one_function() -> None:
    """A class method counts as one function, by its qualified name.

    The baseline's door in `first` stays where it was and is not the changed function's,
    so it is not reported here: `first` is the starting checkpoint's own unchanged text,
    the one place a forbidden builtin may still stand, and the rule reads the changed
    function and the code outside every function.
    """
    changed = BASELINE.replace(
        "        return value + LIMIT\n", "        return value + LIMIT + 0\n"
    )
    assert _findings(changed) == []


def test_a_forbidden_builtin_outside_every_function_is_named() -> None:
    """Module-level and class-level code runs at import; a builtin there is named.

    Such code is compared with the starting checkpoint as syntax, so the builtin was the
    starting checkpoint's own; the rule names it all the same, in both copies.
    """
    baseline = BASELINE.replace("LIMIT = 3\n", "LIMIT = len(open('x').read())\n")
    current = baseline.replace(
        '    return int(getattr(match, "group")(1))\n', "    return int(match.group(1))\n"
    )
    findings = fix_binding.diff_findings(baseline, current, "src/probe.py")
    assert any("`open` outside every function" in finding for finding in findings), findings
    class_docstring = '    """A class with one method."""\n'
    in_class = BASELINE.replace(class_docstring, class_docstring + "\n    reader = open\n")
    current = in_class.replace(
        '    return int(getattr(match, "group")(1))\n', "    return int(match.group(1))\n"
    )
    findings = fix_binding.diff_findings(in_class, current, "src/probe.py")
    assert any("`open` outside every function" in finding for finding in findings), findings
    # The module-level `re.compile(...)` pattern of the probe (and of the shipped files) is
    # an attribute, not the builtin by its name, and is not reported.
    assert _findings(FIXED) == []


def test_two_changed_functions_are_named() -> None:
    """A fix that touches two bodies is not bounded."""
    two = FIXED.replace("    return value * 2\n", "    return value + value\n")
    [finding] = _findings(two)
    assert "2 functions differ" in finding and "first, second" in finding


@pytest.mark.parametrize(
    "current, message",
    [
        (FIXED.replace("import re\n", "import re\nimport ast\n"), "`import ast` is an import"),
        (
            FIXED.replace("import re\n", "import re\nfrom operator import add\n"),
            "`from operator import add`",
        ),
        (FIXED.replace("LIMIT = 3\n", "LIMIT = 4\n"), "module-level statements differ"),
        (
            FIXED.replace('re.compile(r"(\\d+)")\n', 're.compile(r"(\\d+)+")\n'),
            "module-level",
        ),
        (FIXED + "\n\ndef helper() -> None:\n    return None\n", "module-level statements differ"),
        (FIXED.replace("class Holder:", "class Holder(dict):"), "module-level statements differ"),
        (
            FIXED.replace("class Holder:", "class Holder(metaclass=type):"),
            "module-level statements differ",
        ),
        (
            FIXED.replace("class Holder:", "@dataclass\nclass Holder:"),
            "module-level statements differ",
        ),
        (FIXED.replace("class Holder:", "class Holder[T]:"), "module-level statements differ"),
        (
            FIXED.replace(
                "def first(text: str) -> int:", "def first(text: str, strict: bool = False) -> int:"
            ),
            "changed its signature",
        ),
        (
            FIXED.replace("def first(text: str)", "@staticmethod\ndef first(text: str)"),
            "changed its signature",
        ),
        (
            FIXED.replace(
                "    return int(match.group(1))\n",
                "    exec('pass')\n    return int(match.group(1))\n",
            ),
            "a path the starting checkpoint's copy did not open",
        ),
    ],
    ids=[
        "import",
        "from-import",
        "constant",
        "pattern",
        "new-function",
        "class-base",
        "class-keyword",
        "class-decorator",
        "class-type-params",
        "signature",
        "decorator",
        "new-door",
    ],
)
def test_changes_beyond_one_body_are_named(current: str, message: str) -> None:
    """A new import, a module-level change, a new function, a changed head, a new door.

    A class head (its bases, keywords, decorators and type parameters) runs at import
    time and is part of the module-level statement compared. A door the baseline copy
    already had (the attribute reached by name that the fix removes) is not reported when
    it moves; a door of a kind the baseline did not have (`exec`) is.
    """
    findings = _findings(current)
    assert any(message in finding for finding in findings), findings


def test_a_removed_import_and_a_wrapped_line_are_not_findings() -> None:
    """Removing an unused import, or reflowing a statement, changes no syntax that counts."""
    without_import = FIXED.replace("import re\n", "").replace(
        '_PATTERN = re.compile(r"(\\d+)")', "_PATTERN = None"
    )
    # Removing `re` changes the pattern constant too, which is a module-level change; so
    # compare a removal alone: the baseline keeps the import, the current drops an unused one.
    baseline = BASELINE.replace("import re\n", "import re\nimport json\n")
    assert _findings(FIXED, baseline) == []
    assert any("module-level" in finding for finding in _findings(without_import))
    wrapped = FIXED.replace("LIMIT = 3\n", "LIMIT = (\n    3\n)\n")
    assert _findings(wrapped) == []


def test_syntax_errors_on_either_side_are_one_finding() -> None:
    """A file that does not parse is named, as the baseline or the current copy."""
    [finding] = _findings("def broken(:\n")
    assert "src/probe.py is not valid Python" in finding
    [finding] = fix_binding.diff_findings("def broken(:\n", FIXED, "src/probe.py")
    assert "at the starting checkpoint is not valid Python" in finding


def test_candidate_paths_leave_the_four_fixed_files_out() -> None:
    """Only paths beyond the four fixed permitted files are candidates, sorted."""
    changed = ["submission.yaml", "src/b.py", ".gitleaks.toml", "src/a.py", "security/gate.yaml"]
    assert fix_binding.candidate_paths(changed) == ["src/a.py", "src/b.py"]
    assert fix_binding.candidate_paths(list(fix_binding.FIXED_PERMITTED_PATHS)) == []


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(["git", *GIT_IDENTITY, *arguments], cwd=root, check=True, capture_output=True)


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    (root / "src").mkdir(parents=True)
    (root / "src/probe.py").write_text(BASELINE, encoding="utf-8")
    (root / "src/worker").mkdir()
    (root / "src/worker/config.py").write_text("X = 1\n", encoding="utf-8")
    (root / "notes.md").write_text("notes\n", encoding="utf-8")
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "add", "--all")
    _git(root, "commit", "--quiet", "-m", "Starting checkpoint")
    _git(root, "checkout", "--quiet", "-b", "work")
    return root


def test_over_a_repository_the_one_bounded_fix_passes_and_nothing_else_does(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The diff against the merge base: nothing changed, one bounded fix, then two files."""
    root = _repository(tmp_path)
    assert fix_binding.findings(root) == []
    assert fix_binding.main(["--root", str(root)]) == 0
    assert "nothing to check yet" in capsys.readouterr().out

    (root / "src/probe.py").write_text(FIXED, encoding="utf-8")
    (root / "src/worker/config.py").write_text("X = 2\n", encoding="utf-8")
    assert fix_binding.findings(root) == []
    assert fix_binding.main(["--root", str(root)]) == 0
    assert "src/probe.py differs from the starting checkpoint in the body of one function" in (
        capsys.readouterr().out
    )

    (root / "notes.md").write_text("edited\n", encoding="utf-8")
    findings = fix_binding.findings(root)
    assert any("2 files beyond the four fixed permitted files" in f for f in findings)
    assert any("notes.md: not a Python file" in f for f in findings)
    assert fix_binding.main(["--root", str(root)]) == 1

    (root / "notes.md").write_text("notes\n", encoding="utf-8")
    (root / "src/new.py").write_text("Y = 1\n", encoding="utf-8")
    _git(root, "add", "src/new.py")
    findings = fix_binding.findings(root)
    assert any("src/new.py: not a file of the starting checkpoint" in f for f in findings)


def test_a_nested_or_absent_repository_has_nothing_to_check(tmp_path: Path) -> None:
    """Outside a student checkout there is no history to diff, so nothing is checked."""
    assert fix_binding.findings(tmp_path) == []
