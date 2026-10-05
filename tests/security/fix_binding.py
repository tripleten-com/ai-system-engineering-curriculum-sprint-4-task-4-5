"""Coldline.

===================

File:              tests/security/fix_binding.py
Component:         Security tooling — Bounded diff of the fix file
Purpose:           Check, without importing it, that the one file changed beyond the four fixed
                    permitted files differs from the starting checkpoint in the body of one
                    function only, adds no import, holds no forbidden builtin and no dunder
                    name in that function, and opens no new path to the test runner.
Interacts With:    tests/security/repository.py, tests/security/static_rules.py,
                    tests/contract/test_security_contract.py, pyproject.toml (`poe fix-binding`,
                    `poe verify`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A bounded AST diff, a fix that stays inside the function the finding names, a
                    check that knows no finding
Tools:             Python 3.12, ast, Git

Task 4.5 permits four fixed files and one more: the file the finding in
``answers.fixed_finding`` names. That file is application Python the worker or the API
image carries, and this check bounds what may change in it, from the diff alone, without
knowing which finding, which function or which file: whatever file beyond the four has
changed since the starting checkpoint must

1. be a Python file that existed at the starting checkpoint, and be the only such file;
2. add no import: every import statement in the file is one the starting checkpoint's
   copy had (an import may be removed);
3. keep every module-level statement as it was (compared as syntax, so a comment or a
   wrapped line changes nothing): the same classes, with their bases, keywords,
   decorators and type parameters, the same functions, the same constants, in the same
   order;
4. differ in the body of exactly one function or method, with that function's name,
   signature and decorators unchanged: a candidate file whose functions all parse the
   same as the starting checkpoint's (a comment, a scanner suppression marker such as
   ``# nosemgrep``, or a reflowed line) is not a fix and is a finding;
5. open no door the starting checkpoint's copy did not have: the reach rules of
   ``tests/security/static_rules.py`` are applied to the changed file and to its
   starting-checkpoint copy, and only a finding new to the changed file counts;
6. hold no forbidden builtin: none of ``open``, ``exec``, ``eval``, ``compile``,
   ``__import__``, ``getattr``, ``setattr``, ``delattr``, ``globals``, ``vars``,
   ``locals``, ``input`` or ``breakpoint`` (``FORBIDDEN_BUILTINS``, the builtins that read
   or write files, run text as code or reach a namespace by name) anywhere in the changed
   function, called, handed on or reached as an attribute, whatever the starting
   checkpoint's copy held (a fix that keeps the operation under another name,
   ``f = eval; f(x)``, is a finding, and the baseline's findings are not subtracted), and
   none by its own name anywhere else in the file outside a function whose body is the
   starting checkpoint's own, unchanged text. Every statement outside the changed
   function is compared with the starting checkpoint as syntax (rules 3 and 4), so the
   only place a builtin can stand that this rule does not name is a function the fix left
   exactly as the starting checkpoint wrote it;
7. spell no dunder name in the changed function: no ``__name__`` as a name, an attribute,
   a nested function's or parameter's name (``__class__``, ``__builtins__``, ``__globals__``
   and the rest), because a dunder reaches the module's own loader and builtins and
   through them the file system.

The assessed module's own row then confirms, with the scanners, that the finding named
in ``answers.fixed_finding`` was reported in that file on the starting checkpoint and that a
finding is gone from it. When nothing beyond the four fixed files has changed, there is
nothing here to check (the starter, or a tree before its fix). ``python -m
tests.security.fix_binding`` (``poe fix-binding``) prints the findings and exits 1 when
there is one, 2 when the checkout's history cannot be read.
"""

from __future__ import annotations

import argparse
import ast
import sys
from collections.abc import Iterable
from pathlib import Path

from tests.security import repository, static_rules

TASK_ROOT = Path(__file__).resolve().parents[2]
# The four permitted files every submission may change; the fifth is resolved per sheet.
FIXED_PERMITTED_PATHS: tuple[str, ...] = (
    "src/worker/config.py",
    "security/gate.yaml",
    ".gitleaks.toml",
    "submission.yaml",
)
BOUND_HINT = (
    "the fix stays inside the body of the one function the finding names; nothing else in "
    "the file, and no other file beyond the four permitted ones, may change"
)
# Rule 6: the builtins the fix may not hold, in any form: they read or write files, run
# text as code or reach a namespace by name.
FORBIDDEN_BUILTINS: tuple[str, ...] = (
    "open",
    "exec",
    "eval",
    "compile",
    "__import__",
    "getattr",
    "setattr",
    "delattr",
    "globals",
    "vars",
    "locals",
    "input",
    "breakpoint",
)
DYNAMIC_HINT = (
    "the fix holds none of open, exec, eval, compile, __import__, getattr, setattr, delattr, "
    "globals, vars, locals, input or breakpoint, called, handed on or reached as an "
    "attribute, and the fixed function spells no dunder name"
)


class FixBindingError(RuntimeError):
    """Report that the checkout's history could not be read, as opposed to a finding."""


def candidate_paths(changed: list[str]) -> list[str]:
    """Return the changed paths beyond the four fixed permitted files, sorted."""
    return sorted(set(changed) - set(FIXED_PERMITTED_PATHS))


def _import_statements(tree: ast.Module) -> set[str]:
    """Return every import in the tree as one string per imported name."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else ""))
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            for alias in node.names:
                suffix = f" as {alias.asname}" if alias.asname else ""
                found.add(f"from {module} import {alias.name}{suffix}")
    return found


def _is_import(node: ast.stmt) -> bool:
    return isinstance(node, ast.Import | ast.ImportFrom)


def _signature(node: ast.stmt) -> str:
    """Return a module-level statement's structural signature."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return f"def {node.name}"
    if isinstance(node, ast.ClassDef):
        # The class head runs when the module is imported: a base, a keyword (a metaclass
        # among them), a decorator or a type parameter is part of the statement compared.
        head = ";".join(
            ast.dump(item)
            for item in (
                *node.decorator_list,
                *node.bases,
                *node.keywords,
                *getattr(node, "type_params", []),
            )
        )
        methods = ",".join(
            item.name
            for item in node.body
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
        )
        others = ";".join(
            ast.dump(item)
            for item in node.body
            if not isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
        )
        return f"class {node.name}<{head}>({methods})[{others}]"
    return ast.dump(node)


def _functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Return every module-level function and every class method, by qualified name."""
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                    found[f"{node.name}.{item.name}"] = item
    return found


def _head(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """Return a function's name, signature and decorators as one string."""
    returns = ast.dump(node.returns) if node.returns is not None else ""
    decorators = ";".join(ast.dump(item) for item in node.decorator_list)
    kind = "async" if isinstance(node, ast.AsyncFunctionDef) else "def"
    return f"{kind} {node.name}({ast.dump(node.args)})->{returns}@{decorators}"


def _forbidden_builtin(item: ast.AST) -> str | None:
    """Return the forbidden builtin one node spells, as a name or an attribute, or None."""
    if isinstance(item, ast.Name) and item.id in FORBIDDEN_BUILTINS:
        return item.id
    if isinstance(item, ast.Attribute) and item.attr in FORBIDDEN_BUILTINS:
        return item.attr
    return None


def _dunder_names(item: ast.AST) -> list[str]:
    """Return the dunder names one node spells: a name, an attribute, a definition, a parameter."""
    names: list[str] = []
    if isinstance(item, ast.Name):
        names.append(item.id)
    elif isinstance(item, ast.Attribute):
        names.append(item.attr)
    elif isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        names.append(item.name)
    elif isinstance(item, ast.arg):
        names.append(item.arg)
    return [name for name in names if static_rules.is_dunder(name)]


def dynamic_operation_findings(
    node: ast.FunctionDef | ast.AsyncFunctionDef, name: str
) -> list[str]:
    """Return every forbidden builtin and every dunder name the changed function holds.

    Rules 6 and 7, in any form, whatever the starting checkpoint's copy of the function
    held: nothing is subtracted for the baseline.
    """
    findings: list[str] = []
    for item in ast.walk(node):
        spelled = _forbidden_builtin(item)
        if spelled is not None:
            findings.append(
                f"{static_rules.line(item)}: `{spelled}` in `{name}`, the one changed "
                f"function; {DYNAMIC_HINT}; {BOUND_HINT}"
            )
        for dunder in _dunder_names(item):
            findings.append(
                f"{static_rules.line(item)}: the dunder name `{dunder}` in `{name}`, the one "
                f"changed function; {DYNAMIC_HINT}; {BOUND_HINT}"
            )
    return findings


def builtin_findings_outside_functions(
    tree: ast.Module, functions: Iterable[ast.FunctionDef | ast.AsyncFunctionDef]
) -> list[str]:
    """Return every forbidden builtin, by its own name, outside every function (rule 6).

    Module-level and class-level code runs when the file is imported. Everything there
    is compared with the starting checkpoint as syntax, so a builtin reported here was
    the starting checkpoint's own; the rule names it all the same, so the file holds one
    of the forbidden builtins only inside a function the fix did not touch. Only the
    builtin's own name counts here: an attribute such as the ``re.compile`` of a
    module-level pattern is the starting checkpoint's own compiled expression, and the
    attribute form is judged inside the changed function.
    """
    inside = {id(item) for function in functions for item in ast.walk(function)}
    findings: list[str] = []
    for item in ast.walk(tree):
        if id(item) in inside or not isinstance(item, ast.Name):
            continue
        spelled = _forbidden_builtin(item)
        if spelled is not None:
            findings.append(
                f"{static_rules.line(item)}: `{spelled}` outside every function, in code "
                f"that runs when the file is imported; {DYNAMIC_HINT}; {BOUND_HINT}"
            )
    return findings


def diff_findings(baseline_source: str, current_source: str, path: str) -> list[str]:
    """Return every way ``current_source`` changes ``path`` beyond one function's body."""
    baseline = static_rules.parse(baseline_source, f"{path} at the starting checkpoint")
    current = static_rules.parse(current_source, path)
    if isinstance(baseline, list):
        return baseline
    if isinstance(current, list):
        return current
    findings: list[str] = []
    for statement in sorted(_import_statements(current) - _import_statements(baseline)):
        findings.append(
            f"`{statement}` is an import the starting checkpoint's copy did not have; the "
            f"fix adds no import; {BOUND_HINT}"
        )
    new_reach = static_rules.without_lines(static_rules.reach_findings(current)) - (
        static_rules.without_lines(static_rules.reach_findings(baseline))
    )
    for finding in sorted(new_reach):
        findings.append(f"a path the starting checkpoint's copy did not open: {finding}")
    before = [_signature(node) for node in baseline.body if not _is_import(node)]
    after = [_signature(node) for node in current.body if not _is_import(node)]
    if before != after:
        findings.append(
            "the module-level statements differ from the starting checkpoint's (a class, a "
            f"function, a constant or their order changed, or one was added or removed); "
            f"{BOUND_HINT}"
        )
        return findings
    baseline_functions = _functions(baseline)
    current_functions = _functions(current)
    changed = [
        name
        for name, node in baseline_functions.items()
        if name in current_functions and ast.dump(node) != ast.dump(current_functions[name])
    ]
    if not changed:
        findings.append(
            "no function body differs from the starting checkpoint's copy as syntax (a "
            "comment, a scanner suppression marker or a reflowed line is not a fix); the fix "
            f"changes the body of the one function the finding names; {BOUND_HINT}"
        )
    elif len(changed) > 1:
        findings.append(
            f"{len(changed)} functions differ from the starting checkpoint "
            f"({', '.join(changed)}); exactly one may; {BOUND_HINT}"
        )
    else:
        name = changed[0]
        if _head(baseline_functions[name]) != _head(current_functions[name]):
            findings.append(
                f"`{name}` changed its signature, return annotation or decorators; the fix "
                f"changes the body only; {BOUND_HINT}"
            )
        findings.extend(dynamic_operation_findings(current_functions[name], name))
    findings.extend(builtin_findings_outside_functions(current, current_functions.values()))
    return findings


def findings(root: Path = TASK_ROOT) -> list[str]:
    """Return the findings for the changed file beyond the four fixed permitted files."""
    try:
        changed = repository.changed_paths(root)
    except repository.RepositoryError as exc:
        raise FixBindingError(str(exc)) from exc
    candidates = candidate_paths(changed)
    if not candidates:
        return []
    found: list[str] = []
    if len(candidates) > 1:
        found.append(
            f"{len(candidates)} files beyond the four fixed permitted files changed "
            f"({', '.join(candidates)}); only the one file the fixed finding names may"
        )
    for path in candidates:
        if not path.endswith(".py"):
            found.append(f"{path}: not a Python file; the fixed finding names a Python file")
            continue
        try:
            baseline = repository.baseline_text(root, path)
        except repository.RepositoryError as exc:
            raise FixBindingError(str(exc)) from exc
        if baseline is None:
            found.append(f"{path}: not a file of the starting checkpoint; the fix changes one")
            continue
        current_path = root / path
        if not current_path.is_file():
            found.append(f"{path}: removed; the fix changes the file, it does not remove it")
            continue
        try:
            current = current_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            found.append(f"{path}: could not be read as UTF-8 text: {exc}")
            continue
        found.extend(f"{path}: {item}" for item in diff_findings(baseline, current, path))
    return static_rules.deduplicated(found)


def main(argv: list[str] | None = None) -> int:
    """Check the changed file beyond the four permitted ones and print the findings."""
    parser = argparse.ArgumentParser(
        description=(
            "Check that the one file changed beyond the four fixed permitted files differs "
            "in one function's body only and adds no import."
        )
    )
    parser.add_argument("--root", type=Path, default=TASK_ROOT)
    arguments = parser.parse_args(argv)
    try:
        changed = repository.changed_paths(arguments.root)
        found = findings(arguments.root)
    except (FixBindingError, repository.RepositoryError) as exc:
        print(f"fix-binding: {exc}", file=sys.stderr)
        return 2
    candidates = candidate_paths(changed)
    if found:
        print(
            "fix-binding: the change beyond the four fixed permitted files is not bounded:",
            file=sys.stderr,
        )
        for finding in found:
            print(f"- {finding}", file=sys.stderr)
        return 1
    if not candidates:
        print(
            "fix-binding: no file beyond the four fixed permitted files has changed since the "
            "starting checkpoint; nothing to check yet."
        )
        return 0
    print(
        f"fix-binding: {candidates[0]} differs from the starting checkpoint in the body of one "
        "function only, adds no import, holds no forbidden builtin and no dunder name in that "
        "function, and opens no new path beyond application code."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
