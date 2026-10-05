"""Coldline.

===================

File:              tests/security/static_rules.py
Component:         Security tooling — Shared static rules for student-editable Python
Purpose:           The import allowlist and the reach rules both Task 4.5 binding checks apply to a
                    student-editable application file, read as bytes and never imported.
Interacts With:    tests/security/config_binding.py, tests/security/fix_binding.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Trusted static analysis, a closed import set, a closed reach for application
                    code
Tools:             Python 3.12, ast

Task 4.4's worker-binding check closed, rule by rule, every spelled path from a
student-editable application module to the test runner, the interpreter's module table,
or another module's bindings: no runner module imported in any form or reached through
another module, no dynamic name, no three-argument ``type(...)``, no dunder attribute, no
frame access, and an import allowlist of exactly the starter's imports plus the ones the
lesson adds. Task 4.5 has two such files (``src/worker/config.py`` and the one file the
fixed finding names), so the rules live here once and each check supplies its allowlist.

The rules are syntactic: they close the spelled doors. ``reach_findings`` returns rules 6
to 8 of the Task 4.4 check; ``import_allowlist_findings`` returns rule 9 for the statements
a caller permits; ``rebinding_door_findings`` returns rule 4. ``without_lines`` strips the
``line N:`` prefix so two files' findings can be compared as sets.
"""

from __future__ import annotations

import ast
import re

# Modules whose import gives application code a path to the test runner, the interpreter's
# module table, or another module's bindings. The top-level name is matched, so every
# submodule (`_pytest.reports`, `importlib.util`, `ctypes.util`, `unittest.mock`) is
# covered. `unittest` is here for `unittest.mock`; `mock` is the same library's standalone
# distribution.
MODULE_TABLE = "modules"
RUNNER_MODULES: frozenset[str] = frozenset(
    {
        "pytest",
        "_pytest",
        "sys",
        "importlib",
        "builtins",
        "gc",
        "inspect",
        "ctypes",
        "types",
        "runpy",
        "unittest",
        "mock",
    }
)
# Names that run text as code, rebind a name at runtime, or reach an attribute or a whole
# namespace by a string; none has a place in application code, as a call or handed on.
DYNAMIC_NAMES: frozenset[str] = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "__import__",
        "globals",
        "locals",
        "vars",
        "dir",
        "getattr",
        "setattr",
        "delattr",
        "__builtins__",
    }
)
# `type(name, bases, namespace)` builds a class at runtime; the one-argument form stays.
CLASS_BUILDER = "type"
CLASS_BUILDER_ARGUMENTS = 3
# The dunder attributes the reach rule names first; every other dunder attribute is refused
# the same way (`is_dunder`).
INTERNAL_ATTRIBUTES: frozenset[str] = frozenset(
    {"__dict__", "__globals__", "__code__", "__builtins__", "__class__"}
)
# The names that reach a frame or what a frame holds.
FRAME_NAMES: frozenset[str] = frozenset(
    {
        "currentframe",
        "_getframe",
        "f_builtins",
        "f_globals",
        "f_locals",
        "f_back",
        "f_code",
        "tb_frame",
        "gi_frame",
        "cr_frame",
        "ag_frame",
    }
)
# Names that rebind a module or a global at runtime beyond the dynamic names.
REBINDING_NAMES: frozenset[str] = frozenset({"importlib", "sys", "builtins", "modules"})
REACH_HINT = (
    "application code must not reach the test runner, the interpreter's module table, or "
    "another module's bindings"
)
_LINE_PREFIX = re.compile(r"^line \d+: ")


def line(node: ast.AST) -> str:
    """Return ``line N`` for a node, for a finding."""
    return f"line {getattr(node, 'lineno', '?')}"


def is_dunder(name: str) -> bool:
    """Return whether ``name`` is a dunder (``__dict__``)."""
    return len(name) > 4 and name.startswith("__") and name.endswith("__")


def top_module(dotted: str) -> str:
    """Return the first component of a dotted module path."""
    return dotted.split(".", 1)[0]


def without_lines(findings: list[str]) -> frozenset[str]:
    """Return the findings with their ``line N:`` prefix removed, as a set."""
    return frozenset(_LINE_PREFIX.sub("", finding) for finding in findings)


def permitted_tables(
    statements: tuple[str, ...],
) -> tuple[frozenset[str], dict[str, frozenset[str]]]:
    """Return the permitted plain-import modules and, per module, the permitted names.

    Each statement is parsed as Python, so a tuple cannot drift from what the rule
    applies; a statement that is not one import, or carries an alias, is a programming
    error and is refused at import time.
    """
    modules: set[str] = set()
    names: dict[str, set[str]] = {}
    for statement in statements:
        [node] = ast.parse(statement).body
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    raise ValueError(f"a permitted import carries an alias: {statement!r}")
                modules.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for alias in node.names:
                if alias.asname is not None or alias.name == "*":
                    raise ValueError(f"a permitted import carries an alias or `*`: {statement!r}")
                names.setdefault(node.module, set()).add(alias.name)
        else:
            raise ValueError(f"a permitted statement is no import: {statement}")
    return frozenset(modules), {module: frozenset(found) for module, found in names.items()}


def import_allowlist_findings(
    tree: ast.Module, statements: tuple[str, ...], hint: str
) -> list[str]:
    """Return every import that is not one of the permitted imports under its own name.

    A plain import of a module not on the list, a ``from`` import of a module not on the
    list or of a name the list does not give for that module, a relative import, a ``*``
    import and an alias of a permitted import are each a finding. The import's own text
    is quoted; nothing else of the file is.
    """
    modules, names = permitted_tables(statements)
    findings: list[str] = []

    def outside(node: ast.AST, what: str) -> None:
        findings.append(f"{line(node)}: `{ast.unparse(node)}` {what} the import allowlist; {hint}")

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname is not None:
                    outside(node, f"aliases `{alias.name}`, which is not permitted by")
                elif alias.name not in modules:
                    outside(node, "is not in")
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                outside(node, "is a relative import, which is not in")
                continue
            permitted = names.get(node.module)
            if permitted is None:
                outside(node, "is not in")
                continue
            for alias in node.names:
                if alias.asname is not None:
                    outside(node, f"aliases `{alias.name}`, which is not permitted by")
                elif alias.name == "*":
                    outside(node, "imports every name, which is not permitted by")
                elif alias.name not in permitted:
                    outside(node, f"imports `{alias.name}`, which is not in")
    return findings


def rebinding_door_findings(tree: ast.Module) -> list[str]:
    """Return every use of a name that rebinds a module or a global at runtime."""
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and (
            node.attr in REBINDING_NAMES
            or (isinstance(node.value, ast.Name) and node.value.id in REBINDING_NAMES)
        ):
            findings.append(
                f"{line(node)}: `{ast.unparse(node)}` is not permitted in application code; "
                "it can rebind a module or a global at runtime"
            )
        if isinstance(node, ast.Name) and node.id in REBINDING_NAMES and node.id != MODULE_TABLE:
            findings.append(
                f"{line(node)}: `{node.id}` is not permitted in application code; it can rebind "
                "a module or a global at runtime"
            )
    return findings


def _builds_a_class(node: ast.Call) -> bool:
    """Return whether a call is ``type(...)`` with three arguments (or a starred argument)."""
    if not (isinstance(node.func, ast.Name) and node.func.id == CLASS_BUILDER):
        return False
    starred = any(isinstance(argument, ast.Starred) for argument in node.args)
    return starred or len(node.args) >= CLASS_BUILDER_ARGUMENTS


def reach_findings(tree: ast.Module) -> list[str]:
    """Return every spelled path from the file to the runner or another module's bindings.

    An import of a runner module or a submodule of one, a runner module reached by name
    or attribute through another module, a dynamic name in any position, the
    three-argument ``type(...)`` call, a dunder attribute access, and a frame name as an
    attribute or a name.
    """
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _builds_a_class(node):
            findings.append(
                f"{line(node)}: `{CLASS_BUILDER}(...)` with three arguments is not permitted "
                f"in application code; it builds a class at runtime; {REACH_HINT}"
            )
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if top_module(alias.name) in RUNNER_MODULES:
                    findings.append(
                        f"{line(node)}: `import {alias.name}` is not permitted in application "
                        f"code; the module can reach the test runner or rebind a module or a "
                        f"global at runtime; {REACH_HINT}"
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and top_module(node.module or "") in RUNNER_MODULES:
                names = ", ".join(alias.name for alias in node.names)
                findings.append(
                    f"{line(node)}: `from {node.module} import {names}` is not permitted in "
                    f"application code; the module can reach the test runner or rebind a module "
                    f"or a global at runtime; {REACH_HINT}"
                )
            else:
                for alias in node.names:
                    if alias.name in RUNNER_MODULES or alias.name == MODULE_TABLE:
                        findings.append(
                            f"{line(node)}: importing `{alias.name}` from `{node.module}` is "
                            f"not permitted in application code; a runner module reached "
                            f"through another module is the same door; {REACH_HINT}"
                        )
        elif isinstance(node, ast.Name) and node.id in DYNAMIC_NAMES:
            findings.append(
                f"{line(node)}: `{node.id}` is not permitted in application code; it runs text "
                f"as code, rebinds a module or a global at runtime, or reaches an attribute or "
                f"a namespace by a string; {REACH_HINT}"
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in RUNNER_MODULES or node.attr == MODULE_TABLE
        ):
            findings.append(
                f"{line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"runner module or the module table reached as another module's attribute is "
                f"the same door as importing it; {REACH_HINT}"
            )
        elif isinstance(node, ast.Attribute) and (
            node.attr in INTERNAL_ATTRIBUTES or is_dunder(node.attr)
        ):
            findings.append(
                f"{line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"dunder attribute reaches a module's, a class's or a function's bindings; "
                f"{REACH_HINT}"
            )
        elif (isinstance(node, ast.Attribute) and node.attr in FRAME_NAMES) or (
            isinstance(node, ast.Name) and node.id in FRAME_NAMES
        ):
            findings.append(
                f"{line(node)}: `{ast.unparse(node)}` is not permitted in application code; a "
                f"frame, its builtins, globals or locals, or the frame of a traceback, a "
                f"generator or a coroutine reaches the interpreter's bindings; {REACH_HINT}"
            )
    return findings


def parse(source: str | bytes, label: str) -> ast.Module | list[str]:
    """Parse one file's source, or return the one finding that says why it cannot be read."""
    try:
        return ast.parse(source)
    except SyntaxError as exc:
        return [f"{label} is not valid Python: {exc}"]
    except ValueError as exc:
        return [f"{label} could not be decoded as UTF-8: {exc}"]


def deduplicated(findings: list[str]) -> list[str]:
    """Return the findings in first position, each once."""
    seen: set[str] = set()
    ordered: list[str] = []
    for finding in findings:
        if finding not in seen:
            seen.add(finding)
            ordered.append(finding)
    return ordered
