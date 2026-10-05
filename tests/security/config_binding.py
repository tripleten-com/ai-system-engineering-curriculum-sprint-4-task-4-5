"""Coldline.

===================

File:              tests/security/config_binding.py
Component:         Security tooling — Static binding check of the worker's settings module
Purpose:           Check, without importing it, that src/worker/config.py reaches the key only
                    through the supplied SecretProvider adapter: no key literal, an awaitable
                    per-use read with the starter's signature, the starter's imports plus the
                    supplied ones, the one settings class in the starter's shape, no dunder
                    name, builtin annotations only, and no spelled path to the test runner.
Interacts With:    src/worker/config.py, src/adapters/secrets/localstack.py,
                    tests/security/static_rules.py, tests/contract/test_security_contract.py,
                    pyproject.toml (`poe config-binding`, `poe verify`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Trusted static analysis before the worker image is built, no literal in the
                    key's place, a closed import set
Tools:             Python 3.12, ast

``src/worker/config.py`` is student-editable Python that the worker image carries and the
assessed checks' subprocesses import. This check reads it as bytes, parses it, and
requires:

1. an **import allowlist**: the file imports exactly what the shipped starter imports
   (``from pydantic import Field``, ``from pydantic_settings import BaseSettings,
   SettingsConfigDict``) plus the supplied SecretProvider imports (``from adapters.secrets
   import PROVIDER_KEY_SECRET_NAME, secret_provider``, and ``from ports import
   SecretProvider`` for an annotation), each name under its own name; any other module, any
   other name, a relative or ``*`` import or an alias is a finding;
2. the **reach rules** of ``tests/security/static_rules.py``: no runner module, no dynamic
   name, no three-argument ``type(...)``, no dunder attribute, no frame access, nothing
   that rebinds a module at runtime;
3. **no key literal**: no string literal anywhere in the file equal to the first version's
   value (the committed literal the starting checkpoint carried; the live check also
   compares against every version the store holds); no field ``model_provider_key`` with a
   string default or a default factory, which is the literal's place; and, inside
   ``provider_key``, no string literal other than the secret's name, so the read cannot
   return, or build, a value written in the file;
4. the **per-use read**: ``WorkerSettings`` defines ``provider_key`` as an ``async def``
   method (the model client awaits it for every request) with the starter's signature,
   ``async def provider_key(self) -> str``: no decorator, no other parameter and no default
   expression (a decorator and a default run when the class is built);
5. **no import-time door**: the file is imported by the worker image and by the pytest
   process that judges it, so nothing in it may run at import time beyond what a settings
   module needs. No builtin that reads or writes the file system, runs text as code or
   reaches a namespace by name is called or handed on anywhere in the file
   (``FORBIDDEN_BUILTINS``: ``open``, ``exec``, ``eval``, ``compile``, ``__import__``,
   ``getattr``, ``setattr``, ``delattr``, ``globals``, ``vars``, ``locals``, ``dir``,
   ``input``, ``breakpoint``), and every module-level statement is one of: the docstring,
   an import, a class definition, or an assignment of a literal (or a display of literals)
   or of a name one of the permitted imports binds, annotated, if at all, with a builtin
   type (rule 8). A module-level call, ``if``, ``try``, ``with``, loop or function
   definition is a finding;
6. **one class, the starter's shape**: ``WorkerSettings`` is the only class in the file,
   anywhere, with the starter's base (``BaseSettings``), no decorator and no class keyword,
   and its body holds nothing but the docstring, annotated field assignments whose value is
   a literal, a display of literals, a name a permitted import binds or a ``Field(...)`` or
   ``SettingsConfigDict(...)`` call over such values (an inert cache attribute such as
   ``_cache: list[str] = []`` is one of these), the ``model_config`` assignment, and the
   ``provider_key`` method. A second class, a nested class, another method, a call or any
   other statement in the class body is a finding, because the class body runs at import
   time like the module level does;
7. **no dunder name**: no name of the form ``__name__`` anywhere in the file, as a name, an
   attribute, a function or argument name or an import (``__loader__``, ``__spec__``,
   ``__builtins__``, ``__dict__`` and the rest), because the module's own dunder globals
   reach the import system and through it the file system;
8. **builtin annotations only**: pydantic evaluates a field's annotation when the settings
   class is built, and a string annotation is evaluated as code, so no annotation anywhere
   in the file is a string constant or holds a call (a subscript of a call included), and
   every annotated field, cache attribute or module-level name is annotated with a builtin
   type name (``str``, ``int``, ``float``, ``bool``, ``None``, ``dict``, ``list``,
   ``tuple``), a ``dict``, ``list`` or ``tuple`` over such names, or a union of them written
   with ``|`` (``model_config`` may be annotated ``SettingsConfigDict``). The supplied
   ``SecretProvider`` import annotates a local inside ``provider_key``, which no class
   build evaluates.

The rules are syntactic and say nothing about *when* the read happens: a read made once
and kept passes them and fails the live replacement row of the assessed module, which is
where that is judged. They also stop short of one stronger measure that was weighed and
not taken: running the student's module in a process with no write access to the checks'
files (a sandbox the Task's runtime does not have). What the rules leave open is recorded
as residual risk in the authoring report.
``python -m tests.security.config_binding`` (``poe config-binding``) prints the findings and
exits 1 when there is one.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import TypeGuard

from tests.security import static_rules

TASK_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = Path("src/worker/config.py")
SETTINGS_CLASS = "WorkerSettings"
KEY_READ = "provider_key"
KEY_FIELD = "model_provider_key"
FIELD_FACTORY = "Field"
# The first version's value, the committed literal the starting checkpoint carries. Kept here
# as a constant rather than imported, so this check imports nothing from `src/` (it runs
# before the worker is imported anywhere) and still names the one value the file must not
# hold. The live row re-reads every version from the store.
FIRST_VERSION_VALUE = "coldline-dev-provider-key-v1"
# The secret's name: the one string literal the key read may hold.
PROVIDER_KEY_SECRET_NAME = "coldline/worker/model-provider-key"
# Rule 1: the shipped starter's imports plus the supplied SecretProvider imports.
PERMITTED_IMPORTS: tuple[str, ...] = (
    "from pydantic import Field",
    "from pydantic_settings import BaseSettings, SettingsConfigDict",
    "from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider",
    "from ports import SecretProvider",
)
ALLOWLIST_HINT = (
    "src/worker/config.py may import exactly what the starter imports plus the supplied "
    "SecretProvider imports (`from adapters.secrets import PROVIDER_KEY_SECRET_NAME, "
    "secret_provider` and `from ports import SecretProvider`), each name under its own name"
)
LITERAL_HINT = (
    "the key is read through the supplied SecretProvider adapter when the worker needs it; "
    "no version's value is written in this file"
)
# Rule 5: builtins that read or write files, run text as code, or reach a namespace by
# name. Eleven of them are reach rules already (static_rules.DYNAMIC_NAMES, reported
# wherever the name appears); `open`, `input` and `breakpoint` are added here, and a call
# to any of the fourteen is reported by this rule by its own name.
FORBIDDEN_BUILTINS: frozenset[str] = frozenset(
    {
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
        "dir",
        "input",
        "breakpoint",
    }
)
IMPORT_TIME_HINT = (
    "src/worker/config.py runs at import time in the worker image and in the process that "
    "judges it; it holds imports, class definitions and literal assignments only"
)
# Rule 6: the one class, with the starter's head, and what its body may hold.
STARTER_BASES: tuple[str, ...] = ("BaseSettings",)
MODEL_CONFIG = "model_config"
# The two permitted-import names the class body may call, over inert arguments: the
# pydantic field and settings-configuration factories the starter's fields use.
FIELD_CALLS: frozenset[str] = frozenset({FIELD_FACTORY, "SettingsConfigDict"})
CLASS_HINT = (
    "src/worker/config.py defines the one class `WorkerSettings`, with the starter's base and "
    "no decorator, whose body holds its fields, `model_config` and `provider_key` only"
)
DUNDER_HINT = (
    "a dunder name reaches the module's own loader, spec or builtins, and through them the "
    "import system and the file system; none has a place in the settings module"
)
# Rule 4: the starter's head of the key read, as `ast.unparse` writes it.
STARTER_READ_HEAD = f"async def {KEY_READ}(self) -> str"
READ_HEAD_HINT = (
    f"`{KEY_READ}` keeps the starter's signature, `{STARTER_READ_HEAD}:`, with no decorator, "
    "no other parameter and no default expression; a decorator and a default run when the "
    "class is built"
)
# Rule 8: the annotations a field, a cache attribute or a module-level name may carry.
# Pydantic evaluates a field's annotation when the settings class is built, and a string
# annotation is evaluated as code, so an annotation is a builtin type name, `None`, a
# `dict`, `list` or `tuple` over such names, or a union of them written with `|`.
BUILTIN_ANNOTATIONS: frozenset[str] = frozenset(
    {"str", "int", "float", "bool", "dict", "list", "tuple"}
)
GENERIC_ANNOTATIONS: frozenset[str] = frozenset({"dict", "list", "tuple"})
MODEL_CONFIG_ANNOTATION = "SettingsConfigDict"
ANNOTATION_HINT = (
    "an annotation is evaluated when the settings class is built, a string annotation as "
    "code; a field, a cache attribute or a module-level name is annotated with a builtin type "
    "name (str, int, float, bool, None, dict, list, tuple), a dict, list or tuple over such "
    "names, or a union of them written with `|`, and no annotation anywhere is a string or "
    "holds a call"
)


class ConfigBindingError(ValueError):
    """Report that the settings file could not be read, as opposed to a finding about it."""


def _settings_class(tree: ast.Module) -> ast.ClassDef | None:
    """Return the module-level ``WorkerSettings`` class, or None."""
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == SETTINGS_CLASS:
            return node
    return None


def _key_read(settings: ast.ClassDef) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Return the ``provider_key`` method of the settings class, or None."""
    for node in settings.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == KEY_READ:
            return node
    return None


def _is_string(node: ast.AST) -> TypeGuard[ast.Constant]:
    """Return whether a node is a string constant."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _field_holds_a_literal(value: ast.expr) -> bool:
    """Return whether an annotated field's value is a string literal or a Field with one."""
    if _is_string(value):
        return True
    if not (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)):
        return False
    if value.func.id != FIELD_FACTORY:
        return False
    if any(_is_string(argument) for argument in value.args):
        return True
    for keyword in value.keywords:
        if keyword.arg == "default" and _is_string(keyword.value):
            return True
        if keyword.arg == "default_factory":
            return True
    return False


def literal_findings(tree: ast.Module) -> list[str]:
    """Return every key literal (rule 3): the value anywhere, the field's default, the read's."""
    findings: list[str] = []
    for node in ast.walk(tree):
        if _is_string(node) and node.value == FIRST_VERSION_VALUE:
            findings.append(
                f"{static_rules.line(node)}: a string literal equal to the first version's "
                f"value; {LITERAL_HINT}"
            )
    settings = _settings_class(tree)
    if settings is None:
        return findings
    for node in settings.body:
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == KEY_FIELD
            and node.value is not None
            and _field_holds_a_literal(node.value)
        ):
            findings.append(
                f"{static_rules.line(node)}: the field `{KEY_FIELD}` holds a literal or a "
                f"default factory in the key's place; {LITERAL_HINT}"
            )
        elif (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == KEY_FIELD for target in node.targets
            )
            and _field_holds_a_literal(node.value)
        ):
            findings.append(
                f"{static_rules.line(node)}: `{KEY_FIELD}` holds a literal in the key's place; "
                f"{LITERAL_HINT}"
            )
    read = _key_read(settings)
    if read is None:
        return findings
    body = list(read.body)
    if body and isinstance(body[0], ast.Expr) and _is_string(body[0].value):
        body = body[1:]
    for statement in body:
        for node in ast.walk(statement):
            if _is_string(node) and node.value != PROVIDER_KEY_SECRET_NAME:
                findings.append(
                    f"{static_rules.line(node)}: a string literal inside `{KEY_READ}` other "
                    f"than the secret's name is a value in the key's place; {LITERAL_HINT}"
                )
    return findings


def read_findings(tree: ast.Module) -> list[str]:
    """Return why ``WorkerSettings.provider_key`` is not an awaitable per-use read (rule 4)."""
    settings = _settings_class(tree)
    if settings is None:
        return [f"the file defines no module-level class `{SETTINGS_CLASS}`"]
    read = _key_read(settings)
    if read is None:
        return [
            f"`{SETTINGS_CLASS}` defines no `{KEY_READ}` method; the model client awaits "
            f"`settings.{KEY_READ}()` for every request"
        ]
    if isinstance(read, ast.FunctionDef):
        return [
            f"{static_rules.line(read)}: `{KEY_READ}` must be `async def`; the model client "
            "awaits it for every request"
        ]
    returns = ast.unparse(read.returns) if read.returns is not None else ""
    head = f"async def {read.name}({ast.unparse(read.args)}) -> {returns}"
    if head != STARTER_READ_HEAD or read.decorator_list or getattr(read, "type_params", []):
        return [
            f"{static_rules.line(read)}: `{KEY_READ}` changed its signature, decorators or "
            f"return annotation; {READ_HEAD_HINT}"
        ]
    return []


def _is_builtin_annotation(node: ast.AST) -> bool:
    """Return whether an annotation is a builtin type name, a generic over them or a union."""
    if isinstance(node, ast.Constant):
        return node.value is None
    if isinstance(node, ast.Name):
        return node.id in BUILTIN_ANNOTATIONS
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _is_builtin_annotation(node.left) and _is_builtin_annotation(node.right)
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id not in GENERIC_ANNOTATIONS:
            return False
        parameters = node.slice.elts if isinstance(node.slice, ast.Tuple) else [node.slice]
        return all(
            (isinstance(parameter, ast.Constant) and parameter.value is Ellipsis)
            or _is_builtin_annotation(parameter)
            for parameter in parameters
        )
    return False


def _is_model_config_annotation(statement: ast.AnnAssign) -> bool:
    """Return whether an annotated assignment is ``model_config: SettingsConfigDict`` (rule 8)."""
    return (
        isinstance(statement.target, ast.Name)
        and statement.target.id == MODEL_CONFIG
        and isinstance(statement.annotation, ast.Name)
        and statement.annotation.id == MODEL_CONFIG_ANNOTATION
    )


def _is_permitted_annotation(statement: ast.AnnAssign) -> bool:
    """Return whether a field's or a module-level name's annotation is permitted (rule 8)."""
    return _is_builtin_annotation(statement.annotation) or _is_model_config_annotation(statement)


def annotation_findings(tree: ast.Module) -> list[str]:
    """Return every annotation that is a string, holds a call, or is not a builtin type (rule 8).

    A string constant or a call anywhere in any annotation (a field's, a module-level
    name's, a local's, a parameter's or a return annotation) is a finding; the finding
    never quotes the string. Beyond that, a module-level or class-body annotated
    assignment must carry a builtin type annotation; an annotation inside ``provider_key``
    (a local, or a nested function's parameter) is evaluated by no class build and may
    name the supplied ``SecretProvider`` port.
    """
    findings: list[str] = []
    evaluated: list[ast.AnnAssign] = [
        statement for statement in tree.body if isinstance(statement, ast.AnnAssign)
    ]
    settings = _settings_class(tree)
    if settings is not None:
        evaluated.extend(
            statement for statement in settings.body if isinstance(statement, ast.AnnAssign)
        )
    for node in ast.walk(tree):
        field: ast.AnnAssign | None = None
        if isinstance(node, ast.AnnAssign):
            annotation, target = node.annotation, ast.unparse(node.target)
            field = node if any(node is statement for statement in evaluated) else None
        elif isinstance(node, ast.arg) and node.annotation is not None:
            annotation, target = node.annotation, node.arg
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.returns is not None:
            annotation, target = node.returns, f"{node.name}()"
        else:
            continue
        if any(_is_string(child) for child in ast.walk(annotation)):
            findings.append(
                f"{static_rules.line(node)}: a string annotation on `{target}` is code the "
                f"settings class runs when it is built; {ANNOTATION_HINT}"
            )
        elif any(isinstance(child, ast.Call) for child in ast.walk(annotation)):
            findings.append(
                f"{static_rules.line(node)}: the annotation of `{target}` holds a call; "
                f"{ANNOTATION_HINT}"
            )
        elif field is not None and not _is_permitted_annotation(field):
            findings.append(
                f"{static_rules.line(node)}: the annotation of `{target}` is not a builtin "
                f"type name; {ANNOTATION_HINT}"
            )
    return findings


def _is_literal_display(node: ast.AST) -> bool:
    """Return whether an expression is a constant or a display built of constants only."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub | ast.UAdd):
        return isinstance(node.operand, ast.Constant)
    if isinstance(node, ast.Tuple | ast.List | ast.Set):
        return all(_is_literal_display(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            key is not None and _is_literal_display(key) and _is_literal_display(value)
            for key, value in zip(node.keys, node.values, strict=True)
        )
    return False


def _is_inert_value(node: ast.AST, permitted: frozenset[str]) -> bool:
    """Return whether a class-body value is a literal, a permitted name, or a field call (rule 6).

    A field call is ``Field(...)`` or ``SettingsConfigDict(...)`` whose every argument is
    itself inert, so a default factory, a lambda, a comprehension or a call to anything
    else in a field's place is not inert.
    """
    if _is_literal_display(node):
        return True
    if isinstance(node, ast.Name):
        return node.id in permitted
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        if node.func.id not in FIELD_CALLS or node.func.id not in permitted:
            return False
        return all(_is_inert_value(argument, permitted) for argument in node.args) and all(
            keyword.arg is not None and _is_inert_value(keyword.value, permitted)
            for keyword in node.keywords
        )
    return False


def class_findings(tree: ast.Module) -> list[str]:
    """Return every class beyond ``WorkerSettings`` and every class-body statement beyond its shape.

    Rule 6: the one class, anywhere in the file; the starter's base, no decorator and no
    class keyword; a body of the docstring, inert annotated field assignments, the
    ``model_config`` assignment and the ``provider_key`` method, and nothing else.
    """
    findings: list[str] = []
    permitted = _permitted_names()
    settings = _settings_class(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node is not settings:
            findings.append(
                f"{static_rules.line(node)}: the class `{node.name}` is not permitted; {CLASS_HINT}"
            )
    if settings is None:
        return findings
    bases = tuple(ast.unparse(base) for base in settings.bases)
    if bases != STARTER_BASES or settings.keywords or settings.decorator_list:
        findings.append(
            f"{static_rules.line(settings)}: `{SETTINGS_CLASS}` must keep the starter's head, "
            f"`class {SETTINGS_CLASS}({', '.join(STARTER_BASES)}):`, with no decorator and no "
            f"class keyword; {CLASS_HINT}"
        )
    body = list(settings.body)
    if body and isinstance(body[0], ast.Expr) and _is_string(body[0].value):
        body = body[1:]
    for statement in body:
        if isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef):
            if statement.name == KEY_READ:
                continue
            findings.append(
                f"{static_rules.line(statement)}: the method `{statement.name}` is not "
                f"permitted in `{SETTINGS_CLASS}`; {CLASS_HINT}"
            )
            continue
        if (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and _is_permitted_annotation(statement)
            and (statement.value is None or _is_inert_value(statement.value, permitted))
        ):
            continue
        if (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and statement.targets[0].id == MODEL_CONFIG
            and _is_inert_value(statement.value, permitted)
        ):
            continue
        findings.append(
            f"{static_rules.line(statement)}: the `{type(statement).__name__}` statement in "
            f"the body of `{SETTINGS_CLASS}` is not a field assignment over a literal, a "
            f"permitted name or a field call, the `{MODEL_CONFIG}` assignment, or the "
            f"`{KEY_READ}` method; {CLASS_HINT}"
        )
    return findings


def _dunder_names(node: ast.AST) -> list[str]:
    """Return the dunder names one node spells, in any position (rule 7)."""
    names: list[str] = []
    if isinstance(node, ast.Name):
        names.append(node.id)
    elif isinstance(node, ast.Attribute):
        names.append(node.attr)
    elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        names.append(node.name)
    elif isinstance(node, ast.arg):
        names.append(node.arg)
    elif isinstance(node, ast.keyword) and node.arg is not None:
        names.append(node.arg)
    elif isinstance(node, ast.alias):
        names.extend(part for part in node.name.split(".") if part)
        if node.asname is not None:
            names.append(node.asname)
    elif isinstance(node, ast.ImportFrom) and node.module:
        names.extend(part for part in node.module.split(".") if part)
    return [name for name in names if static_rules.is_dunder(name)]


def dunder_findings(tree: ast.Module) -> list[str]:
    """Return every dunder name in the file, as a name, an attribute or a definition (rule 7)."""
    findings: list[str] = []
    for node in ast.walk(tree):
        for name in _dunder_names(node):
            findings.append(
                f"{static_rules.line(node)}: the dunder name `{name}` is not permitted in the "
                f"settings module, as a name, an attribute or a definition; {DUNDER_HINT}"
            )
    return findings


def _permitted_names() -> frozenset[str]:
    """Return every name the permitted imports bind (``Field``, ``secret_provider``, ...)."""
    modules, names = static_rules.permitted_tables(PERMITTED_IMPORTS)
    return frozenset(modules) | frozenset(name for found in names.values() for name in found)


def builtin_findings(tree: ast.Module) -> list[str]:
    """Return every call to, or use of, a forbidden builtin (rule 5), wherever it is."""
    findings: list[str] = []
    reach_names = static_rules.DYNAMIC_NAMES
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in FORBIDDEN_BUILTINS:
                findings.append(
                    f"{static_rules.line(node)}: a call to the builtin `{node.func.id}` is not "
                    f"permitted in the settings module; {IMPORT_TIME_HINT}"
                )
        elif isinstance(node, ast.Name) and node.id in FORBIDDEN_BUILTINS - reach_names:
            findings.append(
                f"{static_rules.line(node)}: the builtin `{node.id}` is not permitted in the "
                f"settings module, called or handed on; {IMPORT_TIME_HINT}"
            )
    return findings


def module_level_findings(tree: ast.Module) -> list[str]:
    """Return every module-level statement that is not an import, a class or a literal (rule 5)."""
    findings: list[str] = []
    permitted = _permitted_names()
    body = list(tree.body)
    if body and isinstance(body[0], ast.Expr) and _is_string(body[0].value):
        body = body[1:]
    for statement in body:
        if isinstance(statement, ast.Import | ast.ImportFrom | ast.ClassDef):
            continue
        if isinstance(statement, ast.Assign | ast.AnnAssign):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            value = statement.value
            simple_targets = all(isinstance(target, ast.Name) for target in targets)
            permitted_name = isinstance(value, ast.Name) and value.id in permitted
            inert_value = value is None or _is_literal_display(value) or permitted_name
            inert_annotation = isinstance(statement, ast.Assign) or _is_permitted_annotation(
                statement
            )
            if simple_targets and inert_value and inert_annotation:
                continue
            findings.append(
                f"{static_rules.line(statement)}: a module-level assignment may bind a name to "
                f"a literal or to a name a permitted import binds, annotated, if at all, with "
                f"a builtin type; {IMPORT_TIME_HINT}"
            )
            continue
        findings.append(
            f"{static_rules.line(statement)}: a module-level `{type(statement).__name__}` "
            f"statement runs at import time and is not permitted; {IMPORT_TIME_HINT}"
        )
    return findings


def findings_for_source(source: str | bytes, path: Path = CONFIG_PATH) -> list[str]:
    """Return every reason the settings file fails its rules, deduplicated, in first position."""
    if path.name != CONFIG_PATH.name:
        raise ConfigBindingError(
            f"{path.name} is not the settings file of this Task ({CONFIG_PATH.as_posix()})"
        )
    parsed = static_rules.parse(source, path.as_posix())
    if isinstance(parsed, list):
        return parsed
    found: list[str] = []
    found.extend(static_rules.import_allowlist_findings(parsed, PERMITTED_IMPORTS, ALLOWLIST_HINT))
    found.extend(static_rules.reach_findings(parsed))
    found.extend(static_rules.rebinding_door_findings(parsed))
    found.extend(builtin_findings(parsed))
    found.extend(module_level_findings(parsed))
    found.extend(class_findings(parsed))
    found.extend(dunder_findings(parsed))
    found.extend(annotation_findings(parsed))
    found.extend(literal_findings(parsed))
    found.extend(read_findings(parsed))
    return static_rules.deduplicated(found)


def findings(path: Path) -> list[str]:
    """Return the findings for the settings file at ``path``, read as bytes."""
    try:
        source = path.read_bytes()
    except OSError as exc:
        raise ConfigBindingError(f"{path.as_posix()} could not be read: {exc}") from exc
    return findings_for_source(source, path)


def application_findings(root: Path = TASK_ROOT) -> list[str]:
    """Return the settings file's findings under ``root``, each prefixed by the file's path."""
    return [f"{CONFIG_PATH.as_posix()}: {item}" for item in findings(root / CONFIG_PATH)]


def main(argv: list[str] | None = None) -> int:
    """Check the settings file (or the file named) and print the findings."""
    parser = argparse.ArgumentParser(
        description=(
            "Check that src/worker/config.py reads the provider key through the supplied "
            "SecretProvider adapter and holds no key literal."
        )
    )
    parser.add_argument("path", nargs="?", type=Path, default=TASK_ROOT / CONFIG_PATH)
    arguments = parser.parse_args(argv)
    try:
        found = findings(arguments.path)
    except ConfigBindingError as exc:
        print(f"config-binding: {exc}", file=sys.stderr)
        return 2
    label = CONFIG_PATH.as_posix()
    if found:
        print(
            f"config-binding: {label} holds a key literal, imports beyond its allowlist, runs "
            "something at import time, defines more than the one settings class, spells a "
            "dunder name, annotates beyond the builtin types, changes the key read's "
            "signature, or reaches beyond application code:",
            file=sys.stderr,
        )
        for finding in found:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print(
        f"config-binding: {label} imports nothing outside the starter's imports and the "
        f"supplied SecretProvider imports, holds no key literal, defines the one class "
        f"`{SETTINGS_CLASS}` in the starter's shape with `{KEY_READ}` as an awaitable read "
        "with the starter's signature, runs nothing at import time beyond its imports, that "
        "class and its literals, spells no dunder name, annotates with builtin types only, "
        "and reaches nothing beyond application code."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
