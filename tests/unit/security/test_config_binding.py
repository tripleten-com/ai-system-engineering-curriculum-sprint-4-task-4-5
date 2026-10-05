"""Coldline.

===================

File:              tests/unit/security/test_config_binding.py
Component:         Unit tests — Static binding check of the worker's settings module
Purpose:           Prove the check accepts a settings module that reads the key through the
                    supplied adapter per use, accepts one that reads it once (the live row's
                    business), and names a key literal, a literal in the field's place, an import
                    beyond the allowlist, a synchronous read, every spelled path to the runner, a
                    forbidden builtin anywhere, any module-level statement that runs at import
                    time, a second class or a class-body statement beyond the starter's shape,
                    any dunder name, a string or non-builtin annotation, and a key read whose
                    signature is not the starter's.
Interacts With:    tests/security/config_binding.py, tests/security/static_rules.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          Trusted static analysis, no literal in the key's place
Tools:             Python 3.12, pytest

Every test feeds a synthetic fragment to the check; none reads the shipped
`src/worker/config.py`, whose state is the student's (the assessed row reads it). The
fragments are probes: a settings class with the few fields the rules look at, not the Task's
module. The snippets that spell `exec`, `sys` or `__globals__` are source text handed to the
parser; nothing here executes them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.security import config_binding as binding

HEAD = '''"""Settings probe."""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
'''
ADAPTER_IMPORT = "from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider\n"
CLASS = '''

class WorkerSettings(BaseSettings):
    """Probe."""

    model_config = SettingsConfigDict(env_prefix="COLDLINE_", extra="forbid")

    service_name: str = "coldline-worker"
    s3_endpoint: str = Field(default="http://localstack:4566", min_length=1)
'''
STARTER = (
    HEAD
    + CLASS
    + (
        f'    model_provider_key: str = Field(default="{binding.FIRST_VERSION_VALUE}", '
        "min_length=1)\n"
        "\n"
        "    async def provider_key(self) -> str:\n"
        '        """Return the literal."""\n'
        "        return self.model_provider_key\n"
    )
)
COMPLETION = (
    HEAD
    + ADAPTER_IMPORT
    + CLASS
    + (
        "\n"
        "    async def provider_key(self) -> str:\n"
        '        """Read the current version each time."""\n'
        "        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)\n"
    )
)
READ_ONCE = (
    HEAD
    + ADAPTER_IMPORT
    + "\n_CACHE: list[str] = []\n"
    + CLASS
    + (
        "\n"
        "    async def provider_key(self) -> str:\n"
        '        """Read once, keep it."""\n'
        "        if not _CACHE:\n"
        "            _CACHE.append(await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME))\n"
        "        return _CACHE[0]\n"
    )
)


def _findings(source: str) -> list[str]:
    return binding.findings_for_source(source)


def test_a_per_use_read_through_the_adapter_passes() -> None:
    """The completion's shape: the adapter import, no literal, an async read."""
    assert _findings(COMPLETION) == []
    port_import = ADAPTER_IMPORT + "from ports import SecretProvider\n"
    with_port = COMPLETION.replace(ADAPTER_IMPORT, port_import)
    assert _findings(with_port) == []


def test_a_read_made_once_and_kept_passes_the_static_rules() -> None:
    """When the read happens is the live replacement row's question, not this check's."""
    assert _findings(READ_ONCE) == []


def test_the_starter_shape_is_named_for_its_literal_and_its_field() -> None:
    """A literal equal to the first version's value, and the field holding it, are findings."""
    findings = _findings(STARTER)
    assert any("equal to the first version's value" in finding for finding in findings)
    assert any("`model_provider_key` holds a literal" in finding for finding in findings)
    # The outcome is computed first, so a failing assertion renders no finding text and no
    # value: pytest shows the operands of the comparison it rewrites.
    rendered = any(binding.FIRST_VERSION_VALUE in finding for finding in findings)
    assert not rendered, "a finding renders the first version's value"


@pytest.mark.parametrize(
    "field_line",
    [
        '    model_provider_key: str = "another-literal"\n',
        '    model_provider_key: str = Field("another-literal")\n',
        '    model_provider_key: str = Field(default="another-literal", min_length=1)\n',
        "    model_provider_key: str = Field(default_factory=lambda: _read())\n",
    ],
    ids=["bare", "positional", "default", "factory"],
)
def test_any_literal_or_factory_in_the_fields_place_is_named(field_line: str) -> None:
    """The field's default is the key's place, whatever the literal is."""
    marker = "\n    async def provider_key"
    source = COMPLETION.replace(marker, "\n" + field_line + marker)
    findings = _findings(source)
    assert any("in the key's place" in finding for finding in findings), findings


def test_a_string_literal_inside_the_read_other_than_the_secret_name_is_named() -> None:
    """A returned literal, a built literal, and an f-string part are each in the key's place."""
    returned = COMPLETION.replace(
        "        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)\n",
        '        return "unit-key-literal"\n',
    )
    [finding] = _findings(returned)
    assert "inside `provider_key` other than the secret's name" in finding

    by_name = COMPLETION.replace(
        "read(PROVIDER_KEY_SECRET_NAME)", 'read("coldline/worker/model-provider-key")'
    )
    assert _findings(by_name) == [], "the secret's name spelled out is not a key literal"

    formatted = COMPLETION.replace(
        "        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)\n",
        '        return f"{await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)}-suffix"\n',
    )
    assert any("in the key's place" in finding for finding in _findings(formatted))


def test_a_synchronous_or_missing_read_and_a_missing_class_are_named() -> None:
    """The client awaits `provider_key`; the method and the class must be there."""
    synchronous = COMPLETION.replace("    async def provider_key", "    def provider_key").replace(
        "return await secret_provider", "return secret_provider"
    )
    assert any("must be `async def`" in finding for finding in _findings(synchronous))

    absent = COMPLETION.split("\n    async def provider_key")[0] + "\n"
    assert any("defines no `provider_key` method" in finding for finding in _findings(absent))

    renamed = COMPLETION.replace("class WorkerSettings", "class Settings")
    assert any("no module-level class `WorkerSettings`" in f for f in _findings(renamed))


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("import os\n", "`import os` is not in"),
        ("from pydantic import Field as F\n", "aliases `Field`"),
        ("from pydantic import BaseModel\n", "imports `BaseModel`, which is not in"),
        (
            "from adapters.secrets import LocalStackSecretProvider\n",
            "imports `LocalStackSecretProvider`",
        ),
        ("from .secrets import secret_provider\n", "is a relative import"),
        ("from adapters.secrets import *\n", "imports every name"),
        ("import sys\n", "`import sys` is not permitted in application code"),
        ("from unittest import mock\n", "not permitted in application code"),
    ],
    ids=["os", "alias", "other-name", "other-adapter-name", "relative", "star", "sys", "mock"],
)
def test_imports_beyond_the_allowlist_are_named(statement: str, expected: str) -> None:
    """Any module, name, alias or form outside the starter's imports plus the supplied ones."""
    findings = _findings(COMPLETION.replace(ADAPTER_IMPORT, ADAPTER_IMPORT + statement))
    assert any(expected in finding for finding in findings), findings


@pytest.mark.parametrize(
    "snippet, expected",
    [
        ("        exec('x = 1')\n", "`exec` is not permitted"),
        ("        getattr(self, 'x')\n", "`getattr` is not permitted"),
        ("        self.__dict__\n", "dunder attribute"),
        ("        type('X', (), {})\n", "with three arguments"),
        ("        logging.currentframe()\n", "frame"),
        ("        modules = secret_provider.sys\n", "`secret_provider.sys` is not permitted"),
    ],
    ids=["exec", "getattr", "dunder", "type3", "frame", "sys-attribute"],
)
def test_every_spelled_path_to_the_runner_is_named(snippet: str, expected: str) -> None:
    """The reach rules apply to the settings module as they did to the worker."""
    source = COMPLETION.replace(
        "        return await secret_provider",
        snippet + "        return await secret_provider",
    )
    findings = _findings(source)
    assert any(expected in finding for finding in findings), findings


def test_a_module_level_file_write_at_import_time_is_named_twice() -> None:
    """A module-level `open(...).write(...)` is a forbidden builtin and a module-level call.

    Code that runs when the settings module is imported runs inside the worker image and
    inside the process that judges the module; a write there could rewrite a check before
    it runs. Both rules name it, by line, without quoting what it would write.
    """
    write = 'open("tests/security/probe.py", "w").write("tampered")\n'
    source = COMPLETION.replace(CLASS, "\n" + write + CLASS)
    findings = _findings(source)
    assert any("a call to the builtin `open`" in finding for finding in findings), findings
    assert any("module-level `Expr` statement runs at import time" in f for f in findings)
    assert all("tampered" not in finding for finding in findings)


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("_STORE = secret_provider(None)\n", "module-level assignment"),
        ("_NAME = str\n", "module-level assignment"),
        ('_TEXT = f"{PROVIDER_KEY_SECRET_NAME}"\n', "module-level assignment"),
        ("_A: open('x', 'w').write('y') = 1\n", "module-level assignment"),
        ("if True:\n    pass\n", "module-level `If` statement"),
        ("try:\n    pass\nexcept Exception:\n    pass\n", "module-level `Try` statement"),
        ("with open('x') as handle:\n    pass\n", "module-level `With` statement"),
        ("for _item in ():\n    pass\n", "module-level `For` statement"),
        ("def helper() -> None:\n    return None\n", "module-level `FunctionDef` statement"),
        ("exec('x = 1')\n", "module-level `Expr` statement"),
    ],
    ids=[
        "call",
        "builtin-name",
        "f-string",
        "annotation-call",
        "if",
        "try",
        "with",
        "for",
        "def",
        "exec",
    ],
)
def test_module_level_statements_beyond_imports_classes_and_literals_are_named(
    statement: str, expected: str
) -> None:
    """Only the docstring, imports, classes and literal assignments may stand at module level."""
    source = COMPLETION.replace(CLASS, "\n" + statement + CLASS)
    findings = _findings(source)
    assert any(expected in finding for finding in findings), findings


@pytest.mark.parametrize(
    "statement",
    [
        "_CACHE: list[str] = []\n",
        "_LIMITS: dict[str, int] = {'a': 1}\n",
        "_PAIR: tuple[int, ...] = (1, 2)\n",
        "_LABEL = 'worker'\n",
        "_FACTORY = Field\n",
        "_READ = secret_provider\n",
        "_FLAG: bool | None = None\n",
    ],
    ids=["list", "dict", "tuple", "string", "permitted-name", "adapter-name", "union"],
)
def test_literal_and_permitted_name_assignments_stand_at_module_level(statement: str) -> None:
    """A literal, a display of literals, or a name a permitted import binds is inert."""
    source = COMPLETION.replace(CLASS, "\n" + statement + CLASS)
    assert _findings(source) == []


@pytest.mark.parametrize(
    "snippet, expected",
    [
        ("        input()\n", "a call to the builtin `input`"),
        ("        breakpoint()\n", "a call to the builtin `breakpoint`"),
        ("        open('x')\n", "a call to the builtin `open`"),
        ("        _opener = open\n", "the builtin `open` is not permitted"),
        ("        compile('1', 'x', 'eval')\n", "a call to the builtin `compile`"),
        ("        __import__('os')\n", "a call to the builtin `__import__`"),
    ],
    ids=["input", "breakpoint", "open", "open-handed-on", "compile", "import"],
)
def test_forbidden_builtins_inside_the_class_are_named(snippet: str, expected: str) -> None:
    """The fourteen builtins are refused wherever they appear, called or handed on."""
    source = COMPLETION.replace(
        "        return await secret_provider",
        snippet + "        return await secret_provider",
    )
    findings = _findings(source)
    assert any(expected in finding for finding in findings), findings


def test_a_second_class_that_writes_through_the_loader_is_named_twice() -> None:
    """A class beside `WorkerSettings` whose body rewrites a check through `__loader__`.

    The module's own `__loader__` is a source loader with `set_data`, which writes a file;
    a class body runs at import time, inside the worker image and inside the process that
    judges the module. The second class is a finding and so is the dunder name, by line,
    and neither finding quotes the path the write would target.
    """
    rewrite = (
        "\n\nclass Rewriter:\n"
        '    __loader__.set_data("tests/contract/test_security_contract.py", b"")\n'
    )
    source = COMPLETION + rewrite
    findings = _findings(source)
    assert any("the class `Rewriter` is not permitted" in finding for finding in findings)
    assert any("the dunder name `__loader__`" in finding for finding in findings), findings
    assert all("test_security_contract" not in finding for finding in findings)


@pytest.mark.parametrize(
    "snippet, name",
    [
        ("        __loader__.set_data('x', b'')\n", "__loader__"),
        ("        __spec__.loader\n", "__spec__"),
        ("        __builtins__['open']\n", "__builtins__"),
        ("        self.__class__\n", "__class__"),
        ("        secret_provider.__globals__\n", "__globals__"),
        ("        def __call__(self) -> None:\n            return None\n", "__call__"),
    ],
    ids=["loader", "spec", "builtins", "class", "globals", "definition"],
)
def test_every_dunder_name_inside_the_read_is_named(snippet: str, name: str) -> None:
    """A dunder name as a name, an attribute or a definition, anywhere, is a finding."""
    source = COMPLETION.replace(
        "        return await secret_provider",
        snippet + "        return await secret_provider",
    )
    findings = _findings(source)
    assert any(f"the dunder name `{name}`" in finding for finding in findings), findings


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("\n\nclass Helper:\n    pass\n", "the class `Helper` is not permitted"),
        ("\n\nclass WorkerSettings(BaseSettings):\n    pass\n", "the class `WorkerSettings`"),
        ("\nimport __main__\n", "the dunder name `__main__`"),
    ],
    ids=["second-class", "second-settings-class", "dunder-import"],
)
def test_classes_beyond_the_settings_class_and_dunder_imports_are_named(
    statement: str, expected: str
) -> None:
    """A second class, a second `WorkerSettings`, or a dunder module name, at module level."""
    findings = _findings(COMPLETION + statement)
    assert any(expected in finding for finding in findings), findings


@pytest.mark.parametrize(
    "class_line, expected",
    [
        ("class WorkerSettings(BaseModel):", "must keep the starter's head"),
        ("class WorkerSettings:", "must keep the starter's head"),
        ("class WorkerSettings(BaseSettings, metaclass=type):", "must keep the starter's head"),
        ("@dataclass\nclass WorkerSettings(BaseSettings):", "must keep the starter's head"),
    ],
    ids=["other-base", "no-base", "keyword", "decorator"],
)
def test_the_settings_class_keeps_the_starters_head(class_line: str, expected: str) -> None:
    """The base, the absence of a decorator and the absence of a class keyword are fixed."""
    source = COMPLETION.replace("class WorkerSettings(BaseSettings):", class_line)
    findings = _findings(source)
    assert any(expected in finding for finding in findings), findings


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("    class Nested:\n        pass\n", "the class `Nested` is not permitted"),
        ("    def helper(self) -> None:\n        return None\n", "the method `helper`"),
        ("    print('loaded')\n", "`Expr` statement in the body"),
        ("    if True:\n        pass\n", "`If` statement in the body"),
        ("    _STORE = secret_provider(None)\n", "`Assign` statement in the body"),
        ("    _store: object = secret_provider(None)\n", "`AnnAssign` statement in the body"),
        ("    retries: int = Field(default_factory=lambda: 3)\n", "`AnnAssign` statement"),
        ("    model_config = {'extra': 'forbid'}.copy()\n", "`Assign` statement in the body"),
        ("    name: str = str(1)\n", "`AnnAssign` statement in the body"),
    ],
    ids=[
        "nested-class",
        "method",
        "call",
        "if",
        "assign-call",
        "annotated-call",
        "factory",
        "model-config-call",
        "builtin-call",
    ],
)
def test_class_body_statements_beyond_fields_model_config_and_the_read_are_named(
    statement: str, expected: str
) -> None:
    """The class body runs at import time: only inert fields, `model_config` and the read."""
    marker = "\n    async def provider_key"
    source = COMPLETION.replace(marker, "\n" + statement + marker)
    findings = _findings(source)
    assert any(expected in finding for finding in findings), findings


@pytest.mark.parametrize(
    "statement",
    [
        "    _cache: list[str] = []\n",
        "    _limits: dict[str, int] = {'reads': 1}\n",
        "    retries: int = Field(default=3, ge=1, le=3)\n",
        "    label: str = 'worker'\n",
        "    pattern: str = Field(default='x', pattern=r'^[a-z]+$')\n",
        "    offset: int = -1\n",
        "    timeout: int | None = None\n",
        "    _name: str = PROVIDER_KEY_SECRET_NAME\n",
        "    _pairs: tuple[tuple[str, int], ...] = ()\n",
        "    _rate: float = 0.5\n",
        "    model_config: SettingsConfigDict = SettingsConfigDict(extra='forbid')\n",
    ],
    ids=[
        "cache",
        "dict",
        "field",
        "string",
        "pattern",
        "negative",
        "optional",
        "permitted-name",
        "nested-generic",
        "float",
        "annotated-model-config",
    ],
)
def test_inert_fields_and_a_cache_attribute_stand_in_the_class_body(statement: str) -> None:
    """A literal, a display, a permitted name or a field call, annotated with a builtin type."""
    marker = "\n    async def provider_key"
    source = COMPLETION.replace(marker, "\n" + statement + marker)
    assert _findings(source) == []


def test_a_string_annotation_that_runs_at_class_build_is_named_without_its_text() -> None:
    """A field whose annotation is a string holding an expression that writes a file.

    Pydantic evaluates a forward-reference annotation when the settings class is built,
    so a string annotation is code that runs inside the worker image and inside the
    process that judges the module; the AST sees a string, not the call, the dunder or
    the path inside it. The rule names the field, by line, and quotes nothing of the
    string. The same string at module level is named the same way.
    """
    expression = "(__import__('pathlib').Path('tests/security/probe.py').write_text('x'), str)[1]"
    field = f'    probe: "{expression}" = "x"\n'
    marker = "\n    async def provider_key"
    findings = _findings(COMPLETION.replace(marker, "\n" + field + marker))
    assert any("a string annotation on `probe`" in finding for finding in findings), findings
    assert all("probe.py" not in finding and "write_text" not in finding for finding in findings)

    module_level = f'_PROBE: "{expression}" = 1\n'
    findings = _findings(COMPLETION.replace(CLASS, "\n" + module_level + CLASS))
    assert any("a string annotation on `_PROBE`" in finding for finding in findings), findings
    assert all("probe.py" not in finding for finding in findings)


@pytest.mark.parametrize(
    "statement, expected",
    [
        ("    retries: Annotated[int, Field(ge=1)] = 3\n", "holds a call"),
        ("    retries: dict[str, str(1)] = {}\n", "holds a call"),
        ("    retries: open('x')[0] = 3\n", "holds a call"),
        ("    retries: str.__class__ = 'x'\n", "is not a builtin type name"),
        ("    store: SecretProvider = secret_provider\n", "is not a builtin type name"),
        ("    retries: Field = 3\n", "is not a builtin type name"),
        ("    _factory: object = Field\n", "is not a builtin type name"),
        ("    retries: list[SecretProvider] = []\n", "is not a builtin type name"),
        ("    retries: set[int] = set()\n", "is not a builtin type name"),
        ("    retries: int | SecretProvider = 3\n", "is not a builtin type name"),
        ("    label: 'str' = 'x'\n", "a string annotation on `label`"),
    ],
    ids=[
        "annotated-call",
        "call-in-generic",
        "subscript-of-call",
        "dunder",
        "port",
        "permitted-name",
        "object",
        "port-in-generic",
        "set",
        "port-in-union",
        "string",
    ],
)
def test_field_annotations_beyond_the_builtin_types_are_named(
    statement: str, expected: str
) -> None:
    """A field or cache attribute is annotated with a builtin type, a generic over them or a union.

    The same statement at module level is named the same way.
    """
    marker = "\n    async def provider_key"
    source = COMPLETION.replace(marker, "\n" + statement + marker)
    findings = _findings(source)
    assert any(expected in finding for finding in findings), findings
    module_level = _findings(COMPLETION.replace(CLASS, "\n" + statement.strip() + "\n" + CLASS))
    assert any(expected in finding for finding in module_level), module_level


def test_a_local_annotation_inside_the_read_may_name_the_port_but_not_a_string() -> None:
    """The supplied `SecretProvider` import annotates a local inside `provider_key`.

    A local's annotation is evaluated by no class build, so the port's name is permitted
    there; a string or a call is a finding anywhere, a nested function's parameter and
    return annotations included.
    """
    port_import = ADAPTER_IMPORT + "from ports import SecretProvider\n"
    local = COMPLETION.replace(ADAPTER_IMPORT, port_import).replace(
        "        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)\n",
        "        provider: SecretProvider = secret_provider(self)\n"
        "        return await provider.read(PROVIDER_KEY_SECRET_NAME)\n",
    )
    assert _findings(local) == []
    string_local = local.replace("provider: SecretProvider", "provider: 'SecretProvider'")
    assert any("a string annotation on `provider`" in f for f in _findings(string_local))
    nested = COMPLETION.replace(
        "        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)\n",
        "        def inner(text: 'str') -> 'str':\n            return text\n"
        "        return await secret_provider(self).read(PROVIDER_KEY_SECRET_NAME)\n",
    )
    findings = _findings(nested)
    assert any("a string annotation on `text`" in finding for finding in findings), findings
    assert any("a string annotation on `inner()`" in finding for finding in findings), findings


@pytest.mark.parametrize(
    "head",
    [
        "    @staticmethod\n    async def provider_key(self) -> str:",
        "    async def provider_key(self, retry: int = 1) -> str:",
        "    async def provider_key(self, name) -> str:",
        "    async def provider_key(self) -> object:",
        "    async def provider_key(self):",
        "    async def provider_key[T](self) -> str:",
        "    async def provider_key(self: 'WorkerSettings') -> str:",
    ],
    ids=["decorator", "default", "parameter", "return", "no-return", "type-params", "string"],
)
def test_the_key_read_keeps_the_starters_signature(head: str) -> None:
    """A decorator, a default, another parameter, another return annotation or a type parameter."""
    source = COMPLETION.replace("    async def provider_key(self) -> str:", head)
    findings = _findings(source)
    assert any("changed its signature, decorators or return annotation" in f for f in findings), (
        findings
    )


def test_the_forbidden_builtins_are_the_fourteen_named_by_the_review() -> None:
    """The set is pinned here as a literal, so a drift in the module is visible."""
    assert binding.FORBIDDEN_BUILTINS == frozenset(
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


def test_the_permitted_imports_are_the_starter_plus_the_supplied_ones() -> None:
    """The allowlist is pinned here as a literal, so a drift in the module is visible."""
    assert binding.PERMITTED_IMPORTS == (
        "from pydantic import Field",
        "from pydantic_settings import BaseSettings, SettingsConfigDict",
        "from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider",
        "from ports import SecretProvider",
    )
    assert binding.PROVIDER_KEY_SECRET_NAME == "coldline/worker/model-provider-key"


def test_an_unparseable_or_wrongly_named_file_is_handled(tmp_path: Path) -> None:
    """A syntax error is one finding; another file name is a tooling error; a missing file too."""
    [finding] = _findings("class WorkerSettings(\n")
    assert "not valid Python" in finding
    with pytest.raises(binding.ConfigBindingError, match="not the settings file"):
        binding.findings_for_source(COMPLETION, Path("src/worker/other.py"))
    with pytest.raises(binding.ConfigBindingError, match="could not be read"):
        binding.findings(tmp_path / "config.py")


def test_the_command_line_prints_the_findings_and_the_success_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 1 with the findings on a starter-shaped file; 0 and the success line on a completion."""
    starter = tmp_path / "config.py"
    starter.write_text(STARTER, encoding="utf-8")
    assert binding.main([str(starter)]) == 1
    assert "holds a key literal" in capsys.readouterr().err

    completion = tmp_path / "done" / "config.py"
    completion.parent.mkdir()
    completion.write_text(COMPLETION, encoding="utf-8")
    assert binding.main([str(completion)]) == 0
    assert "holds no key literal" in capsys.readouterr().out
