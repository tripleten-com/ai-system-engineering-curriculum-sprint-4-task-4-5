"""Coldline.

===================

File:              tests/contract/test_security_contract.py
Component:         Contract tests — Secret and CI security gate
Purpose:           One assessed check per public Check-list row: the SecretProvider read, the
                    replacement in place, no value in any output, the gate's thresholds, the
                    clean tree and the two seeds, the suppression, the fix file, and the
                    inherited Task 2, 3 and 4 controls.
Interacts With:    The running stack, tests/security/*.py, src/worker/config.py and the fix
                    file, security/gate.yaml, .gitleaks.toml, submission.yaml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.5
Concepts:          A secret read per use, a gate proven on seeds, triage with evidence
Tools:             Python 3.12, pytest, httpx, Docker

Assessed: a fresh starter carries the provider key as a literal, report-only thresholds,
no suppression, no fix and a blank sheet, so most rows fail until the Task's work is
done. ``poe contract`` deselects them; ``poe security-contract`` and ``poe verify`` run them
through ``tests/security/assessed_run.py``, right after the smoke checks and before the
inherited end-to-end checks, so a wrong outcome is reported by the row that names it.

The rows run in the order written, and the order carries meaning: the two static rows
first; then every row that runs the worker with the key that is current when the module
starts (the Step 1 row and the inherited Task 2, 3 and 4 rows, which share one
module-scoped set of live interactions); then the replacement row, which stores a new
version and runs the worker again; then the rows that read outputs and run the scanners,
which need no further scenario. When the module ends, the value that was current when it
began is stored again as a new current version, so a worker that still carries the opening
literal, and one that reads the key per use, both work afterwards and a second run of
``poe verify`` judges the same thing (``docs/fidelity/SecretProvider.md``).

No row prints a key value. Versions are named by id and fingerprint; a row that looks for
a value in an output names the version and the output, never the value.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import inspect
import io
import json
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

import adapters.secrets.localstack as secrets_adapter
from adapters.model.deterministic import (
    PLANTED_FIELD,
    PLANTED_NEXT_STEP,
    PLANTED_VALUE,
    REJECTED_RESPONSES,
)
from adapters.secrets import (
    PROVIDER_KEY_SECRET_NAME,
    LocalStackSecretProvider,
    SecretUnavailable,
    SecretVersion,
)
from common.audit import AuditEvent
from domain.contracts import SensorReading
from tests.contract.submission_validation import (
    FINDING_ID,
    SubmissionError,
    _load_one_document,
    validate_submission,
)
from tests.runtime_config import host_port
from tests.security import (
    config_binding,
    fix_binding,
    gate,
    live_record,
    pii,
    pii_scan,
    repository,
    scanners,
    secret_tools,
    seeds,
    suppression,
    trail,
)
from tests.security.assessed_run import INTERACTION_IDS
from tests.security.fixtures import EXPECTED_STATUS, FIXTURE_NAMES, bearer_headers
from tests.security.harness import TASK_ROOT
from tests.security.interaction import expected_summary, replayed_answer
from worker.guardrail import REASON_CODES, REVIEW_MESSAGE

pytestmark = pytest.mark.assessed
ROUTE = "/api/v1/exceptions/{exception_id}"
DISPATCHER = "dispatcher-valid"
DISPATCHER_SUBJECT = "user:dispatcher-01"
DISPATCHER_ROLE = "dispatcher"
FIRST_NOTE = pii.FIRST_NOTE
ECHO = "pii-echo"
NAME = PROVIDER_KEY_SECRET_NAME
CONFIG_PATH = config_binding.CONFIG_PATH
KEY_READ = config_binding.KEY_READ
_MISSING = object()
# The four live interactions the inherited rows share, by the id the parametrized rows
# carry: the supplied note (or None for the shipped scenario note) and the emulator response.
INTERACTIONS: dict[str, tuple[str | None, str]] = {
    "n01-valid": (FIRST_NOTE, "valid"),
    ECHO: (None, ECHO),
    **{response: (FIRST_NOTE, response) for response in REJECTED_RESPONSES},
}
EXPECTED_CODE = {"malformed": "not_json", "manipulated": "unknown_property"}
EXPECTED_DECISION = {
    "n01-valid": AuditEvent.OUTPUT_VALIDATED.value,
    ECHO: AuditEvent.OUTPUT_VALIDATED.value,
    "malformed": AuditEvent.OUTPUT_REJECTED.value,
    "manipulated": AuditEvent.OUTPUT_REJECTED.value,
}
MODEL_TEXT = (
    "Synthetic shipment",
    "thermal_excursion",
    "operational_review",
    PLANTED_FIELD,
    PLANTED_VALUE,
    PLANTED_NEXT_STEP,
    '"summary"',
)
READ_HINT = (
    "read the key through the supplied SecretProvider adapter each time the worker needs it, "
    "not once when the settings load (docs/fidelity/SecretProvider.md)"
)
COMMAND_TIMEOUT_SECONDS = 120
# The in-process probe of the replacement row: three synthetic values a stand-in store hands
# out in turn, one per read, so three per-use reads return three distinct values and a read
# kept from the first call returns one. None is a key; none is printed.
PROBE_VALUES: tuple[str, ...] = ("probe-version-one", "probe-version-two", "probe-version-three")
PROBE_SETTINGS = {
    "database_url": "postgresql://probe",
    "redis_url": "redis://probe",
    "otel_endpoint": "http://probe",
}


class _ProbeSecretsClient:
    """A stand-in Secrets Manager client: counts each secret's reads, changes the value per read."""

    def __init__(self, values: tuple[str, ...]) -> None:
        self._values = values
        self.reads: list[str] = []

    def get_secret_value(self, **arguments: Any) -> dict[str, Any]:
        """Answer one read with the next value for that secret, and record the read."""
        name = str(arguments.get("SecretId", ""))
        self.reads.append(name)
        index = min(self.reads.count(name), len(self._values)) - 1
        return {
            "SecretString": self._values[index],
            "VersionId": f"probe-version-{index + 1}",
            "VersionStages": [secrets_adapter.CURRENT_STAGE],
        }


@dataclass(frozen=True)
class Interaction:
    """One supplied note and response through the running stack, as the trusted harness made it."""

    key: str
    note: str | None
    response: str
    submission: live_record.Submission
    state: str
    read_trace_id: str
    body: dict[str, Any]

    @property
    def exception_id(self) -> str:
        """Return the exception the interaction created."""
        return self.submission.exception_id

    @property
    def reading(self) -> SensorReading:
        """Return the reading as it was submitted."""
        return SensorReading.model_validate(self.submission.reading)

    def expected_summary(self) -> str | None:
        """Return the summary a worker that redacts as supplied stores for this reading."""
        return expected_summary(exception_id=self.exception_id, reading=self.reading)

    def expected(self, record: dict[str, Any]) -> trail.ExpectedInteraction:
        """Return what the trail must agree with, from the harness's own knowledge only."""
        answer = replayed_answer(exception_id=self.exception_id, reading=self.reading)
        summary = record.get("summary")
        return trail.ExpectedInteraction(
            exception_id=self.exception_id,
            reading_id=self.submission.reading_id,
            provider=answer.provider,
            answer_text=answer.text,
            state=str(record.get("state")),
            summary=summary if isinstance(summary, str) else None,
            subject=DISPATCHER_SUBJECT,
            role=DISPATCHER_ROLE,
        )


# --- Fixtures -----------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def api() -> Iterator[httpx.Client]:
    """Return a client for the running API on the host."""
    port = host_port("COLDLINE_API_HOST_PORT", 8000)
    with httpx.Client(base_url=f"http://localhost:{port}", timeout=10.0) as client:
        yield client


@pytest.fixture(scope="module")
def store() -> Iterator[LocalStackSecretProvider]:
    """Return the host-side adapter over the running secret store; restore the value at the end.

    The value current when the module starts is kept in this process's memory only and
    stored again as a new current version when the module ends, whatever the rows did.
    """
    adapter = secret_tools.host_store(TASK_ROOT)
    try:
        _, initial = asyncio.run(adapter.current_value(NAME))
    except SecretUnavailable as exc:
        raise RuntimeError(
            f"the secret rows' precondition was not met: {exc}; is the stack running, and did "
            "the initializer create the provider key's secret?"
        ) from exc
    yield adapter
    try:
        _, final = asyncio.run(adapter.current_value(NAME))
        if final != initial:
            asyncio.run(adapter.put_version(NAME, initial))
    except SecretUnavailable:
        pass


def _read_once(api: httpx.Client, exception_id: str, trace_id: str) -> dict[str, Any]:
    """Read one record through the API as the dispatcher, once, in the given trace."""
    response = api.get(
        ROUTE.format(exception_id=exception_id),
        headers={**bearer_headers(DISPATCHER), **live_record.traceparent(trace_id)},
    )
    assert response.status_code == 200, _detail(response)
    body = response.json()
    assert isinstance(body, dict)
    return body


@pytest.fixture(scope="module")
def interactions(api: httpx.Client) -> dict[str, Interaction]:
    """Run the four inherited interactions: submit, wait, and read each once as the dispatcher."""
    notes = pii.load_notes(TASK_ROOT)
    made: dict[str, Interaction] = {}
    for key, (note, response) in INTERACTIONS.items():
        text = notes[note].text if note is not None else None
        try:
            submission, state = live_record.create_finished_submission(
                api, response=response, note=text
            )
        except live_record.StoredRecordError as exc:
            raise RuntimeError(f"the live rows' precondition was not met: {exc}") from exc
        read_trace_id = live_record.new_trace_id()
        body = _read_once(api, submission.exception_id, read_trace_id)
        made[key] = Interaction(key, note, response, submission, state, read_trace_id, body)
    return made


def _thresholds() -> gate.Thresholds:
    """Return the student's thresholds, or fail the row with the file's problem."""
    try:
        return gate.load_thresholds(root=TASK_ROOT)
    except gate.GateError as exc:
        pytest.fail(str(exc))


@pytest.fixture(scope="module")
def clean_report() -> scanners.Report:
    """Scan the working tree with the student's thresholds and configuration, reports included."""
    try:
        return scanners.scan_working_tree(TASK_ROOT, _thresholds(), sbom=True)
    except scanners.ScanError as exc:
        raise RuntimeError(f"the clean-tree scan could not run: {exc}") from exc


@pytest.fixture(scope="module")
def inventory_report() -> scanners.Report:
    """Scan the working tree with the supplied configuration: every finding, no allowlist."""
    try:
        return scanners.scan_working_tree(TASK_ROOT, _thresholds(), inventory=True)
    except scanners.ScanError as exc:
        raise RuntimeError(f"the inventory scan could not run: {exc}") from exc


@pytest.fixture(scope="module")
def baseline_report() -> scanners.Report:
    """Scan the starting checkpoint, exported from Git, with the supplied configuration."""
    try:
        return scanners.scan_baseline(TASK_ROOT, _thresholds())
    except scanners.ScanError as exc:
        raise RuntimeError(f"the starting checkpoint could not be scanned: {exc}") from exc


# --- Helpers ------------------------------------------------------------------------------------


def _answers() -> dict[str, Any]:
    """Return the sheet's answers mapping (possibly blank), or fail the row."""
    try:
        document = _load_one_document(TASK_ROOT / "submission.yaml")
    except SubmissionError as exc:
        pytest.fail(str(exc))
    answers = document.get("answers")
    return dict(answers) if isinstance(answers, dict) else {}


def _named_finding(field: str) -> str:
    """Return the finding id a sheet field names, or fail the row."""
    value = _answers().get(field)
    if not isinstance(value, str) or not FINDING_ID.match(value):
        pytest.fail(
            f"answers.{field} names no finding id (an id as `poe security-scan` prints it, "
            "F-nn); record it in submission.yaml"
        )
    return value


def _record(exception_id: str) -> dict[str, Any]:
    """Return one record's output fields from the database, or fail the row."""
    try:
        record = live_record.stored_record(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    if record is None:
        pytest.fail(f"exception {exception_id} is not in the database")
    return record


def _detail(response: httpx.Response) -> str:
    """Return the refusal's reason, or the status line, for an assertion message."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict) and "detail" in body:
        return str(body["detail"])
    return str(body)[:200]


def _trail(exception_id: str) -> list[dict[str, Any]]:
    """Return one exception's audit trail from the running stack, or fail the row."""
    try:
        return trail.fetch_trail(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))


def _locations(exception_id: str) -> dict[str, str]:
    """Return the four locations as `poe pii-scan` reads them, or fail the row."""
    try:
        locations = pii_scan.live_locations(exception_id)
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    assert locations["worker logs"] is not None, (
        f"the worker logs hold no line naming {exception_id}; the logs could not be read"
    )
    assert locations["model request"] is not None, (
        f"no model request was recorded for {exception_id}: the worker's request log is not "
        "composed (COLDLINE_MODEL_REQUEST_DIR in compose.yaml) or the record could not be read"
    )
    return {name: text for name, text in locations.items() if text is not None}


def _compose(*arguments: str) -> subprocess.CompletedProcess[str]:
    """Run one Compose command from the Task root."""
    return subprocess.run(
        [*live_record.COMPOSE, *arguments],
        cwd=TASK_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )


def _worker_identity() -> tuple[str, str]:
    """Return the worker container's id and start time, so a recreation is visible."""
    listing = _compose("ps", "--format", "json", "worker")
    rows = [json.loads(line) for line in listing.stdout.splitlines() if line.strip()]
    worker = next((row for row in rows if row.get("Service") == "worker"), None)
    if worker is None:
        pytest.fail("the worker container is not running")
    container = str(worker.get("ID"))
    inspected = subprocess.run(
        ["docker", "inspect", container],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )
    try:
        details = json.loads(inspected.stdout)
        started = str(details[0]["State"]["StartedAt"])
    except (ValueError, LookupError, TypeError):
        pytest.fail(f"docker inspect gave no start time for the worker: {inspected.stderr}")
    return container, started


def _auth_record() -> dict[str, Any]:
    """Return the worker's authentication record, or fail the row."""
    try:
        return secret_tools.provider_auth_record(TASK_ROOT)
    except secret_tools.SecretToolError as exc:
        pytest.fail(str(exc))


def _versions_and_values(store: LocalStackSecretProvider) -> list[tuple[SecretVersion, str]]:
    """Return every version the store holds with its value (kept in memory, never printed)."""
    try:
        versions = asyncio.run(store.versions(NAME))
        return [
            (version, asyncio.run(store.value_of(NAME, version.version_id))) for version in versions
        ]
    except SecretUnavailable as exc:
        pytest.fail(str(exc))


async def _awaited(value: object) -> object:
    """Return ``value``, awaited when it is awaitable (a coroutine, a task, a future)."""
    if inspect.isawaitable(value):
        return await value
    return value


def _read_provider_key(settings: object) -> object:
    """Make one read of the student's ``provider_key``, whatever shape it has.

    ``provider_key`` may be an ``async def`` method (the starter's shape, awaited by the
    model client), a plain method, or a property; a method is called with no argument and
    a property is read, and whatever comes back is awaited when it is awaitable. The
    attribute's absence, or an error on the way, fails the row with its reason.
    """
    try:
        attribute = getattr(settings, KEY_READ, _MISSING)
    except Exception as exc:  # noqa: BLE001 - a property of the student's class is arbitrary code
        pytest.fail(f"reading WorkerSettings.{KEY_READ} raised {type(exc).__name__}: {exc}")
    if attribute is _MISSING:
        pytest.fail(
            f"WorkerSettings defines no `{KEY_READ}`; the model client awaits "
            f"`settings.{KEY_READ}()` for every request ({READ_HINT})"
        )
    try:
        produced = attribute() if callable(attribute) else attribute
        return asyncio.run(_awaited(produced))
    except Exception as exc:  # noqa: BLE001 - the student's method is arbitrary code
        pytest.fail(f"WorkerSettings.{KEY_READ} raised {type(exc).__name__}: {exc}")


def _per_use_read_probe(monkeypatch: pytest.MonkeyPatch) -> tuple[int, int]:
    """Read the student's ``WorkerSettings.provider_key`` three times against a changing store.

    The student's settings module is imported afresh in this process (never run as a
    script), its ``WorkerSettings`` is instantiated with placeholder connection settings,
    and the supplied adapter's client factory is replaced for the duration by a stand-in
    store whose current value changes on every read. ``provider_key`` is read as the model
    client would read it, whether it is an async method, a plain method or a property
    (``_read_provider_key``). Returns how many reads of the provider key's secret the three
    reads made and how many distinct values they returned; a per-use read makes three and
    returns three, a read made once and kept makes one and returns one, and a settings
    module that returns a value of its own without reading the store makes none.
    """
    try:
        module = importlib.reload(importlib.import_module("worker.config"))
    except Exception as exc:  # noqa: BLE001 - the student's module is arbitrary code
        pytest.fail(f"{CONFIG_PATH.as_posix()} could not be imported: {type(exc).__name__}: {exc}")
    settings_class = getattr(module, "WorkerSettings", None)
    if settings_class is None:
        pytest.fail(f"{CONFIG_PATH.as_posix()} defines no WorkerSettings class")
    client = _ProbeSecretsClient(PROBE_VALUES)
    monkeypatch.setattr(secrets_adapter, "create_secrets_client", lambda **arguments: client)
    try:
        settings = settings_class(**PROBE_SETTINGS)
    except Exception as exc:  # noqa: BLE001 - the student's class is arbitrary code
        pytest.fail(f"WorkerSettings could not be built: {type(exc).__name__}: {exc}")
    returned = [_read_provider_key(settings) for _ in range(len(PROBE_VALUES))]
    return client.reads.count(NAME), len({str(value) for value in returned})


def _completed_redacted(interaction: Interaction) -> dict[str, Any]:
    """Assert one interaction ended COMPLETED with the expected redacted summary; return it."""
    assert interaction.state == "COMPLETED", (
        f"the {interaction.key} run ended in {interaction.state}; a redacted answer still "
        "passes the schema, so the run must complete"
    )
    record = _record(interaction.exception_id)
    summary = record.get("summary")
    assert isinstance(summary, str) and summary, "no summary was stored"
    matches = summary == interaction.expected_summary()
    assert matches, (
        f"the stored summary of the {interaction.key} run is not the one the supplied worker "
        "stores (the carried Task 4.4 redaction is supplied code; restore it)"
    )
    return record


# --- Step 1: the SecretProvider read (static, then live) --------------------------------------


def test_config_reads_the_key_through_the_secret_provider_and_holds_no_literal(
    store: LocalStackSecretProvider,
) -> None:
    """`src/worker/config.py` holds no key literal and reads the key through the adapter.

    Static first, over the file's bytes, never an import: the import allowlist (the
    starter's imports plus the supplied SecretProvider imports), the reach rules, no string
    literal equal to the first version's value, no literal or default factory in the
    `model_provider_key` field's place, no string literal inside `provider_key` other than
    the secret's name, and `provider_key` an `async def` of `WorkerSettings`. Then, with the
    store running, no version's value, whatever the store holds now, appears anywhere in
    the file's text. `poe config-binding` is the static half, run inside `poe verify`
    before the stack starts.
    """
    try:
        found = config_binding.application_findings(TASK_ROOT)
    except config_binding.ConfigBindingError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)
    source = (TASK_ROOT / CONFIG_PATH).read_text(encoding="utf-8")
    # The comparison is made in the helper and only its outcome is asserted, so a failing
    # row renders the version id and the file, never the value.
    versions = _versions_and_values(store)
    held = secret_tools.value_findings({CONFIG_PATH.as_posix(): source}, versions)
    assert held == [], "; ".join(held) + f"; {READ_HINT}"


def test_the_fix_changes_one_function_of_one_file_and_adds_no_import() -> None:
    """The one file changed beyond the four fixed permitted files is a bounded fix.

    `poe fix-binding`'s rules over the diff from the starting checkpoint: one Python file
    that existed there, no import added, every module-level statement as it was, exactly
    one function body changed with its signature kept, and no new path beyond application
    code. With nothing changed beyond the four files there is nothing to check.
    """
    try:
        found = fix_binding.findings(TASK_ROOT)
    except fix_binding.FixBindingError as exc:
        pytest.fail(str(exc))
    assert found == [], "; ".join(found)


@pytest.mark.runtime
def test_a_scenario_completes_and_the_worker_authenticated_with_the_current_version(
    api: httpx.Client, store: LocalStackSecretProvider
) -> None:
    """A scenario ends `COMPLETED`, and the worker authenticated with the store's current version.

    The current version is read from the store first; then one reading goes through the
    open intake and is awaited through the database; then the worker container's
    authentication record (what `poe provider-auth-check` prints) must show the most recent
    attempt accepted with that version's id. Versions are compared by id; no value is read.
    """
    try:
        current = asyncio.run(store.current_version(NAME))
    except SecretUnavailable as exc:
        pytest.fail(str(exc))
    try:
        submission, state = live_record.create_finished_submission(api, response="valid")
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    assert state == "COMPLETED", (
        f"the run ended in {state}; the provider accepts the current version of the key only "
        f"({READ_HINT})"
    )
    attempt = _auth_record().get("last_attempt")
    assert isinstance(attempt, dict) and attempt.get("outcome") == "accepted", (
        f"the worker's most recent authentication for {submission.exception_id} was not "
        f"accepted ({attempt!r})"
    )
    assert attempt.get("version_id") == current.version_id, (
        f"the worker authenticated with version {attempt.get('version_id')}; the store's "
        f"current version is {current.version_id} (`poe secret-status`)"
    )


# --- The inherited Task 3 and Task 4 controls ---------------------------------------------------


@pytest.mark.runtime
@pytest.mark.parametrize("response", REJECTED_RESPONSES)
def test_bad_responses_still_end_needs_review(
    interactions: dict[str, Interaction], response: str
) -> None:
    """The malformed and manipulated answers still end `NEEDS_REVIEW` with the policy's outcome."""
    interaction = interactions[response]
    assert interaction.state == "NEEDS_REVIEW", (
        f"the {response} response ended in {interaction.state}"
    )
    record = _record(interaction.exception_id)
    fixed = record.get("summary") == REVIEW_MESSAGE
    assert fixed, f"the {response} run's stored summary is not the output policy's fixed message"
    reason = record.get("rejection_reason")
    assert isinstance(reason, str) and reason.split(":")[0] in REASON_CODES, reason
    assert reason.split(":")[0] == EXPECTED_CODE[response], reason
    assert record.get("handling_class") is None and record.get("next_step") is None
    assert record.get("failure_reason") is None
    for field, value in record.items():
        if isinstance(value, str) and field != "summary":
            for text in MODEL_TEXT:
                assert text not in value, f"{field} carries the model's text ({text!r})"


@pytest.mark.runtime
@pytest.mark.parametrize("key", INTERACTION_IDS)
def test_the_audit_trail_still_reconstructs_one_interaction(
    interactions: dict[str, Interaction], key: str
) -> None:
    """Each interaction's trail is the four worker events, in order, then the one read."""
    interaction = interactions[key]
    assert interaction.body.get("state") == interaction.state
    record = _record(interaction.exception_id)
    records = _trail(interaction.exception_id)
    assert records, (
        f"no audit records for {interaction.exception_id}: the worker recorded no event and "
        "the route recorded no summary read"
    )

    findings = trail.sequence_findings(records, reads=1)
    assert findings == [], "; ".join(findings) + f"\n{trail.events_of(records)}"
    findings = trail.field_findings(records)
    assert findings == [], "; ".join(findings)
    expected = interaction.expected(record)
    findings = trail.value_findings(records, expected)
    assert findings == [], (
        "; ".join(findings)
        + " (the model-response digest is of the answer to the request the supplied worker "
        "sends, the note redacted)"
    )
    findings = trail.trace_findings(
        records, submission=interaction.submission.trace_id, reads=(interaction.read_trace_id,)
    )
    assert findings == [], "; ".join(findings)

    events = trail.events_of(records)
    assert events[2] == EXPECTED_DECISION[key], events
    outcome_stored = trail.details_of(records[3]) == {
        "state": interaction.state,
        "summary": record.get("summary"),
    }
    assert outcome_stored, (
        f"the {key} run's `outcome_stored` details are not its stored state and summary"
    )
    read = trail.details_of(records[4])
    assert read.get("subject") == DISPATCHER_SUBJECT and read.get("role") == DISPATCHER_ROLE, read


@pytest.mark.runtime
def test_pii_scan_still_finds_no_marked_value_from_n01_or_pii_echo(
    interactions: dict[str, Interaction],
) -> None:
    """`poe pii-scan` finds none of N-01's values and none of the pii-echo contact.

    The carried Task 4.4 redaction is supplied code: the N-01 run and the pii-echo run end
    `COMPLETED` with the expected redacted summary, and the four locations, read exactly as
    `poe pii-scan` reads them, hold none of the marked values. Findings are named by label.
    """
    n01 = interactions["n01-valid"]
    _completed_redacted(n01)
    values = pii.marked_values(pii.load_notes(TASK_ROOT), note=FIRST_NOTE)
    found = pii.render(pii.findings(_locations(n01.exception_id), values))
    assert found == [], f"marked values of {FIRST_NOTE} reached: " + "; ".join(found)

    echo = interactions[ECHO]
    _completed_redacted(echo)
    found = pii.render(pii.findings(_locations(echo.exception_id), pii.response_values(ECHO)))
    assert found == [], f"the {ECHO} contact reached: " + "; ".join(found)


# --- The inherited Task 2 control ---------------------------------------------------------------


@pytest.mark.runtime
def test_the_task_2_access_rule_still_protects_the_summary_route(api: httpx.Client) -> None:
    """`dispatcher-valid` reads `200`; the seven other fixtures and a bare request are refused."""
    try:
        exception_id = live_record.create_stored_exception(api)
    except live_record.StoredRecordError as exc:
        pytest.fail(f"the access row's precondition was not met: {exc}")
    for fixture in FIXTURE_NAMES:
        response = api.get(ROUTE.format(exception_id=exception_id), headers=bearer_headers(fixture))
        assert response.status_code == EXPECTED_STATUS[fixture], (
            f"{fixture}: {response.status_code} {_detail(response)}"
        )
        if EXPECTED_STATUS[fixture] != 200:
            assert "exception_id" not in response.text, f"{fixture}: the record was returned"
    bare = api.get(ROUTE.format(exception_id=exception_id))
    assert bare.status_code == 401, f"no token: {bare.status_code} {_detail(bare)}"
    assert "exception_id" not in bare.text


# --- Step 2: the replacement in place ----------------------------------------------------------


@pytest.mark.runtime
def test_a_replacement_takes_effect_without_a_restart_and_the_previous_version_is_rejected(
    api: httpx.Client, store: LocalStackSecretProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new version is stored; the next scenario authenticates with it; the old one is refused.

    First, in this process: the student's `WorkerSettings.provider_key` is read three
    times (as an async method, a plain method or a property, whichever it is) against a
    stand-in store whose current value changes on every read, and must read the secret
    three times and return three distinct values, so a read made once and kept, or kept
    after the first few requests, is named here whatever the live stack shows.
    Then, live: the worker container's identity is recorded before the replacement and
    compared after the scenario, so a worker that was recreated in between does not pass as
    one that read the new version in place. The previous version is then read from the
    store (in this process, never printed) and handed to the emulator's own key check,
    which must refuse it, and `poe secret-check-old`'s path reports the same.
    """
    reads, distinct = _per_use_read_probe(monkeypatch)
    assert reads == len(PROBE_VALUES), (
        f"over {len(PROBE_VALUES)} calls of WorkerSettings.provider_key() against a store whose "
        f"current version changed between the calls, the provider key's secret was read "
        f"{reads} time(s); each call must read the current version from the store ({READ_HINT})"
    )
    assert distinct == len(PROBE_VALUES), (
        f"over {len(PROBE_VALUES)} calls of WorkerSettings.provider_key() against a store whose "
        f"current version changed between the calls, {distinct} distinct value(s) came back; a "
        f"value kept from an earlier call is refused the moment the key is replaced ({READ_HINT})"
    )
    container_before = _worker_identity()
    try:
        previous = asyncio.run(store.current_version(NAME))
        created, _ = asyncio.run(secret_tools.replace(store, NAME))
    except SecretUnavailable as exc:
        pytest.fail(str(exc))
    try:
        submission, state = live_record.create_finished_submission(api, response="valid")
    except live_record.StoredRecordError as exc:
        pytest.fail(str(exc))
    assert state == "COMPLETED", (
        f"after the replacement (new version {created.version_id}) the run ended in {state}: the "
        f"worker presented a key the provider refused; {READ_HINT}"
    )
    attempt = _auth_record().get("last_attempt")
    assert isinstance(attempt, dict) and attempt.get("outcome") == "accepted", (
        f"the worker's most recent authentication for {submission.exception_id} was not "
        f"accepted ({attempt!r}); {READ_HINT}"
    )
    assert attempt.get("version_id") == created.version_id, (
        f"the worker authenticated with version {attempt.get('version_id')} after version "
        f"{created.version_id} became current; {READ_HINT}"
    )
    container_after = _worker_identity()
    assert container_after == container_before, (
        "the worker container was recreated between the replacement and the scenario; the "
        "replacement must take effect without a restart"
    )
    try:
        rejected, old, reason = asyncio.run(secret_tools.check_old(store, NAME))
    except (SecretUnavailable, secret_tools.SecretToolError) as exc:
        pytest.fail(str(exc))
    assert old.version_id == previous.version_id, (
        f"the store's previous version is {old.version_id}, not the version that was current "
        f"before the replacement ({previous.version_id})"
    )
    assert rejected, f"the provider accepted the previous version {old.version_id}: {reason}"


# --- No output holds a value ------------------------------------------------------------------


@pytest.mark.runtime
def test_no_output_contains_any_versions_value(
    store: LocalStackSecretProvider, interactions: dict[str, Interaction]
) -> None:
    """No command output, container log, audit record or stored record holds a version's value.

    Every version the store holds is read into this process. Then the outputs of
    `poe secret-status`, `poe secret-check-old` and `poe provider-auth-check`, the worker,
    API and initializer logs, and the audit trail and stored record of every interaction
    this module made are searched for each value. A finding names the version and the
    output, never the value.
    """
    outputs: dict[str, str] = {}
    for command in ("status", "check-old"):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            secret_tools.main([command, "--root", str(TASK_ROOT)])
        outputs[f"poe secret-{command}"] = stdout.getvalue() + stderr.getvalue()
    auth = _compose("exec", "-T", "worker", "python", "-m", "worker.provider_auth")
    outputs["poe provider-auth-check"] = auth.stdout + auth.stderr
    for service in ("worker", "api", "initializer"):
        logs = _compose("logs", "--no-color", service)
        outputs[f"docker compose logs {service}"] = logs.stdout + logs.stderr
    for interaction in interactions.values():
        outputs[f"audit trail of {interaction.exception_id}"] = json.dumps(
            _trail(interaction.exception_id), default=str
        )
        outputs[f"stored record of {interaction.exception_id}"] = json.dumps(
            _record(interaction.exception_id), default=str
        )
    leaks = secret_tools.value_findings(outputs, _versions_and_values(store))
    assert leaks == [], "; ".join(leaks)


# --- Step 3: the gate ---------------------------------------------------------------------------


def test_gate_thresholds_fail_any_secret_and_a_high_vulnerability() -> None:
    """`security/gate.yaml` meets the policy: secrets `any`, dependencies `high`, static failing.

    The file must be valid (each threshold one of its allowed values) and then: any
    unsuppressed secret finding fails the gate, a known high-severity vulnerability fails
    it, and the static-analysis threshold is one of the failing values you chose.
    """
    thresholds = _thresholds()
    findings = gate.policy_findings(thresholds)
    assert findings == [], "; ".join(findings)
    assert thresholds.fails("gitleaks", gate.SECRET)
    assert thresholds.fails("trivy", "high")


def test_the_clean_tree_scan_passes_with_the_thresholds_and_writes_both_reports(
    clean_report: scanners.Report,
) -> None:
    """With your thresholds and your `.gitleaks.toml`, the working tree passes the gate.

    The three scanners run over a copy of the files Git tracks or would track; no
    unsuppressed finding may be at or above a threshold; and `reports/security/scan.sarif`
    and `reports/security/sbom.cdx.json` are written as `poe security-scan` writes them.
    """
    failing = [clean_report.id_of(finding) for finding in clean_report.failing]
    assert clean_report.passed, (
        f"the working tree fails the gate: {', '.join(failing)} at or above a threshold "
        "(fix the finding you triage as valid, suppress the false positive, and leave the "
        "accepted ones below the threshold)"
    )
    try:
        sarif_path, sbom_path = scanners.write_reports(
            clean_report, TASK_ROOT / scanners.REPORTS_DIRECTORY
        )
    except scanners.ScanError as exc:
        pytest.fail(str(exc))
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert sarif.get("version") == "2.1.0"
    assert [run["tool"]["driver"]["name"] for run in sarif.get("runs", [])] == list(
        scanners.SCANNERS
    )
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert sbom.get("bomFormat") == "CycloneDX", "the bill of materials is not CycloneDX"
    assert sbom.get("components"), "the bill of materials lists no component"


def test_the_seeded_secret_fails_the_scan_on_a_gitleaks_finding() -> None:
    """A copy of the tree with the fake key seeded fails the gate on the Gitleaks finding.

    `poe seed-secret`'s file is written into a temporary copy of the working tree and the
    copy is scanned with your thresholds and your `.gitleaks.toml`: the gate must fail, and
    one failing finding must be the supplied rule's match in the seed's path.
    """
    try:
        report = scanners.scan_seeded("secret", TASK_ROOT, _thresholds())
    except scanners.ScanError as exc:
        pytest.fail(str(exc))
    seed_path = seeds.SECRET_SEED_PATH.as_posix()
    seeded = [
        finding
        for finding in report.failing
        if finding.scanner == "gitleaks" and finding.path == seed_path
    ]
    assert not report.passed, (
        f"the copy with the seeded key passes the gate; `secrets` must be `any` so the "
        f"Gitleaks finding in {seed_path} fails it"
    )
    assert seeded, (
        f"no failing Gitleaks finding names {seed_path}; the supplied rule "
        f"`{seeds.SUPPLIED_RULE_ID}` in .gitleaks.toml must find the seeded key and the "
        "entry you added must not cover that path"
    )
    assert seeded[0].rule == seeds.SUPPLIED_RULE_ID, (
        f"the seeded key was found under rule {seeded[0].rule}, not the supplied rule"
    )


def test_the_seeded_vulnerable_dependency_fails_the_scan_on_a_trivy_finding() -> None:
    """A copy of the tree with the vulnerable pin seeded fails the gate on the Trivy finding.

    `poe seed-vulnerable`'s file is written into a temporary copy of the working tree and
    the copy is scanned with your thresholds: the gate must fail, and one failing finding
    must be a high or critical Trivy finding in the seed's path.
    """
    try:
        report = scanners.scan_seeded("vulnerable", TASK_ROOT, _thresholds())
    except scanners.ScanError as exc:
        pytest.fail(str(exc))
    seed_path = seeds.VULNERABLE_SEED_PATH.as_posix()
    seeded = [
        finding
        for finding in report.failing
        if finding.scanner == "trivy" and finding.path == seed_path
    ]
    reported = [finding for finding in report.findings if finding.path == seed_path]
    assert reported, (
        f"Trivy reports nothing in {seed_path}; the pinned database must know the seeded "
        "release (run `poe security-setup` and the scan again)"
    )
    assert not report.passed and seeded, (
        f"the copy with the seeded dependency passes the gate; `dependencies` must be `high` so "
        f"the {reported[0].severity} finding(s) in {seed_path} fail it"
    )
    assert all(finding.severity in ("high", "critical") for finding in seeded)


def test_the_gitleaks_entry_names_the_rule_and_single_path_of_the_suppressed_finding(
    inventory_report: scanners.Report, clean_report: scanners.Report
) -> None:
    """The one allowlist entry suppresses exactly `answers.suppressed_finding`.

    The finding named must be one the scan reports on your tree with no allowlist applied
    (`poe security-scan --inventory`), and a Gitleaks one; `.gitleaks.toml` must be the
    supplied configuration, as parsed, plus exactly one `[[allowlists]]` entry whose
    `targetRules` is that finding's rule and whose `paths` is the one anchored, escaped
    pattern of its single file, with no other key and the comment the gate policy describes
    over it; and with your configuration applied the finding must be gone from the report.
    """
    suppressed = _named_finding("suppressed_finding")
    finding = inventory_report.finding(suppressed)
    assert finding is not None, (
        f"{suppressed} is not a finding the scan reports on your tree with no allowlist "
        "applied; run `poe security-scan --inventory` and record one of its ids"
    )
    assert finding.scanner == "gitleaks", (
        f"{suppressed} is a {finding.scanner} finding; the Task's one suppression is a Gitleaks "
        "allowlist entry, so answers.suppressed_finding names a Gitleaks finding"
    )
    text = (TASK_ROOT / suppression.CONFIG_PATH).read_text(encoding="utf-8")
    findings = suppression.entry_findings(
        text, rule=finding.rule, path=finding.path, finding_id=suppressed
    )
    assert findings == [], "; ".join(findings)
    assert clean_report.finding(suppressed) is None, (
        f"{suppressed} is still reported with your .gitleaks.toml applied; the entry does not "
        "suppress it"
    )


def test_every_starting_checkpoint_finding_has_one_triage_value(
    baseline_report: scanners.Report,
) -> None:
    """`answers.triage` has one value for every finding of the starting checkpoint, and no other.

    The starting checkpoint (the merge base of this branch with `main`) is exported from
    Git and scanned with the supplied configuration; its finding ids are the keys
    `answers.triage` must hold. Which value each gets is the protected check's question.
    """
    triage = _answers().get("triage")
    assert isinstance(triage, dict) and triage, (
        "answers.triage is empty; record one triage value per finding id `poe security-scan` "
        "printed on the starting checkpoint"
    )
    reported = {baseline_report.id_of(finding) for finding in baseline_report.findings}
    missing = sorted(reported - set(triage))
    extra = sorted(set(triage) - reported)
    assert not missing, (
        f"answers.triage has no value for {', '.join(missing)}, which the starting checkpoint "
        "reports"
    )
    assert not extra, (
        f"answers.triage names {', '.join(extra)}, which the starting checkpoint does not report"
    )


def test_the_fixed_finding_names_the_one_changed_file_and_a_finding_is_gone_from_it(
    baseline_report: scanners.Report, inventory_report: scanners.Report
) -> None:
    """The file `answers.fixed_finding` names is the one changed file, and that finding left it.

    The finding named must be one of the starting checkpoint's; the one file changed beyond
    the four fixed permitted files must be the file that finding names; and in that file
    the named finding must be gone, every other finding of the starting checkpoint must
    still be reported (a fix removes the finding it names and nothing else), and none may
    be added. Ids are content-derived, so the same finding has the same id on the starting
    checkpoint and on your tree. Which finding was the right one to fix is the protected
    check's question: a sheet that names the wrong finding passes here only if that finding
    was really removed.
    """
    fixed = _named_finding("fixed_finding")
    finding = baseline_report.finding(fixed)
    assert finding is not None, (
        f"{fixed} is not a finding of the starting checkpoint; answers.fixed_finding names one "
        "of the ids the scan printed before your fix"
    )
    try:
        changed = repository.changed_paths(TASK_ROOT)
    except repository.RepositoryError as exc:
        pytest.fail(str(exc))
    extra = fix_binding.candidate_paths(changed)
    assert extra == [finding.path], (
        f"the files changed beyond the four fixed permitted files are "
        f"{', '.join(extra) or 'none'}; the finding named by answers.fixed_finding is in "
        f"{finding.path}, which is the one file the fix may change"
    )
    before = {
        baseline_report.id_of(item) for item in scanners.findings_in(baseline_report, finding.path)
    }
    after = {
        inventory_report.id_of(item)
        for item in scanners.findings_in(inventory_report, finding.path)
    }
    added = sorted(after - before)
    assert not added, f"{finding.path} reports new finding(s) {', '.join(added)}; a fix adds none"
    assert fixed not in after, (
        f"{fixed} is still reported in {finding.path} with your change applied; the fix removes "
        "the finding answers.fixed_finding names"
    )
    missing = sorted(before - {fixed} - after)
    assert not missing, (
        f"{finding.path} no longer reports {', '.join(missing)}, which the starting checkpoint "
        f"reports beside {fixed}; the fix removes the one finding answers.fixed_finding names and "
        "leaves every other finding of the file as it was"
    )


# --- The answer sheet ---------------------------------------------------------------------------


def test_submission_answers_use_the_allowed_values() -> None:
    """`submission.yaml` carries a triage map and two finding ids in the published shape.

    The public format check: a non-empty triage map keyed by finding ids with the three
    allowed values, the fixed and the suppressed finding each one of its keys and not the
    same id, and the sheet not a copy of the fictional sample. Which values are right is
    the protected answer check's question, after the submission on the platform.
    """
    try:
        validate_submission(
            TASK_ROOT / "submission.yaml",
            TASK_ROOT / "docs/contracts/submission.schema.json",
            sample_path=TASK_ROOT / "submission-sample.yaml",
            task_root=TASK_ROOT,
        )
    except SubmissionError as exc:
        pytest.fail(str(exc))
