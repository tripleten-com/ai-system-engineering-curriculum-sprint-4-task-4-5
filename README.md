# Coldline Task 4.5 — Secret and CI security gate

This repository starts from the Task 4 checkpoint, with the settled token verification and
access rule from Task 2, the settled output guardrail and audit events from Task 3, and the
settled PII redaction from Task 4, and adds LocalStack Secrets Manager, the supplied
`SecretProvider` adapter, and a security workflow. At this checkpoint the worker's model
provider key is a string default on `WorkerSettings` in `src/worker/config.py`: anyone who can
read the repository has it, and every deployment that does not override it runs with it. The
secret store already holds that key under the name in `docs/fidelity/SecretProvider.md`, the
adapter reads the current version on every call, and the model emulator accepts only the key's
current version. The `security-gate` job in `.github/workflows/security.yml` runs Semgrep, Trivy
and Gitleaks over the files at each pull request's head but reports without failing: its
thresholds come from `security/gate.yaml`, and `docs/security/gate-policy.md` states what the
gate must fail and defines the three triage values. You move the key behind `SecretProvider`,
replace it once and confirm the version, set the thresholds, triage the inherited findings, fix
one and suppress one, and prove the gate on two seeded branches.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-5/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. If your computer cannot run the stack locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe security-setup
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe ingest
```

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

`poe security-setup` is the one network step of the security gate: it pulls the three scanner
images by digest (several hundred megabytes on the first run) and downloads the pinned
vulnerability database into the Git-ignored `.tools/trivy-cache/`, under a directory named by
the pinned digest and beside a marker that records it, so a re-pinned database is never
mistaken for the old one. Every scan after it runs offline. `poe security-scan` runs the
download itself when the database is missing.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Token issuer: discovery document | `http://localhost:8180/.well-known/openid-configuration` | The development issuer's OIDC discovery document: its `issuer` and `jwks_uri` |
| Token issuer: key set | `http://localhost:8180/.well-known/jwks.json` | The published key set (JWKS) the settled `config/auth.yaml` names |
| Jaeger | `http://localhost:16686` | Open traces; the trace ids the audit records carry are these |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS/Secrets Manager | `http://localhost:4566` | The emulated object-storage, queue and secret-store endpoint; the secret tools reach it here |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_ISSUER_HOST_PORT`, `COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`,
`COLDLINE_PROMETHEUS_HOST_PORT`, `COLDLINE_ALERTMANAGER_HOST_PORT`, or
`COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your shell environment or a local
`.env` file (copy `.env.example`) if a default collides with something already running on your
machine. Keep the override in place for every `poe` command. If you remap the issuer port,
keep `config/auth.yaml` unchanged: it is supplied in this Task and names the default port.
Host-side tools (the in-process test harness and `poe token-check`) resolve the issuer's
origin from `COLDLINE_ISSUER_HOST_PORT` (the environment, then `.env`, then the default), the
secret tools resolve LocalStack's host port from `COLDLINE_LOCALSTACK_HOST_PORT` the same way,
and the API and the worker use the Compose-network origins.

This Task runs as its own Compose project, `coldline-task-4-5`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

### After you edit a file

The worker image carries `src/worker/config.py` and the rest of `src/` as they were when it was
built. After editing your settings module or the file your fix goes in, run `poe start` again:
it rebuilds the images and recreates the containers, which is what the Task page means by
"restart the stack as `README.md` describes". `poe restart` restarts the existing containers
**without rebuilding** and is not enough. `security/gate.yaml` and `.gitleaks.toml` are read by
`poe security-scan` from your checkout and need no rebuild. The secret store keeps no state
across `poe reset` (persistence is off in LocalStack), so `poe reset` and `poe start` give a
store that holds the first version again.

## Command path

For this Task, run the supplied commands in this order:

```text
poe security-setup
poe start
poe ingest
poe scenario                             # Step 1, after your change and `poe start` again
poe secret-status
poe provider-auth-check
poe secret-replace                       # Step 2
poe scenario
poe provider-auth-check
poe secret-check-old
poe security-scan                        # Step 3: every finding, before your fix and suppression
poe security-scan                        # after them: the gate passes and both reports are written
poe answers
poe seed-secret                          # Step 4, on a draft branch from your Step 3 commit
poe seed-vulnerable                      # Step 4, on a second draft branch
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe security-setup` | Pull the three pinned scanner images and download the pinned vulnerability database into `.tools/trivy-cache/<digest prefix>/`, once; idempotent, and a cache downloaded for another digest is never reused |
| `poe scenario [--response <name>] [--note <id>]` | Send the supplied reading with a fresh identity and wait for a finished state; print the exception id, the state, and the trace ids. One scenario is one request the worker authenticates with the provider |
| `poe secret-status` | Print the provider key's current version id and fingerprint, the previous version's when there is one, and how many versions the store holds. Never a value |
| `poe secret-replace` | Generate a new value, store it as the current version, and print the new version's id and fingerprint and the previous version's id. Never a value |
| `poe provider-auth-check` | Print, from the record inside the worker container, the version id and fingerprint the worker last authenticated with, and a refusal when the most recent attempt was one. Exit 1 when the worker has not authenticated yet in this container (run `poe scenario` first) |
| `poe secret-check-old` | Read the previous version from the store and hand it to the emulator's key check: reports `rejected` with the reason (exit 0) or, which must not happen, an acceptance (exit 1); exit 2 while the store holds one version only |
| `poe security-scan` | Run Semgrep (the supplied rules, offline, inline `nosemgrep` markers ignored), Trivy (`uv.lock`, the pinned database) and Gitleaks (the checked-out files, your `.gitleaks.toml`, inline `gitleaks:allow` markers ignored) over a copy of the files Git tracks or would track; print every finding with its stable `F-nn` id, scanner, severity, file, lines and rule; mark the ones at or above the thresholds in `security/gate.yaml`; write `reports/security/scan.sarif` and `reports/security/sbom.cdx.json`; exit 1 exactly when an unsuppressed finding is at or above a threshold. `--inventory` applies the supplied Gitleaks configuration (every secret finding, no allowlist, no reports); `--baseline` scans the starting checkpoint; `--seed secret` or `--seed vulnerable` scans a temporary copy with that seed applied and leaves your checkout alone |
| `poe seed-secret`, `poe seed-vulnerable` | Write the supplied fake key to `security/seed/provider-key.txt`, or the supplied vulnerable pin to `security/seed/requirements.txt`, for a demonstration branch. Both paths are outside the permitted files |
| `poe config-binding` | Read `src/worker/config.py` without running it: only the starter's imports and the supplied `SecretProvider` imports (`from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider`, `from ports import SecretProvider`), no string literal equal to the first version's value, no literal or default factory in the `model_provider_key` field's place, no string literal inside `provider_key` other than the secret's name, `provider_key` an `async def` of `WorkerSettings` with the starter's signature (`async def provider_key(self) -> str`, no decorator, no default), no call to or use of `open`, `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `vars`, `locals`, `dir`, `input` or `breakpoint`, nothing at module level but the docstring, imports, the one class and literal assignments, `WorkerSettings` the only class in the file with the starter's head and a body of inert field assignments, `model_config` and `provider_key`, no dunder name anywhere, every field and module-level name annotated with a builtin type (`str`, `int`, `float`, `bool`, `None`, `dict`, `list`, `tuple`, a `dict`/`list`/`tuple` over them, or a `|` union) and no string annotation anywhere, and no path to the test runner (no `sys`, `importlib`, `unittest`, frame access, ...). A step of `poe verify` before the stack starts |
| `poe fix-binding` | Compare the one file changed beyond the four fixed permitted files with its starting-checkpoint copy: a Python file that existed there, no import added, every module-level statement as it was (a class with its bases, keywords, decorators and type parameters), exactly one function body changed with its signature kept (a comment or a `# nosemgrep` marker alone is not a change), none of `open`, `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `vars`, `locals`, `input` or `breakpoint` and no dunder name in that function, and no new path beyond application code. With nothing changed beyond the four files, nothing to check. A step of `poe verify` before the stack starts |
| `poe runtime-logs` | What the hosted jobs print when they fail: the runtime containers' logs with every stored version of the provider key replaced by `[provider-key version <id>]`, one group per service; a diagnostic and no logs when the versions cannot be read. Usable locally after a failed run, while the stack is still up |
| `poe integrity-record`, `poe integrity-check` | The first and last steps of `poe verify`: hash your files and the checks' own files into a snapshot outside the repository, then compare the tree with it, so a file that changed while the run was in progress is named |
| `poe security-contract` | The assessed rows: the settings module (static, then every stored version), the bounded fix, the scenario and the worker's authenticated version, the inherited Task 2, 3 and 4 rows, the replacement in place and the previous version refused, no value in any output, the thresholds against the policy, the clean tree passing with both reports, each seed failing on its finding, the suppression entry, the triage ids against the starting checkpoint, the fix file against the named finding, and the sheet's format. Runs the module through `tests/security/assessed_run.py`, which requires every registered check to have executed and passed |
| `poe pii-scan <exception_id>`, `poe redaction-report`, `poe model-request <exception_id>`, `poe audit-trail <exception_id>` | Task 4's tools, kept for the inherited rows and for diagnosis |
| `poe token-check <fixture>`, `poe auth-checks`, `poe auth-config` | Task 2's diagnosis tools over the settled `config/auth.yaml` and the access rule, kept |
| `poe student-tests` | Run the supplied tests under `tests/student/`: the carried Task 4.4 redaction tests, the carried Task 4.3 guardrail and audit tests, and the settled Task 4.2 access tests. None is yours in this Task |
| `poe answers` | The answer sheet's format only: a non-empty triage map keyed by finding ids with the three allowed values, `fixed_finding` and `suppressed_finding` each one of the map's keys and not the same id, and the sheet not a copy of `submission-sample.yaml` |
| `poe submission` | The same check plus the permitted-files boundary: the diff from your merge base touches only the four fixed permitted files and the file the finding in `answers.fixed_finding` names in the scan of the starting checkpoint (resolved through the scanners, so Docker is needed) |
| `poe verify` | The public student verification path: it starts the stack, exercises the inherited platform, and runs this Task's own checks |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract` | Project 3's own checks, inherited and passing as shipped; `poe verify` runs them |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe smoke` | Check the initialized running platform, including the issuer's documents |
| `poe e2e` | Run the external API-to-worker workflow, including the joined trace |
| `poe migrate`, `poe migrate-down`, `poe migrate-current` | Step the schema by hand; the initializer brings it to head on every start |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes |

`poe verify` records an integrity snapshot of your files and the checks' own files, runs the
static checks of your settings module and your fix before anything imports either, then the unit
tests; it starts the stack, ingests the supplied corpus, runs the smoke tests, then this Task's
assessed checks: the settings module against every version the store holds, one scenario and
the version the worker authenticated with, the inherited refused answers, audit trail, PII scan
and access rule, a replacement it stores itself followed by a scenario (the new version
authenticated, the container not recreated, the previous version refused), the tools' outputs
and the container logs searched for every version's value, the thresholds against the policy,
the three scanners over your tree (the gate passes, both reports written) and over a temporary
copy with each seed applied (the gate fails on the seed's finding), the suppression entry
against the scan with no allowlist, the triage ids against the scan of the starting checkpoint,
and the fix file against the finding it names; then the end-to-end exception workflow, the
inherited queue, SLO, gate, and runbook checks, the supplied tests under `tests/student/`, the
answer-sheet format check, the permitted-files boundary, and finally the integrity check against
the snapshot. When the assessed step ends, the value that was current when it began is stored
again as a new current version, so a second run judges the same thing. Each assessed step
requires every one of its registered checks to have executed and passed. The Project 3 exercise
commands (`poe inject-failure`, `poe redrive`, `poe trigger-alert-load`,
`poe verify-alert-recovery`, `poe dev-failure-lab`) still run but are not part of this Task.

## Folder map

```text
repository root/
├── .gitleaks.toml       The secret-scanner configuration: the default rules, the supplied provider-key rule, your one allowlist entry
├── .semgrepignore       The paths Semgrep leaves out
├── config/              Retrieval configuration, settled since Sprint 2, and the settled auth.yaml
├── docs/                Student guidance, public contracts, fidelity notes, and the security material
│   ├── contracts/       Machine-readable public contracts, including this Task's answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter, including the secret store and the emulator's key check
│   ├── security/        The supplied workflow, threat catalog, control matrix, access policy, output policy, audit events, redactor, and gate policy
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, the settled threat model, and the supplied Project 3 runbook
├── infra/               Local setup and runtime configuration
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── issuer/          The development token issuer: its server script and the published key set
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus (one procedure carries the planted instruction), query set, and investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions
├── reports/             Git-ignored: the scan report and the bill of materials `poe security-scan` writes
├── schemas/             The supplied output schema the guardrail enforces
├── security/            The gate's thresholds (yours), the scanner pins, the supplied Semgrep rules, and the seed files a demonstration branch carries
├── src/
│   ├── api/             HTTP application code, the retrieval and document paths, composition, the initializer, the audit-trail command
│   │   └── security/    The settled TokenVerifier and require_access rule; not student-editable
│   ├── worker/          Background application code, your settings module, the procedure lookup, the supplied guardrail, the carried redaction, the record readers
│   ├── common/          The supplied audit sink and the supplied redactor both services may use; not student-editable
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations, including the secret-store adapter, the model emulator with its key check, the audit store, the SQS adapter
└── tests/
    ├── unit/            Isolated behavior checks, including the adapter's, the key check's, the scan tooling's and the static checks'
    ├── benchmark/       Supplied evaluation harness, metrics, and adoption policy
    ├── contract/        Interface, retrieval, and repository checks, and this Task's assessed security checks
    ├── diagnostics/     Supplied stage inspector
    ├── doubles/         Supplied deterministic test doubles
    ├── failure/         Supplied Project 3 failure-lab and exercise scripts; not this Task's work
    ├── fixtures/        Supplied fixtures: the token fixtures, the credential values, and the supplied handling notes under pii/
    ├── security/        Supplied tooling: the scanners, the gate, the seeds, the suppression reader, the secret tools, the static checks, the integrity bookends, the inherited harness and scan
    ├── student/         The carried Task 4.4, 4.3 and 4.2 tests; none is yours in this Task
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks, including `poe scenario`
```

## Overview

Use the Task 5 lesson (Task 4.5 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-5-contract.md`](docs/student/task-4-5-contract.md) — what this Task
   assesses and who assesses it, the Check-list rows and the checks that read them, and the
   permitted paths.
3. [`docs/fidelity/SecretProvider.md`](docs/fidelity/SecretProvider.md) — the secret's name, the
   adapter's call form, the read timing, the tools, and what the local store does not show.
4. [`docs/security/gate-policy.md`](docs/security/gate-policy.md) — what the gate scans, what it
   must fail, the three triage values, the suppression's form, and the demonstration branches.
5. [`security/gate.yaml`](security/gate.yaml) — the three thresholds and their allowed values.
6. [`.gitleaks.toml`](.gitleaks.toml) — the secret-scanner configuration your one entry goes in.
7. [`src/adapters/secrets/localstack.py`](src/adapters/secrets/localstack.py) — the supplied
   adapter, with the call form in its docstring.
8. [`docs/student/threat-model.md`](docs/student/threat-model.md) — the settled Task 1 threat
   model this Project's controls answer; C-05 and C-06 are this Task's controls.

The application source lives in six flat packages:

| Package | Responsibility |
|---|---|
| `api` | HTTP delivery, API use cases, the retrieval workflow, versioned routes, token verification and the access rule, configuration, composition, the initializer, and the audit-trail command |
| `worker` | Background processing, retries, procedure lookup, the output guardrail, the redaction, the record readers, configuration (your settings module), and composition |
| `common` | The audit sink and the redactor the API and the worker share, and the event names |
| `domain` | Provider-neutral contracts, state rules, identity, embedding, chunking, fusion, access constraints, failure classification, service and repository contracts |
| `ports` | Exactly five visible application interfaces |
| `adapters` | PostgreSQL (exception records and audit records), pgvector retrieval, LocalStack SQS/DLQ, S3-compatible object storage, LocalStack Secrets Manager, the deterministic model emulator with its supplied responses, request log and key check, the resilient model-provider wrapper, logs, traces |

`src/api/bootstrap.py` and `src/worker/bootstrap.py` compose each process from its settings and
adapters. Process settings live in `src/api/config.py` and `src/worker/config.py`; the token
verification settings live in `config/auth.yaml`.

## The five ports

Find the available interfaces in `src/ports/`. A port describes an application capability; an
adapter provides it using a concrete technology.

| Port | General responsibility |
|---|---|
| `ModelProvider` | Call an AI model service; it returns the provider's raw answer text, which the worker redacts and the guardrail checks, and from this Task it authenticates the key the client presents |
| `Retriever` | Look up relevant context or documents; the worker calls it too |
| `ObjectStore` | Store large binary objects or files |
| `JobQueue` | Publish and consume background work |
| `SecretProvider` | Read API keys and credentials; the supplied LocalStack Secrets Manager adapter provides it from this Task |

## Test levels

| Level | Requires Compose | Main question |
|---|---|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |
| Student | Issuer | Do the carried Task 4, 3 and 2 tests still hold over the supplied code? |

Contract checks marked `runtime` need the running stack. `poe contract` skips them; `poe verify`,
`poe runtime-contract`, `poe queue-contract`, `poe slo-contract`, and `poe gate-contract` run them.
Contract checks marked `assessed` read your files, the running stack, the secret store and the
scanners, and are expected to fail on a fresh checkout; `poe contract` skips them too, and
`poe security-contract` and `poe verify` run them.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe answers` first so a malformed sheet fails fast, and the
`security-gate` job runs `poe security-scan` with your thresholds and your suppression. The
protected answer check compares your triage map and your fixed finding with the expected
values after you submit on the platform; no file in this repository holds those values. Follow
the Task lesson's instructor-review and progression policy.

## Task boundary

Task 4.5 asks you to change how `src/worker/config.py` reads the provider key, set the three
thresholds in `security/gate.yaml`, add one allowlist entry to `.gitleaks.toml`, fix the finding
you triage as `valid` in the file it names, record the triage, the fixed finding and the
suppressed finding in `submission.yaml`, run `poe verify`, open a pull request that changes only
those files, and add the two version ids with the `poe provider-auth-check` and
`poe secret-check-old` outputs, the four `security-gate` run URLs, your suppression's
justification, and the link to the report artifact to the pull request description, with each
command and when you ran it.

The only student-editable paths are:

- `src/worker/config.py`
- `security/gate.yaml`
- `.gitleaks.toml`
- `submission.yaml`
- The one file named by the finding you triage as `valid`

Keep the adapter (`src/adapters/secrets/`), the provider-key check
(`src/adapters/model/provider_keys.py`), the
scanner pins and rules (`security/scanners.yaml`, `security/semgrep-rules.yaml`,
`.semgrepignore`), the workflows (`.github/workflows/`), the seeds, the carried Task 4.4 files
(`src/worker/use_cases.py`, `tests/student/test_redaction.py`), the carried Task 4.3 and settled
Task 4.2 material, the supplied tests, `compose.yaml` and `pyproject.toml` exactly as supplied;
the public check compares the diff from your merge base against the permitted files and reports
any other change as a boundary violation. In `src/worker/config.py`, every setting but the key
read stays where it is.

### Student walkthrough

See **Task 5: Secret and CI security gate** in your course platform for the full walkthrough. In
outline: start the stack and prepare the scanners, make the key a read through `SecretProvider`
and confirm the version the worker authenticated with, replace the key and confirm the new
version and the refusal of the old one, set the thresholds, triage every finding, fix one and
suppress one, prove the gate on two seeded draft branches, run `poe verify`, open and merge your
pull request, and submit on the platform.

## Operational limits

This local system does not authenticate users against a managed identity provider, terminate
TLS, or manage production secrets. The token issuer is a development service: it publishes one
fixed key set over plain HTTP and issues no tokens; the eight fixtures were signed once and
committed. The Compose PostgreSQL password and the LocalStack access keys are development
values, listed once more in `tests/fixtures/credentials/test-values.yaml` so the audit checks
can search for them; the worker's provider key starts as a development value too, which this
Task moves and replaces. Never place real credentials, personal data, or production records in
this repository. Every handling note in this repository is synthetic. Test with the supplied
readings, notes, and seeds only.

The secret store is LocalStack Secrets Manager: it shows that the worker reads the current
version of one secret through one adapter on each use and that a replaced value takes effect
without a restart. It does not show how AWS Secrets Manager, IAM, or KMS would control who may
read the secret or how it is stored, and it keeps no audit of reads. See
[SecretProvider fidelity](docs/fidelity/SecretProvider.md). The emulator's key check is a
property of this emulator; a hosted provider authenticates keys its own way. See
[ModelProvider fidelity](docs/fidelity/ModelProvider.md).

The scanners find what their rules and their database cover, at the versions pinned in
`security/scanners.yaml`, over the files at the pull request's head: an absent finding is not an
absent weakness, a removed secret stays in the history of every clone that fetched it, and the
operating-system packages of the base image are outside the gate's scan, as
`docs/security/gate-policy.md` states. The gate fails only on unsuppressed findings at or above
the thresholds you set, and a suppression hides a finding from the verdict, not from the file.

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

LocalStack's SQS emulation is a local reliability primitive, not a managed-service durability,
IAM, availability, or cost claim. Stopping and starting one Compose container is a local fault
control, not an ECS service event. See [JobQueue fidelity](docs/fidelity/JobQueue.md) for the
exact boundary.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`; the audit table is in the PostgreSQL volume. LocalStack object, queue and
secret contents are deliberately not persisted; the initializer re-uploads the supplied corpus
artifacts, re-provisions the queue and re-creates the secret's first version on every start. The
worker's request records and its authentication record live inside the worker container and are
gone when it is recreated. The `poe reset` command deletes the named volumes. This topology makes
no backup, replication, high-availability, disaster-recovery, capacity, latency-SLO, or
availability claim beyond what Project 3 settled.

See [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md),
[JobQueue fidelity](docs/fidelity/JobQueue.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[SecretProvider fidelity](docs/fidelity/SecretProvider.md),
[ObjectStore fidelity](docs/fidelity/ObjectStore.md), and
[Retriever fidelity](docs/fidelity/Retriever.md) for the active adapter boundaries. The
[local runtime evidence](docs/fidelity/local-runtime.md) records the current measurement and its
qualification limits.
