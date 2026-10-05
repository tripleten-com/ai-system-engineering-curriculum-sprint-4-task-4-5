# Task 4.5 — Secret and CI security gate contract

Move the model provider key behind the supplied `SecretProvider` adapter and turn the supplied
security workflow into a gate. You change how `src/worker/config.py` reads the key, set the
thresholds in `security/gate.yaml`, triage every finding `poe security-scan` reports on the
starting checkpoint, fix the one you triage as `valid` in the file it names, add one bounded
suppression to `.gitleaks.toml`, and record the triage, the fixed finding and the suppressed
finding in `submission.yaml`. You write no adapter, no scanner rule and no workflow; you change
no other file.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| The pull request changes only `src/worker/config.py`, `security/gate.yaml`, `.gitleaks.toml`, `submission.yaml`, and the one file named by the finding in `answers.fixed_finding` | Automated, in this repository; the fifth file is resolved by scanning the starting checkpoint with the supplied scanners and reading the named finding's file out of that scan |
| Nothing under the permitted files or the checks' own files changed while `poe verify` ran | Automated: `poe verify` records a hash snapshot as its first step and checks it as its last |
| `src/worker/config.py` imports nothing beyond the starter's imports and the supplied `SecretProvider` imports, holds no string literal equal to any version's value, holds no literal or default factory in the `model_provider_key` field's place and no string literal inside `provider_key` other than the secret's name, defines `WorkerSettings.provider_key` as an `async def` with the starter's signature, calls no builtin that reads or writes files, runs text as code or reaches a namespace by name, holds nothing at module level but the docstring, imports, the one class and literal assignments, defines `WorkerSettings` as its only class with the starter's head and a body of inert field assignments, `model_config` and `provider_key`, spells no dunder name, annotates every field with a builtin type and nothing with a string, and reaches nothing beyond application code | Automated, static, over the file's bytes, never an import (`poe config-binding`, inside `poe verify` before the stack starts); the live row re-reads every version from the store |
| The one file changed beyond the four fixed permitted files is a Python file of the starting checkpoint that differs in the body of exactly one function (a comment or a suppression marker alone is not a change; a class head counts as a module-level statement), holds no forbidden builtin in that function (`open`, `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `vars`, `locals`, `input`, `breakpoint`, called or handed on) and no dunder name, with no import added and no new path beyond application code | Automated, static, from the diff against the starting checkpoint (`poe fix-binding`, inside `poe verify` before the stack starts) |
| A scenario ends `COMPLETED` and the worker authenticated with the store's current version | Automated, against the running stack (`poe verify`): one reading through the open intake, the record awaited through the database, the worker container's authentication record compared with the store by version id |
| `WorkerSettings.provider_key` reads the store on every call: after a replacement, the next scenario authenticates with the new version without a restart, and the previous version is refused | Automated (`poe verify`): first in the check's own process, your `WorkerSettings` is instantiated against a stand-in store whose value changes on every read and `provider_key()` is called three times, which must read the secret three times and return three distinct values; then, against the running stack, the check stores a new version itself, runs a scenario, compares the worker's record and the container's identity before and after, and hands the previous version to the emulator's key check |
| No command output, container log, audit record or stored record holds any version's value | Automated, against the running stack (`poe verify`), searching the tools' outputs and the logs for every version the store holds; a finding names the version and the output |
| `security/gate.yaml` fails the gate on any secret finding and on a known high-severity vulnerability, with a failing static-analysis threshold of your choice | Automated, in this repository (`poe verify`) |
| With your thresholds and your `.gitleaks.toml`, the working tree passes the scan and both reports are written | Automated (`poe verify`): the three scanners over a copy of the tracked files, through Docker |
| A copy of the tree with the seeded secret fails the scan on the Gitleaks finding, and a copy with the seeded vulnerable dependency fails it on the Trivy finding | Automated (`poe verify`): each seed applied to a temporary copy, the copy scanned with your configuration |
| Your `.gitleaks.toml` is the supplied configuration plus exactly one `[[allowlists]]` entry whose `targetRules` is the rule of the finding in `answers.suppressed_finding` and whose `paths` is the one anchored, escaped pattern of its single file, with no other key, the required comment over it, and that finding gone from the gated scan | Automated (`poe verify`), against the scan of your tree with no allowlist applied; the file is parsed and compared with the supplied configuration key for key |
| Every finding the scan reports on the starting checkpoint has one value in `answers.triage`, and no other id does | Automated (`poe verify`), against the scan of the starting checkpoint exported from Git |
| The file `answers.fixed_finding` names is the one changed file beyond the four; that finding is gone from it, every other finding of the file is still reported, and none is added | Automated (`poe verify`), against the scans of the starting checkpoint and of your tree, by content-derived id |
| `answers.triage`, `answers.fixed_finding` and `answers.suppressed_finding` are in the published shape, and the sheet is not a copy of the sample | Automated, in this repository (`poe answers`, repeated by `poe verify`) |
| Your triage values and your fixed finding | Protected automated check, after you submit on the platform; no check in this repository reads the correct values |
| The Task 2 access rule, the Task 3 refused answers and audit trail, and the Task 4 redaction still hold | Automated, against the running stack (`poe verify`) |
| The `security-gate` job passes on your pull request, and the four run URLs, the version ids, the two command outputs and the suppression's justification are in its description | Your instructor, at the Task 7 Instructor Review; you use the security-gate evidence again at the Project Defense |

The inherited Project 3 checks (smoke, end-to-end workflow, queue, SLO, gate, and runbook
contracts) also run inside `poe verify`, over the supplied checkpoint, and pass as shipped.

## The supplied material

| Supplied | Where | Note |
|---|---|---|
| The secret adapter | `src/adapters/secrets/` | `LocalStackSecretProvider` behind the `SecretProvider` port; `secret_provider(settings)` builds it from the LocalStack settings the worker already carries; `read(name)` returns the current version on every call, with no cache and no TTL. Not student-editable |
| Its fidelity note | `docs/fidelity/SecretProvider.md` | The secret's name, the call form, the read timing, the tools, and what the local store does not show |
| The provider-key check | `src/adapters/model/provider_keys.py` | The emulator accepts only the current version and records the version id and a fingerprint, never the value, inside the worker container |
| The secret store | `compose.yaml` (`localstack`, `secretsmanager`), `src/api/initialize.py` | The initializer creates the secret on every start with its first version equal to the opening checkpoint's literal, and leaves an existing secret alone |
| The gate's thresholds | `security/gate.yaml` | One threshold per scanner, the allowed values in its comments, every threshold `none` as supplied. Yours to set |
| The gate policy | `docs/security/gate-policy.md` | What the gate scans, what it must fail, the three triage values, the suppression's form, the demonstration branches, the re-pin step |
| The scanner pins | `security/scanners.yaml` | The three images by digest and the vulnerability database by digest. Not student-editable |
| The static-analysis rules | `security/semgrep-rules.yaml`, `.semgrepignore` | The supplied local rules Semgrep runs offline. Not student-editable |
| The secret-scanner configuration | `.gitleaks.toml` | Extends the default rules with the supplied Coldline provider-key rule; where your one allowlist entry goes. Yours to extend by that entry |
| The workflow | `.github/workflows/security.yml` | The `security-gate` job: `poe security-setup`, `poe security-scan`, the `security-reports` artifact. Not student-editable |
| The hosted log renderer | `tests/security/runtime_logs.py` | What the `verify` and `reliability-gate` jobs of `task.yml` print when they fail: the runtime logs with every stored version of the provider key replaced by `[provider-key version <id>]`, or a diagnostic and no logs when the versions cannot be read. Never the raw logs. Not student-editable |
| The seeds | `tests/security/seeds.py` | `poe seed-secret` writes `security/seed/provider-key.txt`; `poe seed-vulnerable` writes `security/seed/requirements.txt`. Both outside the permitted files |
| The carried Task 4.4 completion | `src/worker/use_cases.py`, `tests/student/test_redaction.py` | The two redaction calls and the two redaction tests, as the reference completion left them; `poe student-tests` still runs the tests. Not student-editable |
| The carried Task 4.3 and settled Task 4.2 material | `src/api/routes.py`, `tests/student/test_output_guardrail.py`, `tests/student/test_audit.py`, `config/auth.yaml`, `src/api/security/`, `tests/fixtures/tokens/`, `tests/student/test_exception_access.py` | As in Task 4.4. Not student-editable |
| The static checks | `tests/security/config_binding.py`, `tests/security/fix_binding.py`, `tests/security/static_rules.py` | `poe config-binding` and `poe fix-binding` |
| The scan tooling | `tests/security/scanners.py`, `tests/security/gate.py`, `tests/security/suppression.py`, `tests/security/security_scan.py`, `tests/security/security_setup.py` | `poe security-scan`, `poe security-setup`, and what the assessed rows run |
| The secret tools | `tests/security/secret_tools.py`, `src/worker/provider_auth.py` | `poe secret-status`, `poe secret-replace`, `poe secret-check-old`, `poe provider-auth-check` |
| The assessed-module runner | `tests/security/assessed_run.py` | Runs the assessed module under pytest with a junit report and requires every registered case to have executed and passed; `poe security-contract` goes through it |
| The integrity snapshot | `tests/security/integrity.py` | Hashes your files and the checks' own files when `poe verify` starts and compares them when it ends |

## The four steps

### Step 1 — Read the provider key through `SecretProvider`

Start the stack as `README.md` describes and run `poe security-setup` once. In
`src/worker/config.py`, remove the key literal and make `provider_key` a read through the
supplied adapter with the secret name in `docs/fidelity/SecretProvider.md`, made each time the
worker needs the key. Run `poe start` again (the worker image carries your file), then
`poe scenario`, `poe secret-status` and `poe provider-auth-check`: the version ids agree.

### Step 2 — Replace the key and confirm the current version

Record the current version id. Run `poe secret-replace`, then `poe scenario` and
`poe provider-auth-check`: the version id is the new one, with no restart. Run
`poe secret-check-old`: the previous version is rejected. Keep both version ids and the two
outputs for the pull request; none of them holds a value.

### Step 3 — Set the gate thresholds and triage the inherited findings

Set the three thresholds in `security/gate.yaml` as `docs/security/gate-policy.md` requires. Run
`poe security-scan` and read every finding: its id, scanner, file and rule. Decide each one's
triage value by the policy's definitions and record it in `answers.triage`. Fix the finding you
triage as `valid` inside the function it names, in the file it names, following the rule's own
recommendation, and record its id in `answers.fixed_finding`. Add one allowlist entry to
`.gitleaks.toml` for the false positive, scoped to its rule and its single path, with the
comment the policy describes, and record its id in `answers.suppressed_finding`. Run
`poe security-scan` again: it passes and writes both reports. Run `poe answers`. Commit the
permitted files.

### Step 4 — Prove the gate rejects a seeded secret and a vulnerable dependency

From your Step 3 commit, on one draft branch run `poe seed-secret`, commit, push, and read the
failing `security-gate` run; revert, push, and read the passing one. On a second draft branch do
the same with `poe seed-vulnerable`. Close both pull requests without merging. `poe verify` runs
the same two proofs on temporary copies of your tree.

## Commands

```shell
poe security-setup                 # pull the pinned scanners and the pinned database, once
poe scenario                       # one reading through the stack; the worker authenticates with the provider
poe secret-status                  # the current and previous version ids and fingerprints
poe provider-auth-check            # the version id the worker last authenticated with
poe secret-replace                 # a new current version; prints its id and fingerprint
poe secret-check-old               # the previous version, handed to the emulator's key check: rejected
poe security-scan                  # every finding with its id, the marks, the verdict, the two reports
poe security-scan --inventory      # the same with no allowlist applied, no reports written
poe security-scan --baseline       # the starting checkpoint's findings
poe security-scan --seed secret    # a temporary copy with that seed applied (or `vulnerable`)
poe seed-secret                    # write the fake key for a demonstration branch
poe seed-vulnerable                # write the vulnerable pin for a demonstration branch
poe config-binding                 # your settings module: imports, literals, the read, without running it
poe fix-binding                    # your fix: one function's body in one file, no import added
poe integrity-record               # hash your files and the checks' files; the first step of `poe verify`
poe integrity-check                # compare the tree with that snapshot; the last step of `poe verify`
poe security-contract              # the assessed rows, through the assessed-module runner
poe answers                        # the answer sheet's format only
poe verify                         # the full public path
```

Start the stack per `README.md` first; `poe verify` starts it again itself and ingests the
supplied corpus. `poe config-binding`, `poe fix-binding` and `poe answers` are static;
`poe security-scan`, `poe security-setup` and the seeds need Docker and no stack; every other
command above needs the running stack.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| `src/worker/config.py` contains no key literal and reads the key through `SecretProvider` | `test_config_reads_the_key_through_the_secret_provider_and_holds_no_literal` (static, then every stored version), with `poe config-binding` inside `poe verify` |
| After `poe secret-replace`, the worker authenticates with the new version without a restart | `test_a_replacement_takes_effect_without_a_restart_and_the_previous_version_is_rejected`, with `test_a_scenario_completes_and_the_worker_authenticated_with_the_current_version` first |
| The emulator rejects the previous version of the key | `test_a_replacement_takes_effect_without_a_restart_and_the_previous_version_is_rejected` (its last assertion, the emulator's key check over the previous version) |
| No command output, test, log, or pull request description contains the model provider key's value | `test_no_output_contains_any_versions_value` (the outputs, the logs, the records); the pull request description is your instructor's |
| `security/gate.yaml` fails the gate on any secret finding | `test_gate_thresholds_fail_any_secret_and_a_high_vulnerability` |
| `security/gate.yaml` fails the gate on a known high-severity vulnerability | `test_gate_thresholds_fail_any_secret_and_a_high_vulnerability` |
| Every finding that `poe security-scan` reports on the starting checkpoint has one triage value in `answers.triage` | `test_every_starting_checkpoint_finding_has_one_triage_value` |
| `answers.fixed_finding` and `answers.suppressed_finding` each name one finding id | `test_submission_answers_use_the_allowed_values`, and `poe answers` |
| Your `.gitleaks.toml` entry names the rule and the single path of the finding in `answers.suppressed_finding` | `test_the_gitleaks_entry_names_the_rule_and_single_path_of_the_suppressed_finding` |
| `submission.yaml` passes the public answer-format check | `test_submission_answers_use_the_allowed_values`, and `poe answers` |
| Your `answers.triage` and `answers.fixed_finding` pass the protected answer check | The protected check on the platform; no check in this repository reads the correct values |
| The finding you triaged as `valid` is fixed in the file it names | `test_the_fixed_finding_names_the_one_changed_file_and_a_finding_is_gone_from_it`, with `test_the_fix_changes_one_function_of_one_file_and_adds_no_import` (static) and `poe fix-binding` inside `poe verify` |
| `.gitleaks.toml` has one suppression, scoped to one rule and one path, with a justification comment | `test_the_gitleaks_entry_names_the_rule_and_single_path_of_the_suppressed_finding` |
| With your thresholds, `poe security-scan` passes on the clean tree and writes `reports/security/scan.sarif` and `reports/security/sbom.cdx.json` | `test_the_clean_tree_scan_passes_with_the_thresholds_and_writes_both_reports` |
| `poe verify` shows that, with your thresholds, the scan fails for the seeded secret and for the vulnerable fixture | `test_the_seeded_secret_fails_the_scan_on_a_gitleaks_finding` and `test_the_seeded_vulnerable_dependency_fails_the_scan_on_a_trivy_finding` |
| Your pull request description links a failing and a passing `security-gate` run for each seed | Your instructor, at the Task 7 Instructor Review |
| Neither seed is present in `main` | `poe security-scan` on `main` after your merge (the hosted gate on the next pull request), and your instructor |
| The `security-gate` job passes on this Task's pull request | The hosted `security-gate` job; `poe security-scan` is the same command |
| The Task 2 access rule still protects `GET /api/v1/exceptions/{exception_id}` | `test_the_task_2_access_rule_still_protects_the_summary_route` |
| The malformed and manipulated responses still end in `NEEDS_REVIEW` | `test_bad_responses_still_end_needs_review[malformed]` and `[manipulated]` |
| `poe audit-trail` still shows every event in `docs/security/audit-events.md` for one interaction | `test_the_audit_trail_still_reconstructs_one_interaction[n01-valid]`, `[pii-echo]`, `[malformed]` and `[manipulated]` |
| `poe pii-scan` still finds none of the marked PII values from `N-01` or `pii-echo` | `test_pii_scan_still_finds_no_marked_value_from_n01_or_pii_echo` |
| The pull request modifies only `src/worker/config.py`, `security/gate.yaml`, `.gitleaks.toml`, `submission.yaml`, and the one file named by the finding you triage as `valid` | `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py`, and `poe submission` (the `tests/contract/submission_validation.py` module, which applies the same boundary) inside `poe verify` |

The rows live in `tests/contract/test_security_contract.py` (`poe security-contract`). They are
marked `assessed`: `poe contract` leaves them out, and `poe verify` runs them through
`tests/security/assessed_run.py`, which requires every registered case to have executed and
passed (a skipped or missing case fails the step). The rows that touch the stack are also marked
`runtime`. A fresh checkout fails most of them, which is the exercise; the inherited Task 2, 3
and 4 rows, the first scenario row, the bounded-fix row (nothing changed yet) and the no-output
row pass on it. The last Check-list row above is not an assessed row: `poe submission` applies
the boundary inside `poe verify`, and `test_submission_change_stays_within_the_permitted_diff`
in `tests/contract/test_authoring_contract.py` applies the same boundary under `poe contract`.

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/security/config_binding.py` | `src/worker/config.py` read as bytes, parsed, never imported: the import allowlist (the starter's two imports plus `from adapters.secrets import PROVIDER_KEY_SECRET_NAME, secret_provider` and `from ports import SecretProvider`), the reach rules, no call to or use of `open`, `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `vars`, `locals`, `dir`, `input` or `breakpoint`, nothing at module level but the docstring, imports, class definitions and assignments of literals (or of a name a permitted import binds) with annotations that call nothing, no string literal equal to the first version's value, no literal or default factory in the `model_provider_key` field, no string literal inside `provider_key` other than the secret's name, `provider_key` an `async def` of `WorkerSettings` with the starter's signature (`async def provider_key(self) -> str`, no decorator, no default expression), `WorkerSettings` the only class in the file (anywhere) with the starter's base, no decorator and no class keyword, its body nothing but the docstring, annotated field assignments over a literal, a permitted name or a `Field(...)` or `SettingsConfigDict(...)` call over such values, the `model_config` assignment and the `provider_key` method, no dunder name anywhere, as a name, an attribute, a definition or an import, and every field, cache attribute and module-level name annotated with a builtin type name (`str`, `int`, `float`, `bool`, `None`, `dict`, `list`, `tuple`, a `dict`, `list` or `tuple` over them, or a union of them written with `|`) with no string annotation and no call in any annotation anywhere (pydantic evaluates a field's annotation when the class is built, a string one as code). The rules are syntactic and say nothing about when the read happens; the replacement row judges that, in-process and live |
| `tests/security/fix_binding.py` | The diff from the starting checkpoint (the merge base with `main`): the one path beyond the four fixed files must be a Python file that existed there; its import statements a subset of the baseline's; its module-level statements the same, compared as syntax (a class with its bases, keywords, decorators and type parameters); exactly one function or method body different (none is a finding: a comment, a `# nosemgrep` marker or a reflowed line changes no function), with the signature kept; none of `open`, `exec`, `eval`, `compile`, `__import__`, `getattr`, `setattr`, `delattr`, `globals`, `vars`, `locals`, `input` or `breakpoint` anywhere in that function or outside every function, called, handed on or reached as an attribute, whatever the baseline copy held, and no dunder name in that function; and no reach finding the baseline copy did not have. It knows no finding and no function name |
| `tests/security/secret_tools.py`, `src/worker/provider_auth.py` | The host-side store over the published LocalStack port with the development credentials; the worker container's authentication record through `docker compose exec`. Versions by id and fingerprint; no value printed |
| `tests/security/scanners.py` | A copy of the files Git tracks or would track, mounted read-only; Semgrep with the supplied rules, `--metrics=off` and `--disable-nosem` (an inline `nosemgrep` marker hides nothing), Gitleaks in `dir` mode with your `.gitleaks.toml` (or the supplied inventory configuration) and `--ignore-gitleaks-allow` (an inline `gitleaks:allow` marker hides nothing either), Trivy with the pinned database (cached under `.tools/trivy-cache/<digest prefix>/` with a marker naming the pin) and no update; one finding per rule per file; fixed-width ids from the SHA-256 of `scanner|rule|path`, sorted numerically, a collision an error; the gate's scale; SARIF (with the scanned commit when the hosted job passes it) and CycloneDX written from the same scan |
| `tests/security/gate.py` | `security/gate.yaml` against its allowed values, and against the policy: `secrets: any`, `dependencies: high`, `static_analysis` one of `high`, `critical` |
| `tests/security/suppression.py` | `.gitleaks.toml` parsed as TOML and, with its `allowlists` set aside, compared key for key with the supplied configuration (the title, `useDefault = true`, the supplied rule with its regex and keywords); exactly one `[[allowlists]]` entry holding `targetRules` (the finding's rule alone) and `paths` (the one pattern `^` + the escaped path + `$`) and no other key, with comment lines directly over it naming the finding id, a date, and a reason |
| `tests/security/live_record.py`, `tests/security/trail.py`, `tests/security/pii_scan.py`, `tests/security/pii.py` | The inherited rows' tooling, as in Task 4.4: records through the database, the trail through the API container, the four locations as `poe pii-scan` reads them |
| `tests/security/assessed_run.py` | The assessed module run under pytest with a junit report, then, outside that process, the report compared with the registered inventory: every registered case must appear once and have passed |
| `tests/security/integrity.py` | SHA-256 digests of the four fixed permitted files, every file under `src/` (the fifth permitted file among them), `security/`, `tests/contract/`, `tests/security/`, `tests/student/`, `tests/fixtures/`, `schemas/`, `docs/security/`, plus `.gitleaks.toml`, `.semgrepignore`, the security workflow, the answer schema, `config/auth.yaml`, `infra/corpus/documents.jsonl`, `pyproject.toml` and `uv.lock`, recorded to a file outside the repository when `poe verify` starts and compared when it ends |
| `tests/contract/submission_validation.py` (`poe answers`, `poe submission`) and `test_submission_change_stays_within_the_permitted_diff` | `submission.yaml` is one plain YAML mapping whose `answers` holds a non-empty triage map keyed by finding ids with the three allowed values, and two finding ids that are keys of the map and differ, and is not a copy of `submission-sample.yaml`; the diff from the merge base touches only the four fixed files and the file the named fixed finding has in the scan of the starting checkpoint |
| `tests/security/secret_tools.py` (`value_findings`) | The one comparison the rows make between a stored value and a text (the settings file, the tools' outputs, the logs, the records): it returns findings naming the version id, the fingerprint and the output, never the value, and the rows assert on that list, so a failing row renders ids only |

The scans leave your files untouched: each scan copies the tracked files to a temporary
directory, applies a seed to the copy when one is asked for, mounts the copy read-only, and
deletes it; the two reports go under the Git-ignored `reports/security/`.

## Student-editable paths

- `src/worker/config.py` (how the worker reads the model provider key; every other setting
  stays where it is)
- `security/gate.yaml`
- `.gitleaks.toml` (one allowlist entry; the default rules and the supplied rule stay)
- `submission.yaml`
- The one file named by the finding you triage as `valid`, inside the function the finding
  names

That is the whole list. The adapter (`src/adapters/secrets/`), the provider-key check, the
scanner pins, the rules, the workflows, the seeds, the carried Task 4.4, 4.3 and 4.2 files, the
supplied tests, `compose.yaml` and `pyproject.toml` stay as supplied. Before you push, run
`git status` and `git diff --stat`: if anything else changed, the public check reports the
boundary violation rather than your work.
