# Evidence report contract

Stdlib helpers validate supplied structure and consistency, not factual truth, catalog membership or safety. The auditor verifies every reference. JSON schema remains additive `1.0`; gate/profile/scorecard policies are independently versioned. No retrieval time or revision is invented.

## Input

| Field | Contract |
| --- | --- |
| `scope` | Nonempty target/revision/dirty-scope description. |
| `revision`, `audited_at` | Optional nonempty strings; time requires ISO format and timezone. Missing values stay unknown. |
| `sources` | Array: nonempty `edition` (four-digit year), HTTPS `url` without credentials, timezone `retrieved_at`, lowercase 64-hex `sha256`. OWASP provenance only. |
| `coverage` | Array: edition-qualified `id`, `status` reviewed/not_applicable/not_tested, nonempty `reason`; duplicate IDs reject. |
| `limitations` | Array of nonempty strings. |
| `findings` | Array of the finding objects below. |

Empty arrays allow partial evidence, not complete-coverage claims. Sources/coverage/supplemental arrays preserve supplied order; freeze them in stable catalog order. Finding order is normalized by severity/path/line/rule.

### Findings and severity

Required: nonempty `rule`, repository-relative POSIX `path`, positive integer `line`, `title`, `evidence`, `remediation`, `verification`; `severity`; `status` candidate/supported/reproduced; nonempty `categories` with edition-qualified OWASP IDs. Add preconditions, impact, controls and optional supplemental `jev`. Sanitize secrets before input.

Generated IDs hash rule/path/line. Duplicate identities reject; merge evidence explicitly. IDs may change when code moves. Candidates count but remain unconfirmed.

| Severity | Impact and prerequisites |
| --- | --- |
| CRITICAL | Broad system/tenant compromise with minimal prerequisites. |
| HIGH | Substantial confidentiality/integrity/availability impact and plausible attack path. |
| MEDIUM | Meaningful bounded impact or restrictive prerequisites. |
| LOW | Limited impact or narrow defense weakness. |
| INFORMATIONAL | Relevant observation without demonstrated security impact. |

Explain assigned severity. Uncertainty changes evidence status, not potential severity. CVSS needs sourced version/vector and verified calculation.

### Remediation state

Optional `remediation_state`: `open`, `fix_reported`, `fix_verified`. Missing means open **for queue accounting only**, not a verified real-world state. Open cannot carry `remediation_evidence`.

- `fix_reported`: exact `remediation_evidence` object with nonempty `fix_revision` and `report_evidence`.
- `fix_verified`: those fields plus `verified_revision`, `verification_evidence`, `verification_result`. Revisions must match and result must be `passed`. Cite an actual recheck of the fix at that revision; never fabricate verification from a suggested fix or a Jev opinion.

The validator checks fields/references, not test truth. Fixed findings remain in severity counts; remediation counts are separate.

## Audit profiles

`audit_profile` has only `mode` (`lean`, `full`, `custom`), `version` (exactly `bauer-audit-profile-v1`) and `selected_sources`. Preflight defaults to Lean; new reports inherit the pinned record, never infer a replacement profile. Legacy normalization preserves saved Full scope. Null/unknown fields, duplicate/unknown IDs, wrong version or contradictory fixed-mode selections reject. Lean/Full derive selections; supplied lists must match exactly. Custom needs at least one explicit registry selection; prerequisites are never silently added.

| Profile | Source IDs |
| --- | --- |
| Lean | `owasp-web`, `owasp-llm`, `cwe`, `osv`, `vendor` |
| Full | Every ID in `security-sources.json` |
| Custom | Explicit registry IDs, with this prerequisite graph |

**Graph v1:** `ghsa`, `vendor`, `cve` require `osv`; `nvd`, `kev`, `epss` require `cve` (therefore OSV). All modes always require the dependency ledger, remote-scope assessment and every relevant remote target. This conservative source-selection graph is Bauer policy, not a claim that every ecosystem is OSV-supported. A source-specific non-OSV inventory contract remains open.

At runtime dependent rows stay unsatisfied unless prerequisites and inventory coverage are satisfied; CVE-family absence needs resolved inventory and applicable-CVE assessment. Known applicability with unresolved work is not certification. A selected source can legitimately be nonapplicable only with scope evidence. Selecting a feed does not approve its queries.

```json
{"mode":"custom","version":"bauer-audit-profile-v1","selected_sources":["osv","cve","kev","epss"]}
```

## Run record

New audits use two turns: `control.py preflight` generates a pending `run_record`; the host presents `preflight_message`, asks confirmation and **stops before target inspection, selection, guidance or reports**. Lean stays default, with one record-confirmation question. Offline restrictions never imply disabling review. `audit`/`mode` remain previews, not audits.

Schema `bauer-run-record-v2` has exactly these fields. The unpublished v1 schema is unsupported, never silently confirmed; published v0.2.1 reports have no such record and retain historical migration.

| Field | Contract |
| --- | --- |
| `schema_version`, `run_id`, `created_at` | Exact schema, canonical UUID4 and timezone preflight time; run ID stays stable through confirmation. |
| `record_id` | SHA-256 of canonical JSON excluding only this field (sorted keys, compact separators, UTF-8). A public content digest, **not a signature**. |
| `origin`, `authority` | Fixed supplied-provenance/consistency statements, never authenticated authority. |
| `audit_profile`, `excluded_sources`, `always_required` | Normalized profile, sorted registry complement and required dependency/remote obligations. |
| `profile_decision` | `{kind: default}` only for Lean; otherwise `kind: user_requested|agent_proposal`, literal `user_instruction`, `decision_ref`, `reason`. Unattributed nondefault CLI arguments are labeled agent proposals. |
| `host_environment` | Boolean `key_present`, matching key_present/missing_key. Initial presence always checked, even offline/disabled; no key values or inferred filtering. |
| `review_decision` | `{state: not_requested}` default; `{state: pending}` or explicit-disable object below. Default scheduling is not a user decline. |
| `chat_delivery` | `pending_host_delivery` even after confirmation: no helper chat-verification claim. |
| `scope_change` | Null initially; otherwise `previous_run_id`, `previous_record_id`, `previous_audit_profile`, literal `user_instruction`, `decision_ref`, `reason`. |
| `status`, `confirmation` | `pending_confirmation` + null, or `confirmed|declined` + the object below. |

After the real later response, `control.py confirm --run-record FILE --decision confirm|decline --user-response TEXT --response-ref REF` creates a new record, never mutates pending. Its `confirmation` contains exactly `decision`, literal `user_response`, actual supplied `response_ref`, timezone `recorded_at`, `pending_record_id` and the complete `pending_record`. Run ID/profile/presence/decisions stay equal to that snapshot; only status, confirmation and derived record ID change. Empty response/reference, wrong linkage, missing metadata, reused confirmation or inconsistent profile rejects. `--output PATH` on either control exclusively creates an approved artifact; no overwrite, implicit persistence, credential access during confirm, execution or network.

These are **unsigned agent assertions**, not proof of a genuine user response. The helper checks consistency, cannot authenticate chat, and cannot prevent an agent from fabricating a consistently regenerated record. `chat_delivery_verified`/`user_response_authenticated` remain false in preflight output. Host interaction must be independently observed; test fixtures use explicitly synthetic responses, never runtime consent. No external calls are authorized.

Only an actual explicit disable supplies `--review-decision FILE`: exactly `state: explicit_disable_captured`, literal `user_instruction`, `decision_ref`, `reason`. `--profile-decision FILE` uses the profile-decision object above. Preserve literals/references; never invent their origin or translate offline/default scheduling into disable.

New report creation requires a **confirmed** file via `--run-record FILE` or embedded `run_record`; both must match exactly, including types. Pending/declined/missing confirmation rejects even empty completion input, not a fabricated partial/complete report. Evidence profile must match. JSON retains the record; Markdown, scorecard and selection queue bind the same stable run ID and confirmed record ID. A deliberate scope/decision change requires new preflight with `--previous-run-record FILE --scope-change-decision FILE`, then new confirmation. The latter file has literal `user_instruction`, `decision_ref`, `reason`; prior IDs/profile stay linked, never rewritten. Scheduling/threshold overrides recompute derived queue/card while preserving confirmed decisions; captured disable cannot be silently enabled. Record time is never target audit time or freshness proof.

`report.py --saved-report` is historical normalization only: an existing saved gate is required and validated before migration/derivation; naked evidence cannot use this flag. Historical v1/v2 and scorecard metadata reject forgery. Output marks `report_origin: historical_saved_report`, visibly historical in Markdown, never new-audit completion. New record-backed output marks `preflight_run_record`. Legacy migration metadata cannot be grafted onto a new run. `normalize()` remains a backward-compatible supplied ledger function for saved controls/selection, not a new-audit certificate.

## Completion/applicability input and derived gate

Selection uses the same CLI-boundary validators: `normalize_new_evidence()` requires a confirmed record and matching profile; `normalize_saved()` requires and fully validates the original saved gate and derived metadata. `selection.py REPORT.json [--enabled] [--min-severity HIGH]` automatically chooses saved history only without a record. Policy overrides follow original validation and regenerate queue/card together, preserving Full scope, ASVS gaps and migration provenance. A `historical_saved_report` label alone never admits raw evidence. Saved selection requires no new confirmation; `normalize()` remains the pure aggregation API used for queue generation, not a circular CLI enforcement hook.

`completion_checks` is an array of exact objects with five nonempty strings:

| Field | Values |
| --- | --- |
| `id` | Registry ID, `dependency_coverage`, `remote_configuration`, or `remote:<target>` declared in scope. |
| `applicability` | applicable/not_applicable/unknown |
| `status` | checked/reviewed/not_applicable/blocked/not_tested/unattempted/error/unavailable |
| `reason` | Specific classification/outcome rationale. |
| `evidence` | Verified scope/source/control/result reference. |

Unknown/duplicate IDs, unsupported states and mismatched not_applicable reject. Unknown never satisfies a row. Unavailable means attempted retrieval/access failure, distinct from unattempted. Missing selected records produce unknown/unattempted placeholders, never invented checks.

`completion_scope` requires exactly:

| Fields | Meaning |
| --- | --- |
| `inventory_ids`, `approved_ids`, `queried_ids` | Full scoped exact identities, exact approved disclosure subset, actual completed queries. Queried ⊆ approved ⊆ inventory. Link ecosystem/name/version/context through evidence; constraints are not resolved versions. |
| `excluded`, `blocked` | Arrays of exact `{id, reason, evidence}`; identities must be inventoried, unique, disjoint and not queried. Exclusions need genuine scope evidence, not merely missing approval/access. Blocked/unapproved work remains unresolved. |
| `inventory_evidence`, `query_evidence` | Nonempty reviewed references, including evidence-backed empty inventories/queries. |
| `remote_targets`, `remote_scope_evidence` | Exact relevant target IDs and nonempty scope reference. Unknown scope is missing, never an invented empty list. Each target needs an applicable satisfied remote row; local files cannot prove deployed settings. |
| `published_cve_ids`, `cve_assessment_evidence` | Applicable published `CVE-YYYY-NNNN…` IDs and adjudication reference, excluding reserved/rejected/unverified candidates. |

Identity/disposition arrays are bounded at 10000. Duplicates/outside-inventory/unapproved queries and overlapping dispositions reject. Counts are derived; completed batches cannot erase remaining identities. Disclosure approval does not authorize the full discovered inventory.

Gate `bauer-completion-v2` emits all registry/core/remote rows with `selected` and `satisfied`. Only selected satisfied rows count toward complete; otherwise partial. Unselected rows are `out_of_scope`, not NA, with supplied records retained under `supplied_record` and explicitly ignored for completion. Supplemental arrays are visible but never substitute for selected obligations. Missing scope/remote evidence leaves partial. A generic reviewed remote row cannot bypass relevant targets.

Nonapplicable dependency coverage contradicts approved, queried or nonexcluded inventory; completing queries does not remove applicability. OSV NA over nonempty queried IDs remains unsatisfied because the generic ledger lacks source-specific applicability. CVE/NVD/KEV/EPSS NA cannot satisfy unresolved inventories or applicable published CVEs. Preserve original classifications with `gate_reason`; do not rewrite performed work. GHSA/vendor/Scorecard applicability still needs verified scope; ASVS needs control scope; SLSA can apply to stdlib-only plugin source/build/release work.

Saved unprofiled `bauer-completion-v1` reports first validate against the original all-registry v1 expectation. Only then migrate to explicit Full/v2, recording `completion_migration` with from/to policies and the validated `legacy_gate`. The v2 prerequisite rules may add blockers; no historical row or ASVS gap is discarded. Migration metadata and both gate versions reject forgery; normalized migrated reports round-trip. Do not strip the old gate to force Lean.

At closing show status and obligations; partial stays partial even with zero findings. Ask permission to continue unresolved work and wait. Jev has no authority over this gate.

## Security Scorecard

Derived `security_scorecard`, version `bauer-security-scorecard-v1`, precedes severity counts in Markdown/final chat. It includes scope, supplied revision/time, profile, completion, selected/satisfied counts, blockers/exclusions, dependency coverage, remote gaps, severity/evidence/remediation counts, Jev queue/outcomes and next action. Missing Jev selection is unknown (`null`), not a completed review; outcomes retain supplied supplemental notes without certifying them.

Next action: first unresolved finding in severity/path/line/rule order (including candidates and fix_reported); otherwise first selected coverage gap in registry/core/remote order; otherwise no unresolved supplied work, explicitly not certification. Fix_verified does not hide historical severity counts. No numeric security score, green badge, conformance claim or out-of-scope NA.

`control.py status REPORT.json [--current-revision REVISION]` reads frozen evidence only. Missing revision/time/current revision is reported as unknown/gaps; mismatch is `stale_revision`, match is only `matches_supplied_revision`. No mtime/current time/git inference or audited script runs. `scorecard REPORT.json --format json|markdown` renders the same card without rerunning checks. Status bundles `report_handle`, `security_scorecard` and matching `severity_counts`; Markdown status/scorecard show the card before all five count rows. Saved controls require neither key inspection nor a new-audit preflight.

## Jev, supplemental fields and output

Jev policy/queue and mandatory offer/packet rules are defined in [jev.md](jev.md). The report accepts `jev_policy` with only `policy_version`, `enabled`, `min_severity`; absent policy is backward-compatible, not proof the mandatory workflow ran. Generated selection, completion gate, scorecard and resource note reject supplied forged/stale metadata by exact recomputation (including boolean/integer distinctions).

Optional `source_checks`, `framework_checks`, `supply_chain_checks` arrays require unique nonempty `id` and `reason`. Source status: checked/not_applicable/unavailable. Framework/supply-chain status: reviewed/not_applicable/not_tested.

Optional provenance: nonempty `version`/`evidence` text, HTTPS credential-free `url` without whitespace/control characters, timezone `retrieved_at`, lowercase 64-hex `sha256`. Non-year versions are not OWASP edition years. Unknown supplemental fields and finding Jev objects are retained, not validated outcomes/conformance.

```sh
python3 skills/bauer/scripts/report.py evidence.json --run-record /approved/scratch/confirmed.json --format json
python3 skills/bauer/scripts/report.py evidence.json --run-record /approved/scratch/confirmed.json --format markdown
```

JSON is default. Both formats normalize the same evidence. All five `Severity | Count` rows include zeros; reproduce them in final chat even with limited highlights, without repeating level totals per finding. Resource note is stable policy text about token-intensive work, scope/host-model variability and separate Jev cost, not measured usage or a cap; actual-chat warnings remain required by SKILL.

Markdown renders evidence inertly: entity-encoded syntax, visible control/format characters, code spans around URL-like text and safe path delimiters. No active links/images/HTML; this is not secret redaction. `render_markdown` expects normalized input. CLI unreadable/invalid UTF-8/JSON/schema, duplicate keys, nonfinite numbers or excessive nesting produce nonzero exit, empty stdout and static `bauer report: invalid input` (control uses `bauer control: invalid input`). Invalid arguments use the corresponding `invalid arguments` message; no paths/input/tracebacks leak.
