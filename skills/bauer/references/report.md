# Evidence report contract

Input object: `scope` (revision and dirty scope), `sources` (edition/URL/time/digest records), `coverage` (each frozen category, status and reason), `limitations` (strings), `findings` (objects).

Each source requires `edition` (four-digit year), `url` (HTTPS without user credentials), `retrieved_at` (ISO timestamp with timezone), and `sha256` (64 lowercase hexadecimal characters). Each coverage entry requires `id` (edition-qualified category), `status` (`reviewed`, `not_applicable`, or `not_tested`), and a nonempty `reason`. Duplicate coverage IDs are rejected. Limitations must be nonempty strings. Empty arrays are permitted for explicitly partial reports, never evidence of complete coverage.

Each finding requires `rule` (stable root-cause identifier), `path` (repository-relative POSIX path), `line` (positive integer), `severity`, `title`, `evidence`, `status`, `categories` (edition-qualified IDs), `remediation`, `verification`. Add preconditions, impact, controls and optional `jev` as needed. Strip secrets from all evidence and terminal output. The helper validates the required structure and ID syntax, not source truth or membership in the frozen OWASP catalog; the agent must check those.

Allowed statuses: `candidate`, `supported`, `reproduced`. Candidate findings count but must remain labeled unconfirmed. Merge duplicate root-cause/location evidence explicitly; the helper rejects duplicates rather than choosing one silently. IDs are derived from rule/path/line and can change when code moves; they are stable for a frozen input, not a cross-revision identity guarantee.

Severity rubric (Bauer policy, not an OWASP-assigned score):
- CRITICAL: broad system/tenant compromise or similarly severe impact with minimal attacker prerequisites.
- HIGH: substantial confidentiality, integrity or availability compromise with a plausible attack path.
- MEDIUM: meaningful but bounded impact or materially restrictive attack prerequisites.
- LOW: limited impact or defense weakness with narrow exposure.
- INFORMATIONAL: relevant observation without a demonstrated security impact.

Explain impact and prerequisites for every assigned level. If using CVSS, record the version/vector and calculate with a verified implementation; do not invent a number. Never reduce severity because evidence is uncertain: retain the potential severity and candidate status.

Output JSON includes generated IDs, severity ordering and all five counts. Preserve source provenance, coverage, limitations, and supplemental Jev responses. No timestamps are added: identical frozen input produces identical output regardless of finding input order. Sources, coverage and supplemental arrays retain supplied order; prepare them in stable catalog order. Existing inputs without supplemental arrays remain valid, and the JSON schema version stays `1.0` (additive extension).

## Jev selection policy (optional report field, mandatory workflow step)

Every audit workflow executes `scripts/selection.py EVIDENCE.json` before optional Jev use; without `--enabled`, it returns a disabled plan and sends nothing. Copy its returned `policy` into evidence `jev_policy`. The report's additive input is an object with only `policy_version` (exactly `bauer-jev-selection-v1`), `enabled` (JSON boolean), and `min_severity` (one of the five uppercase severity levels). Missing fields default to that version, false and MEDIUM; `{}` is valid. Unknown fields, wrong types, unknown versions and invalid levels fail closed. Inputs without this field remain valid for report compatibility but do not show a selection plan.

Normalization generates `jev_selection: {"policy": ..., "queue": [...]}`. The queue includes every normalized finding, using generated `id`, `severity`, evidence `status`, boolean threshold `eligible`, `state` and `reason`. It uses the report's stable finding order. Default MEDIUM boundary includes CRITICAL/HIGH/MEDIUM across candidate/supported/reproduced; no cap. Disabled entries have `disabled`/`policy_disabled`; enabled eligible entries have `pending_packet_approval`/`severity_at_or_above_threshold`; enabled ineligible entries have `not_selected`/`below_min_severity`. Eligibility is independent of enablement and is never disclosure consent.

Derived `jev_selection` supplied on input must exactly match recomputation, including metadata types; it is rejected without `jev_policy` or if forged/stale. No circular import: policy/queue generation lives in `report.normalize`, and the selection CLI imports it. Neither performs a request or reads keys/code. JSON and Markdown show the same plan. Preserve actual completed/unavailable adapter results and auditor-authored declined notes separately in existing finding `jev`, as described in `jev.md`; these supplemental values are retained, not schema-validated review outcomes. Queue states are a plan, not completion tracking. Never infer fresh agent discovery or severity judgments are deterministic from a stable frozen-input queue.

## Completion/applicability input and derived gate

The report always emits `completion_gate`: `policy_version`, `status` (`complete`/`partial`), every obligation with applicability/outcome/reason/evidence, identity coverage and assessed scope. Missing rows are visibly derived placeholders (`record_supplied: false`, `unattempted`, `unknown`), never invented performed checks. A supplied derived gate must exactly match recomputation or input fails closed. JSON and Markdown show the same ledger. No new feed clients, host API calls, environment reads or automatic queries occur; this validates evidence traces, not their truth. Missing inputs remain compatible but produce partial.

`completion_checks` is an array of objects with exactly these nonempty strings:
- `id`: every ID in `security-sources.json`, plus `dependency_coverage`, `remote_configuration`, and `remote:<target>` for each declared relevant hosted target.
- `applicability`: `applicable`, `not_applicable`, or `unknown`.
- `status`: `checked`, `reviewed`, `not_applicable`, `blocked`, `not_tested`, `unattempted`, `error`, or `unavailable` (actual retrieval/access failure, not a synonym for never attempted).
- `reason`: specific classification/outcome rationale, not a generic assertion of safety.
- `evidence`: supporting scope/control/source snapshot or command/result reference. The auditor must verify that reference; the helper cannot resolve or certify it.

Unknown/duplicate IDs, unsupported states, empty reasons/evidence and `not_applicable` without matching explicit applicability fail closed. Unknown applicability never satisfies a row, even with `checked`. All records must be supplied and satisfied for complete. A legitimate evidenced nonapplicable record satisfies its obligation without pretending a query ran. Legacy supplemental arrays below do not replace this ledger.

`completion_scope` has exactly these fields:
- `inventory_ids`, `approved_ids`, `queried_ids`: arrays of stable exact identity strings linked by `inventory_evidence` to actual resolved ecosystem/name/version/context. Include full discovered scoped inventory, not just the approved subset. `queried_ids` means actual completed queries linked to `query_evidence`, not submitted/failed work. Deduplicate explicitly before input; duplicates are rejected, not silently hidden. Queried IDs must be a subset of approved IDs, themselves a subset of inventory. Approval must refer to that exact curated disclosure inventory; permission to audit is not permission to disclose all packages.
- `excluded`, `blocked`: arrays of `{id, reason, evidence}` with per-identity rationale/reference. IDs must belong to inventory; no duplicate or overlapping disposition or queried/excluded/blocked identity. Excluded means genuinely outside defined scope, not simply unapproved or inaccessible. Blocked/unapproved/unattempted identities remain unresolved. Unsupported identities need recorded dispositions, not disappearing headcounts.
- `inventory_evidence`, `query_evidence`: nonempty reviewed references, including an explicit evidence-backed empty inventory/query list when appropriate. Identity/disposition lists are bounded at 10000 per array.
- `remote_targets`: exact stable target IDs (for example `supabase:production`, `vercel:production`), derived from explicit audited deployment scope, not guessed from a source file. `remote_scope_evidence`: nonempty reference identifying relevant targets or an evidenced no-hosted-target scope. Unknown scope is missing, never an empty list invented to pass. Missing scope makes the gate partial. Each named relevant target needs an applicable satisfied `remote:<target>` row; unavailable read-only access requires permission and remains blocked. Local config cannot prove actual deployed settings.
- `published_cve_ids`: exact applicable published CVE IDs established by adjudication, not reserved/rejected/unverified candidates. `cve_assessment_evidence`: supporting adjudication reference. CVE/NVD/KEV/EPSS nonapplicability is unsatisfied when dependency coverage is unresolved or applicable published CVEs exist. No CVE on custom findings does not establish absence across an unqueried inventory.

Dependency coverage counts are derived from identity sets and retain queried, excluded, blocked and unresolved IDs/reasons. For instance 90 queried of 715 scoped identities leaves 625 unresolved absent evidence-backed individual exclusions; scoped disclosure approval does not erase the remainder. An entirely covered identity ledger still needs a supplied satisfied dependency obligation. `dependency_coverage: not_applicable` contradicts any approved, queried, or nonexcluded inventory identity: completing queries does not make the work nonapplicable. The gate keeps the supplied classification, marks the obligation unsatisfied with a contradiction reason, and leaves the overall report partial. Evidenced empty scope, or entirely excluded inventory with no approvals/queries, may legitimately be nonapplicable.

The generic identity ledger does not identify each query's advisory source or supported ecosystem. Therefore an OSV `not_applicable` record over nonempty `queried_ids` also remains unsatisfied: source-specific nonapplicability cannot be established with this schema. This does not assert that OSV performed the queries or that every inventory identity is OSV-supported; recording valid non-OSV-only queried work alongside OSV nonapplicability requires a future source-specific scope contract. Do not infer GHSA/vendor/Scorecard applicability solely from generic query counts. Their conditional scope still requires auditor-verified reason/evidence. Remote scope and every relevant target likewise cannot be bypassed with a generic reviewed row.

At preflight plan all registered obligations and evidence needed; at end run the gate and show overall status plus the table. Ask permission to continue unresolved checks, never broaden disclosure/access automatically. GHSA conditional means an explicit applicability decision, not silent omission. ASVS nonapplicability needs evidenced control scope; SLSA normally includes source/build/distribution of plugin code, not only third-party runtime dependencies. Jev presence/offer/review outcomes remain separate optional supplemental notes; disabled, declined or missing key does not complete or invalidate base coverage. No optional Jev state authorizes disclosure or certifies safety.

## Supplemental checks

Optional `source_checks`, `framework_checks`, and `supply_chain_checks` must be arrays of objects when present; empty arrays are allowed but do not establish coverage. Every entry requires nonempty string `id` and `reason`, plus an explicit `status`:

- `source_checks`: `checked`, `not_applicable`, `unavailable`.
- `framework_checks` and `supply_chain_checks`: `reviewed`, `not_applicable`, `not_tested`.

IDs must be unique within each array, not globally across arrays. Use stable source-registry IDs or framework-qualified control IDs. The helper does not verify registry membership, completeness, factual accuracy, or conformance.

Optional `version`, `url`, `retrieved_at`, `sha256`, and `evidence` must be nonempty strings if supplied. `version` accepts semantic versions and framework names (for example `5.0.0`, `ASVS 5.0.0`, or `SLSA 1.2`), without coercing them into an edition year. `url` requires HTTPS with a hostname, no credentials and no whitespace/control characters. `retrieved_at` requires an ISO timestamp with timezone; `sha256` requires 64 lowercase hexadecimal characters. `evidence` is a text summary or local snapshot reference, not an arbitrary JSON object. Unknown supplemental fields are retained, not schema-validated; the agent remains responsible for checking their values against retrieved sources. These arrays extend rather than replace OWASP `sources`/`coverage`.

## CLI and Markdown

```sh
python3 skills/bauer/scripts/report.py evidence.json
python3 skills/bauer/scripts/report.py evidence.json --format json
python3 skills/bauer/scripts/report.py evidence.json --format markdown
```

JSON is the default and remains byte-identical to explicit `--format json`. Both formats use the same normalized report. `render_markdown(normalized_report)` renders an already normalized object; it does not collect evidence or execute checks.

Markdown displays a separate compact `Severity | Count` summary table, all five levels in severity order including zeros, directly from normalized `counts`. Reproduce that helper table in the final chat even when finding highlights are limited; prose counts alone or a finding-detail table without per-level counts is insufficient. Do not repeat the level count on each finding row. Markdown also displays finding IDs, severity, evidence status, path/line, categories, evidence, remediation and verification; a severity-ordered remediation queue; source provenance; coverage; explicit `not_tested`/`unavailable` gaps; limitations; and optional source/framework/supply-chain checks. Candidate findings are labeled unconfirmed. Empty lists or absence of explicit gaps never claim a complete or safe audit. Optional finding `jev` is shown separately as supplemental JSON and cannot change severity, evidence status or counts.

All untrusted text, including metadata keys, is rendered as inert text: HTML/Markdown punctuation is entity-encoded, URL syntax cannot become links or external images, and control/format characters are shown as literal Unicode escape sequences. URL-like text additionally uses inert code spans so renderers that decode entities before automatic link detection cannot create active links. Paths use padded code spans with a delimiter longer than every supplied backtick run, escaped HTML and visible controls. Reports contain no raw HTML, active links or embedded external content. The conservative escaping favors safety over raw Markdown readability; normalized JSON preserves original evidence text. This is not secret redaction: sanitize evidence before supplying it.

Unreadable files, invalid UTF-8/JSON/schema data, duplicate JSON keys, nonfinite JSON numbers and excessive nesting exit nonzero with empty stdout and the static stderr message `bauer report: invalid input`. Invalid CLI arguments use `bauer report: invalid arguments`. Errors never print input, paths, exception details or tracebacks. Successful output is assembled before writing stdout.
