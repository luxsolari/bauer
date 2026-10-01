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

Markdown displays all five severity counts; finding IDs, severity, evidence status, path/line, categories, evidence, remediation and verification; a severity-ordered remediation queue; source provenance; coverage; explicit `not_tested`/`unavailable` gaps; limitations; and optional source/framework/supply-chain checks. Candidate findings are labeled unconfirmed. Empty lists or absence of explicit gaps never claim a complete or safe audit. Optional finding `jev` is shown separately as supplemental JSON and cannot change severity, evidence status or counts.

All untrusted text, including metadata keys, is rendered as inert text: HTML/Markdown punctuation is entity-encoded, URL syntax cannot become links or external images, and control/format characters are shown as literal Unicode escape sequences. URL-like text additionally uses inert code spans so renderers that decode entities before automatic link detection cannot create active links. Paths use padded code spans with a delimiter longer than every supplied backtick run, escaped HTML and visible controls. Reports contain no raw HTML, active links or embedded external content. The conservative escaping favors safety over raw Markdown readability; normalized JSON preserves original evidence text. This is not secret redaction: sanitize evidence before supplying it.

Unreadable files, invalid UTF-8/JSON/schema data, duplicate JSON keys, nonfinite JSON numbers and excessive nesting exit nonzero with empty stdout and the static stderr message `bauer report: invalid input`. Invalid CLI arguments use `bauer report: invalid arguments`. Errors never print input, paths, exception details or tracebacks. Successful output is assembled before writing stdout.
