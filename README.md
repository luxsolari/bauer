# Bauer

Bauer guides your coding agent through an evidence-backed security audit: trace attack paths, check dependencies and remote controls, challenge findings, then produce JSON and Markdown. Named after Formula 1 technical delegate Jo Bauer. Optional TypeSafe Jev reviews approved evidence packets.

## Token usage

Security audits can be token-intensive. Usage depends on scope and your host model; Bauer cannot predict tokens or cost. Jev may incur separate provider charges. The agent warns before auditing and at closing. Ask for bounded scope if budget matters; unfinished checks remain partial. No automatic cap. New audits require one confirmation of the generated mode/decision record.

## Status

Version 0.3.0 adds profiles, confirmed run records, offline controls and the Security Scorecard. See [releases](https://github.com/luxsolari/bauer/releases) and the bounded host limits below.

## Start an audit

Load [the Bauer skill](skills/bauer/SKILL.md) and ask: “Audit this repository with Bauer using Lean. Show gaps and ask before disclosure or active tests.”

| Profile | Selected work |
| --- | --- |
| **Lean**, announced default | Applicable OWASP Web/LLM, CWE, OSV over the full approved scoped inventory, vendor fix verification and relevant remote controls. |
| **Full** | Lean plus GHSA, CVE, NVD, KEV, EPSS, ASVS, SLSA and OpenSSF Scorecard; all registered sources. More token-intensive: bound target scope rather than sample inventory. |
| **Custom** | Explicit selections with enforced prerequisites. Dependency ledger and relevant remote controls cannot be dropped. |

Profiles select obligations, not permission. Unselected sources remain `out_of_scope`, never `not_applicable`. Unknown applicability remains a gap. Only OWASP retrieval and OSV have dedicated clients; other checks are agent-mediated. See the [source registry](skills/bauer/references/security-sources.json), [advisory procedure](skills/bauer/references/advisories.md) and [supply-chain procedure](skills/bauer/references/supply-chain.md).

### Check mode or saved results

Ask your agent: "Show mode for Lean", "Show status of the saved report at /path/report.json", or "Show its Security Scorecard". Give the report path so the agent uses the same saved results throughout.

These are read-only requests. They do not rerun the audit, check keys or query external sources. Mode shows a per-run profile, not a persistent setting; an audit-plan preview runs no checks. For a new audit, the agent shows the mode and decisions, then waits for your confirmation before inspecting the target. Declining stops it; corrections require a new confirmation. See [preflight, confirmation and CLI details](skills/bauer/references/report.md#run-record).

For direct use from this repository, Python 3.9+ is enough:

| Request | Command |
| --- | --- |
| Show mode | `python3 skills/bauer/scripts/control.py mode --mode lean` |
| Inspect saved status | `python3 skills/bauer/scripts/control.py status /path/report.json` |
| Show saved scorecard | `python3 skills/bauer/scripts/control.py scorecard /path/report.json --format markdown` |

Status and scorecard support JSON or Markdown. Missing revision or audit time stays unknown. Status can compare a supplied revision with `--current-revision REVISION`; a mismatch warns `stale_revision`, but a match does not prove freshness. Validated v0.2.1 reports retain Full scope and their original gaps when read, without new confirmation.

### Completion and Security Scorecard

Complete means the selected audit obligations are satisfied by supplied evidence, not that the project is secure. Partial means required work remains unresolved, including budget or access limits. Unknown applicability remains a gap; unselected checks are `out_of_scope`, not nonapplicable. The agent asks permission before continuing unresolved disclosure, access or testing.

The Security Scorecard gives you a quick view:

| Field | What to look for |
| --- | --- |
| Scope and mode | Audited scope, revision and profile (`audit_profile`). |
| Completion and coverage | Satisfied checks, blockers, exclusions, dependency coverage and remote gaps. |
| Findings and fixes | Severity and evidence status; separate counts for open findings, reported fixes and verified fixes. |
| Review and next action | Jev queue/outcomes and the next unresolved finding or check. |

A reported fix is not verified. Verification requires matching fix/recheck revisions and supplied passed-test evidence; the helper checks consistency, not test truth. The scorecard gives no numeric safety rating or certification.

Report and final chat identify the same report and show its scorecard before a separate `Severity | Count` table: CRITICAL, HIGH, MEDIUM, LOW and INFORMATIONAL, including zeros. Zero findings does not establish safety. [Completion rules](skills/bauer/references/report.md#completionapplicability-input-and-derived-gate) and the [scorecard contract](skills/bauer/references/report.md#security-scorecard) cover evidence fields and report-generation commands.

## Optional Jev

Jev adds judgments on attacker control, missing context and control effectiveness. It cannot suppress findings, lower severity, approve fixes or override reproduced evidence. Accuracy gains and fewer false positives have not been measured.

Every audit runs local selection: disabled by default, MEDIUM threshold, no cap. Scheduling opt-in and final **packet approval** are separate. The agent must read and follow the [captured presence and proactive offer contract](skills/bauer/references/jev.md#mandatory-presence-check-and-proactive-offer), even while scheduling is disabled. Default disabled is not a user decline; with presence, offer the complete eligible queue and wait for consent. Missing keys or API failures leave the base audit available. Host/advisory-provider data policies still apply without Jev.

### Configure your own key

You provide the API key and configure your environment. Bauer reads `TYPESAFE_API_KEY` from its helper process; it does not manage credentials or load configuration files. Get a key from [TypeSafe](https://console.typesafe.ai/); Bauer includes no key or credits.

The variable must be available to the helper process. Sending evidence still requires approval; see [the Jev contract](skills/bauer/references/jev.md). A [secret manager](https://developer.1password.com/docs/cli/secrets-environment-variables/) is recommended.

## Installation and limits

Claude/Codex manifests and the portable `skills/bauer/` bundle are provided. Hermes tap:

```sh
hermes skills tap add luxsolari/lux-solari-hermes-plugins
hermes skills install luxsolari/lux-solari-hermes-plugins/skills/bauer
```

GitHub quota may require authentication. Keep normal scanning enabled and restart the session. Historical installs apply to their exact package, not unpublished changes.

### Known host limits

Claude discovered target names before confirmation, inspected some helper help late and needed a third turn to save full reports. Codex mistook offline scope for explicit review disable; user correction and a third confirmation turn repaired the record. Explicit Lean two-turn and decline routes passed separately. These bounded exercises do not certify strict preconfirmation isolation or prevent host reads and hallucinated input. New-release host activation and fresh installation are not established by historical installs. [The journal](JOURNAL.md) holds receipts and remaining gaps.

Read-only inspection is the default. No live exploitation, secret access, destructive testing or automatic remediation. Repository scripts/build hooks require permission and isolation. Failed guidance freshness/extraction stays a gap. LLM PDF extraction is agent-led; publication wording/download labels need document verification. Secret screening is best effort. OSV leap-second timestamps fail closed as incomplete; nanosecond fractions are supported. Remote controls need authorized evidence. Complete ledgers validate supplied consistency, never truth or security certification.

## Contributing

Keep runtime changes focused and reuse shared validation. Review every Markdown document for concise, functional prose; link to one authoritative policy instead of copying it. Preserve consent boundaries, partial outcomes and recorded failures. Avoid new dependencies, abstractions or documentation files without a concrete need.

Code/workflow: MIT. Guidance retains its terms; see [NOTICE.md](NOTICE.md). No affiliation with FIA, Jo Bauer, OWASP or TypeSafe.
