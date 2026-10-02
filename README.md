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

### Offline controls

Python 3.9+, standard library only. For a **new audit**, read the helper implementation and help, then make preflight the first workflow command:

```sh
python3 skills/bauer/scripts/control.py preflight --help
python3 skills/bauer/scripts/control.py preflight --mode lean --output /approved/scratch/run.json
```

Use `--output` only at an approved artifact path outside the target; existing files are never overwritten. Preflight returns a pending `run_record` with pinned `audit_profile`, selected/excluded sources, IDs, boolean presence and captured decisions. The agent presents its summary and asks for confirmation in ordinary chat, then **stops** before target inspection, selection, guidance or reports. Lean stays default; nondefault agent proposals must be labeled, not passed off as user requests.

Only after your real later response does the agent capture it with `control.py confirm --run-record /approved/scratch/run.json --decision confirm --user-response 'LITERAL RESPONSE' --response-ref ACTUAL_REFERENCE --output /approved/scratch/confirmed.json`. Placeholders are not consent; the response/reference must come from that interaction. Decline stops the audit. Corrections create a linked new pending record and require new confirmation. See [the run contract](skills/bauer/references/report.md#run-record).

Presence always runs, even offline or with review disabled. An explicit disable needs `--review-decision FILE` containing state `explicit_disable_captured`, literal `user_instruction`, `decision_ref` and `reason`; the shortcut flag is removed. The helper checks structure, not user authority. It cannot prevent fabricated input, certify chat delivery or authorize external calls. Profile changes require a new preflight, not editing the original record.

Saved controls and plan previews do **not** use preflight:

```sh
python3 skills/bauer/scripts/control.py audit --mode lean
python3 skills/bauer/scripts/control.py mode --mode full
python3 skills/bauer/scripts/control.py mode --mode custom --selected-source osv --selected-source cve --selected-source kev
python3 skills/bauer/scripts/control.py mode --profile-file /explicit/path/profile.json
python3 skills/bauer/scripts/control.py status /explicit/path/report.json --current-revision REVISION
python3 skills/bauer/scripts/control.py scorecard /explicit/path/report.json --format markdown
```

`audit` is a dry-run plan for the agent workflow, not a scanner. `mode` inspects a per-run profile. Neither queries sources nor saves settings. `--profile-file` reads only an explicitly supplied nonsecret JSON profile object; it cannot be combined with inline overrides. No implicit settings search or persistent mode set exists. These are Python commands, not promised host slash commands. Installed agents resolve helpers relative to their skill.

`status` reads frozen evidence: missing revision/time is unknown; an explicit mismatch warns `stale_revision`. A match does not prove freshness or unchanged dirty files. `scorecard` renders saved evidence without a new audit. Status bundles the same report handle, scorecard and counts; Markdown controls show all five severity rows. Both support JSON/Markdown and reject forged derived metadata. Saved inspection needs no key check or audit-warning preflight.

Validated v0.2.1 saved gates migrate to explicit Full, retaining their original gate and gaps; never strip the old gate to force Lean.

### Completion and Security Scorecard

Supply `audit_profile`, `completion_checks` and `completion_scope` using the [report contract](skills/bauer/references/report.md). The gate tracks selected obligations, exact dependency identities and relevant remote targets. Missing records stay `unattempted`; applicability `unknown` cannot satisfy a row. Local source does not establish deployed settings. Ask permission to continue unresolved disclosure, access or testing.

The Security Scorecard precedes severity counts: scope/revision/profile, satisfied checks/blockers, exclusions, dependency coverage, remote gaps, Jev queue/outcomes and next action. It has no numeric security rating or green badge. Findings retain severity and candidate/supported/reproduced evidence status. Remediation is `open`, `fix_reported` or evidenced `fix_verified`; omitted state defaults to open for queue accounting, not factual verification.

```sh
python3 skills/bauer/scripts/selection.py evidence.json --run-record /approved/scratch/confirmed.json
python3 skills/bauer/scripts/report.py evidence.json --run-record /approved/scratch/confirmed.json --format json
python3 skills/bauer/scripts/report.py evidence.json --run-record /approved/scratch/confirmed.json --format markdown
python3 -m unittest discover -s tests -v
```

Final chat names one report handle and pairs its scorecard/completion with all five rows of its `Severity | Count` table, including zeros. Zero findings is not safety. Frozen evidence yields stable reports; fresh agent discovery remains nondeterministic.

New reports require a matching confirmed run file or embedded record; pending/declined/missing confirmation rejects, even with empty completion input. Captures are unsigned assertions, not authenticated proof of user consent or chat delivery. `report.py --saved-report` only normalizes an existing validated saved gate as historical. Published v0.2.1 saved controls/Full migration need no new confirmation; unpublished run-record v1 is unsupported.

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
