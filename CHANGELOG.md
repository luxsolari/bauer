# Changelog

## [0.3.0] - 2026-10-02

- Require one interactive mode/decision-record confirmation before any new-audit target work. Preflight creates pending v2; credential-free `confirm` captures a literal later response/reference in a linked new confirmed/declined record. Pending/declined/missing confirmation rejects reports, even empty completion input. Scope changes require new confirmation; unsigned consistency checks are not authenticated user consent or chat verification. Published v0.2.1 history remains supported; unpublished run-record v1 rejects. Host adherence is bounded; see README known limits.

- Reject non-object JSON roots immediately after parsing in `report.py`, including `--saved-report`, with static invalid-input stderr and empty stdout instead of a traceback.

- Bind new audit reports to validated preflight run records: normalized profile, run ID, supplied provenance and always-checked boolean presence. Remove the disable shortcut; capture literal user decisions/references without claiming authority verification. Reject silent profile switches and empty Custom; scope changes create a linked new run. Save artifacts only at explicit approved paths, never overwrite. Saved report normalization remains historical, not new-audit completion. Unsigned records cannot prevent host-side fabrication or reads.

- Add announced-default Lean, Full and explicit Custom profiles, versioned stdlib policy and prerequisite validation. Unselected sources stay visible out_of_scope; dependency/remote obligations remain mandatory.
- Add deterministic Security Scorecard before severity counts, evidence-backed remediation states and stable next-action priority without a numeric rating or certification.
- Add offline `control.py audit` plan, effective `mode`, saved-report `status` and `scorecard`; no scanner, persistent mode setting or implicit configuration reads/writes.
- Accept validated saved v0.2.1 gates through explicit Full/v2 migration with the historical gate retained; preserve ASVS gaps and reject forged metadata before policy overrides. Recompute both Jev queue and scorecard.
- Pair saved status/Markdown scorecards with all five severity counts; distinguish audit presence/consent steps from offline controls.
- Consolidate project documentation and retain historical decisions/failures in the journal. Known host omissions remain documented; this release is not isolation certification.

## [0.2.1] - 2026-10-01

- Require token-intensive audit warnings in actual preflight/closing chat and generated JSON/Markdown. Budget exclusions remain explicit/partial; no new confirmation, automatic cap or invented usage/cost.
- Add stable resource_note with fail-closed forged/stale-note validation; separate optional Jev charges. Existing evidence remains compatible. Verified 96 offline tests. Messaging correction, not a security/detection fix.

## [0.2.0] - 2026-10-01

- Add stdlib completion/applicability gate for all thirteen registered sources, exact dependency coverage and scoped remote settings. Missing/unknown/blocked work stays partial; no new feed client or automatic disclosure.
- Fix false completion from dependency nonapplicability contradicting approved/queried/nonexcluded identities and OSV NA over generic queried scope. Retain classifications and explicit gate reasons; source-specific scope remains open.
- Add deterministic all-finding Jev queue (disabled/MEDIUM default), explicit threshold overrides and separate scheduling/packet consent. Require boolean-only presence/proactive eligible offer with explicit decline/missing/filtering/interaction outcomes.
- Add all five severity rows including zeros, persistent environment/secret-manager guidance and preserved supplemental outcomes. Verified 94 offline tests and bounded synthetic Claude/Codex local routes; not activated-marketplace, fresh-feed or post-consent API verification.

## [0.1.1] - 2026-10-01

- Refresh documentation/packages with actual Claude/Codex dogfood boundaries, source-discovery/secret-filter limits, source catalog, Jev trade-offs and bring-your-own-key setup. Runtime unchanged.

## [0.1.0] - 2026-10-01

- Initial portable Claude/Codex/Hermes audit workflow: official OWASP discovery/provenance, deterministic JSON/Markdown and optional consent-bound Jev evidence review.
- Add opt-in OSV public resolved-inventory queries, pagination, package-aware aliases/provenance and supplemental-check validation.
- Add agent-mediated CWE/GHSA/CVE/NVD/vendor, KEV/EPSS, ASVS and SLSA/Scorecard guidance. No autonomous exploitation or confidence-based suppression.
