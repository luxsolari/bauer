# Dependency advisories and root-cause classification

Read `references/security-sources.json` for the approved source registry. OWASP retrieval and OSV inventory queries have bundled helpers; other sources are agent-mediated using available web/terminal tools. Record actual queries and failures; a source listed here is not automatically checked. Inspect `scripts/dependencies.py --help` and supply `{ "packages": [{ "ecosystem": "PyPI", "name": "public-name", "version": "1.2.3" }] }` using actual resolved identities, not this example. Invoke through the terminal tool with `--allow-inventory-disclosure` only after approval, and `--output` for frozen result/provenance. No resolver or repository scanner runs inside this helper; OSV's upstream matching may be fuzzy, so applicability still requires review.

## Inventory and disclosure

Inspect manifests, lockfiles, SBOMs and deployed component records without executing installers. Prefer exact resolved ecosystem/name/version or commit and record direct/transitive and runtime/build/development context. Constraints are not resolved versions. Unknown versions or missing transitive inventory remain gaps. Do not resolve dependencies by running untrusted package hooks. SBOMs describe inventory, not safety.

External package queries disclose names and versions. Obtain approval for inventory disclosure, especially private packages; minimize queries and do not transmit private names, registry credentials or lockfile contents. Local inspection is not necessarily offline/private when performed by a hosted agent: host provider policies still apply.

## Source procedure

1. Query OSV for exact public package ecosystem/version or supported commit identity using official documented API or an approved installed scanner. Record query, retrieval UTC, source update time and response digest. Follow pagination fully or mark incomplete. Affected-version results are advisory matches, not exploit reproductions.
2. Supplement using GitHub Advisory Database and verified maintainer references when needed. GitHub reviewed vulnerability queries exclude malware by default: explicitly check relevant malware advisories as a separate query when supply-chain scope requires it. Preserve reviewed/unreviewed/malware distinction.
3. Verify CVE record identity/state through the CVE Program; consult NVD for enrichment. Keep source-attributed CVSS version/vector and scores separate; conflicting scores remain visible. Match NVD products via established product identity, never fuzzy name alone. Rejected or withdrawn records do not remain active matches without recorded contrary evidence. Reserved records cannot supply a published vulnerability claim.
4. Deduplicate OSV/GHSA/CVE aliases with package/context awareness. Shared CWE or similar text is not an alias. Preserve each source and affected/fixed ranges. Withdrawn advisories, conflicting ranges, distribution backports and unknown applicability need explicit adjudication; no generic lexical version comparison.
5. Check applicable CVEs against CISA KEV. Record catalog time and match/no-match/unavailable separately; no match does not prove no exploitation. FIRST EPSS adds score, percentile, observation date and model version when available. Missing scores remain unknown, not zero. EPSS is likelihood of exploitation in the wild, not likelihood this installation is exploitable or severity.
6. Review vendor/maintainer security advisories for conditions, supported branches, patches, workarounds and backports. Do not assume the latest release is the first fixed version or that upstream version ordering applies to vendor builds. Do not install a suggested fix automatically.
7. Map custom-code findings to the most specific defensible CWE allowed for vulnerability mapping. Record taxonomy version and mapping rationale. Do not invent CVEs for custom findings. Use ASVS version-qualified requirements to guide applicable control verification, with reviewed/not_applicable/not_tested and cited evidence. No ASVS conformance claim from partial checks.

## Report

Known parser boundary: OSV RFC3339 leap-second timestamps (`:60`) are not supported by the current helper. Such responses fail closed as incomplete/invalid_response, not a zero-finding result. Nanosecond fractions and explicit timezone offsets are supported. Keep this compatibility limitation visible until a tested leap-second policy is implemented.

Keep OWASP category mappings, `cwe_ids`, advisory IDs/aliases, affected package evidence, reachability, source-attributed severity and threat signals distinct. Supplemental objects are retained by the report helper but not fully schema-validated: the agent must validate their values against retrieved sources. Jev can assess bounded supplied evidence, never decide package version arithmetic, alias equivalence or KEV membership.

The helper bounds an input to 100 packages per invocation and 128 KiB; this is a local validation/resource bound, not permission to audit only the first batch and not a claim that OSV limits total inventory to 100. After exact inventory-disclosure approval, the agent may split the approved public resolved identities into bounded batches and aggregate deduplicated identity/provenance records. Complete pagination within each identity; failed/unsupported/unapproved identities remain gaps. No automatic batch orchestrator ships. Never assume all discovered identities were approved.

Decide applicability for every registered source, including conditional GHSA; CVE/NVD/KEV/EPSS decisions depend on adjudicated applicable published CVEs and resolved inventory coverage. Distinguish never attempted from attempted retrieval failure. Use the mandatory `completion_checks`/`completion_scope` gate in `report.md`; the legacy arrays alone do not establish complete coverage.

Record source outcomes in `source_checks`: source ID, checked/not_applicable/unavailable, reason, timestamp and snapshot reference. The existing `sources` schema is for year-edition OWASP provenance; preserve non-year framework versions and feed dates in supplemental `source_checks`/`framework_checks` rather than fabricating an edition year.

Official API documentation: https://google.github.io/osv.dev/api/, https://docs.github.com/en/rest/security-advisories/global-advisories, https://nvd.nist.gov/developers/vulnerabilities, https://www.first.org/epss/.
