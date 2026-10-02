# Dependency advisories and CWE

Use selected obligations from `report.md` and IDs from `security-sources.json`. Only OWASP/OSV have bundled clients; other checks are agent-mediated. A registered source is not automatically checked.

## Inventory and disclosure

Inspect manifests, lockfiles, SBOMs and deployed component records without installers. Record exact resolved ecosystem/name/version or supported commit plus direct/transitive/runtime/build/dev context. Constraints, missing versions and incomplete transitive inventories remain gaps. SBOMs are inventory evidence, not safety; never run untrusted package hooks to resolve them.

Obtain explicit inventory disclosure approval. External queries reveal names/versions; do not transmit private identities, credentials or lockfiles. Local inspection by a hosted agent is still subject to host-provider policies.

Inspect `scripts/dependencies.py --help`. Supply actual approved public identities:

```json
{"packages":[{"ecosystem":"PyPI","name":"public-name","version":"1.2.3"}]}
```

Invoke with `--allow-inventory-disclosure` only after approval; use `--output` for frozen provenance. This helper resolves/scans no repository. OSV upstream matching may be fuzzy; matches still need applicability/reachability review.

Bound: **100 packages per invocation**, 128 KiB, not total audit inventory. Batch the full approved scoped identity set and aggregate deduplicated provenance; complete each identity's pagination. Failed/unsupported/unapproved identities stay gaps. No batch orchestrator ships, and discovered inventory is not automatically approved. Full or Lean never means first-batch sampling.

## Selected-source procedure

1. **OSV:** record exact query, UTC retrieval/update time and response digest; complete pagination or mark partial. Matches are not reproductions.
2. **GHSA:** supplement aliases/maintainer detail as selected. Preserve reviewed/unreviewed/malware distinctions; default reviewed-vulnerability queries exclude malware, so check it separately when relevant.
3. **CVE/NVD:** establish published record state and product applicability before enrichment; no fuzzy-name-only NVD match. Preserve source-attributed CVSS/version/vector and conflicts. Reserved/rejected/withdrawn records do not support active vulnerability claims without contrary evidence.
4. **Aliases/ranges:** deduplicate with package/context awareness. Shared CWE/text is not an alias. Retain conflicting affected/fixed ranges, withdrawals, backports and unknown applicability; no lexical version arithmetic.
5. **KEV/EPSS:** use adjudicated applicable CVEs. Record KEV snapshot/match/no-match/unavailable; absence is not absence of exploitation. EPSS needs date/model/score/percentile; missing is unknown, never zero or severity/reachability.
6. **Vendor:** verify branches, first fixed builds, patches/workarounds/backports from maintainer evidence. Latest release is not necessarily first fixed. Do not install suggested fixes automatically.
7. **CWE/ASVS:** defensible mapping-eligible CWE with taxonomy/rationale; no invented custom-code CVE. Selected ASVS uses version-qualified controls and reviewed/not_applicable/not_tested evidence, not partial conformance claims.

## Reporting and limits

Separate OWASP mappings, CWE/aliases, affected-package evidence, reachability, severity and threat signals. Use `completion_checks`/`completion_scope` from `report.md`; supplemental source_checks/framework_checks retain non-year provenance but do not close obligations. Decide selected applicability, including GHSA, with evidence. Unknown/unattempted differs from actual retrieval failure.

OSV leap-second (`:60`) timestamps currently fail closed as incomplete/invalid_response, not zero findings. Nanosecond fractions and offsets are supported. The generic query ledger lacks source-specific OSV applicability; its conservative nonapplicability guard remains documented in `report.md`.

Official APIs: https://google.github.io/osv.dev/api/, https://docs.github.com/en/rest/security-advisories/global-advisories, https://nvd.nist.gov/developers/vulnerabilities, https://www.first.org/epss/.
