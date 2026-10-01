# Supply-chain audit

Review supply-chain evidence explicitly, not merely as dependency CVE lookup. Use selected OWASP Web/LLM supply-chain categories, SLSA source/build requirements and relevant OpenSSF Scorecard checks. Retrieve and freeze published framework versions; never assert a SLSA level from a few observed practices or a Scorecard score.

## Audit surfaces

- Dependencies: resolved direct/transitive inventory, advisory and malware matches, maintained branches, package origins, private/public registry precedence, dependency confusion, uncontrolled installation hooks and updates. Missing origin or integrity evidence is a gap, not proof of maliciousness.
- Source: review protections, permitted bypasses, protected release branches/tags and publishing identities. Local configuration is not server-side enforcement; query read-only repository settings only with authorized access.
- CI: untrusted pull-request inputs reaching privileged jobs, workflow/shell injection, minimal token permissions, secret boundaries, reusable workflow/action pinning, caches, artifact handoffs and persistent/self-hosted runner isolation. Immutable pins establish identity, not that the pinned code is benign.
- Build: toolchain/container origin and immutable digests, verified downloads, build isolation, dependency resolution, provenance generation and expected builder identity. Do not execute builds merely to inspect them.
- Release/distribution: source revision-to-artifact digest binding, trusted signing/provenance verification against expected identity and policy, registry upload permissions, release approvals, mutable tags, update-channel integrity and rollback. A signature without expected identity verification is insufficient.
- AI artifacts: model/adapter and dataset origins, revision pinning, integrity/licensing evidence, risky deserialization, third-party tools/MCP packages, retrieval/training data provenance and write permissions. Never deserialize unknown artifacts for inspection.

## Evidence and limitations

Record every selected control in supplemental `supply_chain_checks` with stable control ID, framework/version reference, reviewed/not_applicable/not_tested, reason and evidence. Settings, registries, builders, attestations and deployment details inaccessible from the checkout are `not_tested`, not assumed safe or absent. Read-only API access still requires authorization; never change protections, publish artifacts or access secrets as part of an audit.

OpenSSF Scorecard per-check results can support investigation when available for the relevant repository/revision. Record revision/time/tool version and incomplete checks; do not use an aggregate score as a trust decision. Obtain permission before installing/running scanners. Existing SBOMs and attestations are evidence to validate, not proof by their mere presence.

Follow `references/advisories.md` for advisory matching and disclosure boundaries. Findings retain severity, evidence status and threat prioritization separately. These are agent-mediated checks; no automated SBOM generation, provenance/signature verifier or Scorecard runner ships in this initial implementation.
