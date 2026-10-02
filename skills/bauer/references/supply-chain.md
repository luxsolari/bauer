# Supply-chain review

Core source/CI/build/release and relevant remote checks remain part of the scoped audit. Apply version-qualified SLSA/OpenSSF Scorecard frameworks only when selected by the profile. A few observed practices or an aggregate score cannot establish conformance/trust.

| Surface | Evidence to inspect |
| --- | --- |
| Dependencies | Full resolved inventory, advisories/malware, maintained branches, origins/registry precedence, confusion risk, hooks and updates. Missing integrity/origin is a gap, not maliciousness. |
| Source | Review/protection enforcement, bypasses, release refs and publishing identities. Local config is not server enforcement. |
| CI | Untrusted inputs reaching privileged jobs, injection, token/secret boundaries, immutable workflow/action refs, caches/artifact handoffs and runner isolation. Pins establish identity, not benignness. |
| Build | Toolchain/container digests, downloads, isolation, resolution, provenance and expected builder. Do not execute builds merely to inspect them. |
| Release | Revision/artifact binding, signatures/provenance verified against expected identity and policy, upload permissions/approvals, mutable tags, channels and rollback. Signature presence alone is insufficient. |
| AI artifacts | Model/adapter/dataset/tool/MCP origins, revisions, licensing/integrity, deserialization and data write permissions. Never deserialize unknown artifacts. |

Record controls in supply_chain_checks with stable ID, framework/version, reviewed/not_applicable/not_tested, reason and evidence. Inaccessible settings/registries/builders/attestations stay `not_tested`. Authorized read-only remote access is required; never change protections, publish or read secrets. Completion uses the core/selected ledger in `report.md`, not supplemental rows alone.

Scorecard evidence needs relevant repository/revision/time/tool version and incomplete checks; aggregate ratings are not trust decisions. Scanner installation/execution needs permission. SBOM/attestation presence is evidence to validate. No SBOM generator, signature/provenance verifier or Scorecard runner ships. Advisory disclosure rules: `advisories.md`.
