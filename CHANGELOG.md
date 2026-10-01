# Changelog

## [Unreleased]

## [0.2.0] - 2026-10-01

- Add the fifth stdlib helper, deterministic Jev selection: scheduling disabled by default, MEDIUM minimum when enabled, explicit severity overrides, stable all-finding queue and fail-closed policy validation. Selection does not authorize disclosure; existing packet consent remains mandatory.
- Render all five severity counts, including zeros, in a dedicated Markdown table and require the same table in final agent responses. Preserve evidence statuses and supplemental Jev outcomes independently.
- Add ten regression tests (84 total), bounded independent review and actual Claude/Codex synthetic policy/report exercises. These are not fresh security audits, activated marketplace-plugin checks or live Jev calls.
- Include current persistent environment and secret-manager setup guidance; preserve historical release/install evidence and immutable earlier tags.

## [0.1.1] - 2026-10-01

- Record actual Claude/Codex dogfood boundaries and known source-discovery/secret-filter limitations; refresh release packages with current documentation. Runtime helper behavior is unchanged.

- Edit README using Lux's blog-voice guidance and add the thirteen-source catalog with descriptions and actual integration boundaries.

- Explain with/without-Jev behavior, supplemental evidence-review benefits, disclosure/cost trade-offs and unmeasured accuracy boundaries.

- Document optional bring-your-own-key Jev setup for Claude Code, Codex, Hermes and other agents, including safe presence checks and packet-specific disclosure approval.

## [0.1.0] - 2026-10-01

- Added opt-in OSV curated-inventory queries with bounded pagination, package-aware alias deduplication and response provenance; deterministic Markdown reporting and supplemental-check schema validation.

- Added agent-mediated CWE, OSV/GHSA/CVE/NVD/vendor checks, KEV/EPSS enrichment, ASVS verification guidance and explicit SLSA/Scorecard-informed supply-chain review; distinguish these from bundled retrieval integrations.

- Initial portable security-audit workflow for Claude Code, Codex and Hermes.
- Official OWASP source discovery and provenance, deterministic evidence reports, and optional Jev focused evidence review.
- External evidence review requires explicit consent and packet review; no autonomous exploitation or confidence-based suppression.
