# Bauer

An F1-inspired security advisor, named after Jo Bauer: inspect the evidence, not the promise.

Bauer is a portable agent skill for authorized, adversarial codebase reviews against current OWASP Web and LLM Top 10 guidance. It combines source tracing and safely authorized tests with source provenance, deterministic JSON reporting, and optional TypeSafe Jev review of focused evidence questions.

## Status

Initial implementation under development. No release or marketplace publication yet. This is an agent-driven workflow, not a standalone scanner, penetration-testing engine, or certification. Tool tests do not demonstrate discovery accuracy. Jev integration must remain optional and requires per-packet external-disclosure consent.

## Local use

Load `skills/bauer/SKILL.md` in your agent. Python 3.9+; helpers use only the standard library. Resolve helper paths relative to the installed skill, and inspect each helper's `--help` before invoking it. Keep audit artifacts outside the target repo. The report helper consumes auditor-supplied evidence; it does not scan the repository.

```sh
python -m unittest discover -s tests -v
python skills/bauer/scripts/report.py evidence.json
```

Claude Code and Codex manifests are provided in this repository. Hermes uses the same `skills/bauer/` directory. Marketplace installation routes will be documented after their publication and readback checks, not guessed in advance.

## Exercised behavior

- 74 offline tests passed locally on Python 3.9.6/macOS. Hosted cross-platform CI remains pending.
- Actual OWASP source retrieval selected Web 2025 and LLM 2026; the LLM PDF category extraction is an agent step, and the downloaded cover's publication-date placeholder remains an explicit provenance discrepancy.
- Approved synthetic live Jev packet returned a schema-validated response from pinned `jev-1.13.0`; no domain-calibration claim.
- Approved public OSV test inventory (`PyPI/requests/2.19.1`, not project inventory) returned ten source records grouped into five alias groups. Applicability stays unverified.
- Read-only self-audit produced category coverage/evidence and deterministic reports; the mutable CI action finding prompted commit pinning. Known OSV leap-second timestamps fail closed as incomplete; nanosecond fractions are supported.
- Isolated Claude/Codex local-marketplace installs and installed helper execution succeeded. Hermes's actual scanner/quarantine/installer API accepted the bundle without force; full CLI/tap installation is still pending because empty-home launcher bootstrap failed on a missing dependency.

These checks exercise the workflow and transport, not exhaustive vulnerability discovery, production exploitation or certification. Instruction changes after an installation snapshot require new readback before claiming that snapshot verifies the latest package.

## Boundaries

The audit source registry now covers OWASP Web/LLM Top 10, CWE, OSV, GitHub advisories, CVE, NVD, CISA KEV, FIRST EPSS, relevant vendor advisories, ASVS, SLSA and OpenSSF Scorecard. OWASP retrieval and OSV curated-inventory queries have dedicated bundled clients; the remaining checks are agent-mediated and conditional on relevance, permissions and available tools. Supply-chain review includes source/CI/build/release integrity, not just dependency advisories. Source availability and untested surfaces must appear in the report. `report.py --format json|markdown` renders both outputs from the same frozen evidence.

- Read-only inspection by default; executing repository code requires permission and isolation.
- No live-target exploitation, secret access, destructive tests or automatic remediation.
- OWASP publication discovery must not trust a stale landing page alone. Frozen sources have editions and digests; failed freshness checks remain visible.
- Jev cannot erase findings, alter severity or override reproduced failures. Its confidence is not measured Bauer accuracy.
- Deterministic reporting means stable aggregation of frozen evidence, not identical findings from fresh AI runs.
- Zero findings does not mean secure.

Original code and workflow are MIT licensed. OWASP guidance retains its own terms; see NOTICE.md. No affiliation with or endorsement by FIA, Jo Bauer, OWASP or TypeSafe is implied.
