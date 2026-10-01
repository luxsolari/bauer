# Bauer

An F1-inspired security advisor, named after Jo Bauer: inspect the evidence, not the promise.

Bauer is a portable agent skill for authorized, adversarial codebase reviews against current OWASP Web and LLM Top 10 guidance. It combines source tracing and safely authorized tests with source provenance, deterministic JSON reporting, and optional TypeSafe Jev review of focused evidence questions.

## Status

Bauer 0.1.0 is [released](https://github.com/luxsolari/bauer/releases/tag/v0.1.0) and listed in the Claude/Codex marketplaces and Hermes tap. Published-install verification is tracked separately. This is an agent-driven workflow, not a standalone scanner, penetration-testing engine, or certification. Tool tests do not demonstrate discovery accuracy.

## Optional Jev setup — bring your own key

**Jev is optional. Bauer can audit and report without it. To use Jev, you must provide your own TypeSafe API key and account; no key, credits or subscription are bundled.** Obtain a key through the [TypeSafe console](https://console.typesafe.ai/). Requests use your account and may incur provider charges.

The adapter reads `TYPESAFE_API_KEY` from its execution environment. It does not load a repository `.env` or save credentials. Never paste the key into an agent conversation, commit it, or put it inside the plugin. Prefer your secret manager; enter any key locally, outside the chat.

### Claude Code

Supply the key to the environment **before launching `claude`**. A secret-manager launcher is preferred. For a one-session Bash launch on macOS/Linux, enter it at a hidden local prompt (not as a literal shell command that enters history):

```bash
read -r -s -p 'TypeSafe API key: ' TYPESAFE_API_KEY; printf '\n'
export TYPESAFE_API_KEY
claude
unset TYPESAFE_API_KEY
```

This example requires Bash; from another shell, run `bash` first. For Claude Desktop/editor integrations, supply the variable through that application's launch environment or supported local environment configuration and restart it. An export in an unrelated terminal is not enough.

### Codex

Use the same hidden-prompt Bash sequence, replacing `claude` with `codex`. If Codex's shell environment policy filters out the key, review its `shell_environment_policy` in your user configuration and allow the helper to receive `TYPESAFE_API_KEY` under your existing policy. Do not broadly forward all credentials or store the literal key in shared settings. Managed policy may prohibit forwarding; report Jev unavailable rather than bypass it. Desktop/cloud executions need the variable in their actual execution environment, not just your local shell.

### Hermes

1. In a local editor, add `TYPESAFE_API_KEY=<your-own-key>` to the **active profile's `.env`**, or map it through Hermes's supported secret manager. Default profile: `~/.hermes/.env`; named profiles use their own Hermes home.
2. On macOS/Linux restrict the file: `chmod 600 ~/.hermes/.env` (use the actual profile path). On Windows restrict its file permissions to your account.
3. Inspect `hermes config get terminal.env_passthrough`. Add `TYPESAFE_API_KEY` while preserving existing entries. If the list is empty:

   ```sh
   hermes config set terminal.env_passthrough '["TYPESAFE_API_KEY"]'
   ```

4. Restart Hermes if needed. Passthrough is necessary because Hermes sanitizes subprocess credentials. Do not disable that protection globally.

### Other agents

Inject `TYPESAFE_API_KEY` through the agent's secret manager or launch environment, and explicitly permit it in the Python helper's subprocess. For containers, remote workers and cloud agents, configure the secret in that worker—not only on your laptop. Never print the environment or key to debug setup.

### Verify and use

Ask the agent to check **presence only** in the helper's execution environment:

```sh
python3 -c "import os; print('Jev key available:', bool(os.environ.get('TYPESAFE_API_KEY')))"
```

Then ask: “Audit with Bauer; prepare a Jev evidence packet and ask before sending it.” Having a key available is **not consent to upload code**. Review the final redacted snippet packet before approval; the helper requires both `--allow-external` and `--packet-reviewed`. Missing keys or API failures leave the base audit available with Jev marked unavailable. Jev never overrides reproduced evidence or decides severity. See [the evidence/credential contract](skills/bauer/references/jev.md).

## Local use

Load `skills/bauer/SKILL.md` in your agent. Python 3.9+; helpers use only the standard library. Resolve helper paths relative to the installed skill, and inspect each helper's `--help` before invoking it. Keep audit artifacts outside the target repo. The report helper consumes auditor-supplied evidence; it does not scan the repository.

```sh
python -m unittest discover -s tests -v
python skills/bauer/scripts/report.py evidence.json
```

Claude Code and Codex manifests are provided in this repository. Hermes uses the same `skills/bauer/` directory. Marketplace installation routes will be documented after their publication and readback checks, not guessed in advance.

## Exercised behavior

- 74 offline tests passed locally on Python 3.9.6/macOS and in hosted Linux/macOS/Windows CI on Python 3.9 and 3.13 ([run](https://github.com/luxsolari/bauer/actions/runs/36898896800)).
- Actual OWASP source retrieval selected Web 2025 and LLM 2026; the LLM PDF category extraction is an agent step, and the downloaded cover's publication-date placeholder remains an explicit provenance discrepancy.
- Approved synthetic live Jev packet returned a schema-validated response from pinned `jev-1.13.0`; no domain-calibration claim.
- Approved public OSV test inventory (`PyPI/requests/2.19.1`, not project inventory) returned ten source records grouped into five alias groups. Applicability stays unverified.
- Read-only self-audit produced category coverage/evidence and deterministic reports; the mutable CI action finding prompted commit pinning. Known OSV leap-second timestamps fail closed as incomplete; nanosecond fractions are supported.
- Isolated Claude/Codex local-marketplace installs and installed helper execution succeeded. Hermes's actual scanner/quarantine/installer API accepted the bundle without force; full CLI/tap installation is still pending because empty-home launcher bootstrap failed on a missing dependency.

These checks exercise the workflow and transport, not exhaustive vulnerability discovery, production exploitation or certification. Instruction changes after an installation snapshot require new readback before claiming that snapshot verifies the latest package.

A bounded source-only audit of OWASP-linked PyGoat at `19d17cc8874861142b330636d068bbde54e86b85` identified ten supported findings. Independent adjudication required two revisions (SQL impact/severity and file-read prerequisites); revised totals are five HIGH, four MEDIUM and one LOW. No target code was executed, no finding was reproduced, and intentional training vulnerabilities are not a production benchmark. All twenty OWASP categories and unqueried feed/framework gaps were recorded.

## Boundaries

The audit source registry now covers OWASP Web/LLM Top 10, CWE, OSV, GitHub advisories, CVE, NVD, CISA KEV, FIRST EPSS, relevant vendor advisories, ASVS, SLSA and OpenSSF Scorecard. OWASP retrieval and OSV curated-inventory queries have dedicated bundled clients; the remaining checks are agent-mediated and conditional on relevance, permissions and available tools. Supply-chain review includes source/CI/build/release integrity, not just dependency advisories. Source availability and untested surfaces must appear in the report. `report.py --format json|markdown` renders both outputs from the same frozen evidence.

- Read-only inspection by default; executing repository code requires permission and isolation.
- No live-target exploitation, secret access, destructive tests or automatic remediation.
- OWASP publication discovery must not trust a stale landing page alone. Frozen sources have editions and digests; failed freshness checks remain visible.
- Jev cannot erase findings, alter severity or override reproduced failures. Its confidence is not measured Bauer accuracy.
- Deterministic reporting means stable aggregation of frozen evidence, not identical findings from fresh AI runs.
- Zero findings does not mean secure.

Original code and workflow are MIT licensed. OWASP guidance retains its own terms; see NOTICE.md. No affiliation with or endorsement by FIA, Jo Bauer, OWASP or TypeSafe is implied.
