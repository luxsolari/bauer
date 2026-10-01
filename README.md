# Bauer

Bauer takes its name from Jo Bauer, Formula 1's technical delegate.

Bauer guides your coding agent through a security audit of a codebase. It traces attack paths, checks dependency advisories and reviews the supply chain, then produces JSON and Markdown reports with code evidence, proposed fixes and gaps in coverage. You can add TypeSafe Jev for a second opinion on selected findings.

## Status

Bauer is listed in the Claude/Codex marketplaces and Hermes tap. Version 0.1.1 refreshes the documentation and records the host dogfood results; release status is available on the [releases page](https://github.com/luxsolari/bauer/releases). Your agent runs the audit using the skill and its Python helpers. Installation checks and audit results are recorded below; neither certifies that an application is secure.

## Sources we check

Bauer uses advisory databases, weakness classifications and verification standards. They answer different questions. The report records which sources the agent checked, which were irrelevant and which it could not access.

| Source | What it tells us | How Bauer uses it |
| --- | --- | --- |
| [OWASP Web Top 10](https://owasp.org/Top10/) | Common web application security risks | A bundled helper retrieves the published list; the agent reviews the relevant code paths. |
| [OWASP LLM Top 10](https://genai.owasp.org/) | Risks specific to LLM applications | The helper finds the publication; the agent extracts its categories and reviews LLM/tool/retrieval flows. |
| [CWE](https://cwe.mitre.org/) | Types of software weakness, such as SQL injection | The agent assigns a root-cause classification supported by the evidence. |
| [OSV](https://osv.dev/) | Advisories tied to package versions and commits | A bundled helper queries approved public package versions and records matches, aliases and source history. |
| [GitHub Advisory Database](https://github.com/advisories) | Package vulnerabilities, malware advisories and fixes | The agent checks relevant records and reconciles their aliases with other sources. |
| [CVE Program](https://www.cve.org/) | Identifiers and records for disclosed vulnerabilities | The agent verifies a known vulnerability's identity and record state. |
| [NVD](https://nvd.nist.gov/) | CVE severity, weakness and affected-product information | The agent adds source-attributed details to applicable CVE findings. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities known to have been exploited | The agent checks applicable CVEs to help prioritize remediation. |
| [FIRST EPSS](https://www.first.org/epss/) | Estimated likelihood of CVE exploitation in the next 30 days | The agent records the score and observation date separately from severity. |
| Vendor and maintainer advisories | Product-specific conditions, patches, workarounds and backports | The agent follows verified references for the components in scope. There is no single vendor feed. |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | Specific application security control requirements | The agent selects version-qualified requirements and records what was reviewed or left untested. |
| [SLSA](https://slsa.dev/) | Source/build integrity and provenance requirements | The agent reviews the build and release process against applicable requirements. |
| [OpenSSF Scorecard](https://scorecard.dev/) | Checks of an open-source repository's security practices | The agent uses available per-check results as evidence, not as a blanket trust score. |

Only OWASP retrieval and OSV queries have dedicated clients in this release. The other checks depend on the agent's tools, access and the application being audited. A dependency match still needs an applicability review. An unqueried feed stays unqueried in the report.

## Optional Jev review

### With or without Jev

The audit covers the same code and sources with or without Jev. Jev reviews selected evidence packets after the agent has investigated the finding.

| | Without Jev | With Jev |
| --- | --- | --- |
| Code, dependency and supply-chain review | Agent-led investigation using Bauer's procedures and available sources/tools | Same investigation |
| Evidence verification | Source tracing, counterevidence and authorized tests | Same verification, plus focused questions about reviewed snippet packets |
| Additional judgments | No Jev probabilities; missing values stay unavailable | Attacker-control and missing-context probabilities; effective/ineffective/insufficient-evidence control judgment with its distribution |
| Report | Deterministic JSON/Markdown, severity, evidence status, remediation and gaps | Same report with supplemental Jev answers, model/rubric version and request digest |
| Requirements | No TypeSafe account/key or Jev API cost | Your own TypeSafe key/account, network access and approval for each disclosed packet; provider charges may apply |
| Data disclosure | No evidence sent to TypeSafe; the host agent and advisory services still have their own data policies | Selected redacted snippets/evidence also go to TypeSafe after approval |
| Failure handling | Audit proceeds without Jev | API/key/response failures mark Jev unavailable; the underlying audit still proceeds |

Jev gives the reviewer a few things to work with:

- It evaluates the code snippets, controls and test evidence, rather than just the agent's summary.
- Its probabilities and insufficient-evidence answer show where it is uncertain.
- Separate questions about attacker control, missing context and control effectiveness help you decide what to investigate next.
- The report keeps its answers, model version, question rubric and request digest with the finding.

Use Jev when you want that extra review and can approve sending the packet. Skip it when cost or code-disclosure rules get in the way. We tested the live integration; we have not measured better accuracy or fewer false positives. Model agreement can still be wrong, and confidence is not the probability that a finding is correct. Jev cannot suppress findings, lower severity, override a reproduced failure or approve a fix.

### Configure your key

**Jev is optional, and you must supply your own API key to use it.** Get one from the [TypeSafe console](https://console.typesafe.ai/). Bauer includes no key, credits or subscription; requests use your account and may incur charges.

The adapter reads `TYPESAFE_API_KEY` from its execution environment. It does not load a repository `.env` or save credentials. Never paste the key into an agent conversation, commit it, or put it inside the plugin. Prefer your secret manager; enter any key locally, outside the chat.

### Claude Code

For persistent terminal setup on macOS/Linux, open your shell configuration in a local editor and add:

```bash
export TYPESAFE_API_KEY='REPLACE_WITH_YOUR_OWN_KEY'
```

Replace the placeholder in the editor, not in a command typed into shell history. Use `~/.zshrc` for interactive zsh sessions (`$ZDOTDIR/.zshrc` if you set `ZDOTDIR`), or `~/.bashrc` for interactive non-login Bash sessions. Bash login shells read `~/.bash_profile`, `~/.bash_login` or `~/.profile` instead; add the export to the file your shell uses, or have that file load `.bashrc`.

Open a new terminal, then run `claude`. The exported variable is inherited by Claude and its permitted helper subprocesses; Bauer only reads the environment and never reads or executes your shell configuration. A previously launched Claude process will not receive a later export.

**A secret manager is recommended.** A literal key in shell configuration is plaintext and available to child processes. Keep that file out of shared dotfile repositories and restrict access to your account. If your shell configuration is tracked, use the secret-manager example below or load the export from a separate private file outside the repository; a private file is still plaintext.

For Claude Desktop/editor integrations, supply the variable through that application's launch environment or supported local environment configuration and restart it. Terminal exports are not system-wide settings and do not automatically reach GUI applications.

### Codex

Use the same persistent shell export, then launch `codex` from a new terminal. If Codex's shell environment policy filters out the key, review its `shell_environment_policy` in your user configuration and allow the helper to receive `TYPESAFE_API_KEY` under your existing policy. Do not broadly forward all credentials or store the literal key in shared settings. Managed policy may prohibit forwarding; report Jev unavailable rather than bypass it. Desktop/cloud executions need the variable in their actual execution environment, not just your local shell.

### Secret-manager example: 1Password

With [1Password CLI installed and authenticated](https://developer.1password.com/docs/cli/get-started/), save the TypeSafe key in a vault item and copy its field's secret reference. The example `op://Private/TypeSafe/api_key` is a placeholder: replace it with your actual reference, not the key itself.

For a launch that keeps the literal key out of shell configuration and command history:

```bash
TYPESAFE_API_KEY='op://Private/TypeSafe/api_key' op run -- claude
```

For Codex, replace `claude` with `codex`. [`op run`](https://developer.1password.com/docs/cli/secrets-environment-variables/) resolves the reference and injects the key into the launched process. Keep its default output masking enabled. The key still exists in that process's environment; masking is not an access-control boundary.

For a persistent shortcut, put this function in your `.zshrc` or `.bashrc` **instead of the plaintext export**, then open a new terminal and run `claude-jev`:

```bash
claude-jev() {
  TYPESAFE_API_KEY='op://Private/TypeSafe/api_key' op run -- claude "$@"
}
```

The function stores only a reference and loads the secret when you launch Claude. Do not pass the unresolved `op://` reference directly to `claude`; Bauer does not resolve secret-manager references. Other secret managers work too if their launcher supplies the resolved `TYPESAFE_API_KEY` to the helper's execution environment. This example's command syntax was checked against 1Password's documentation; no live vault retrieval was exercised.

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

Then ask: "Audit with Bauer; prepare a Jev evidence packet and ask before sending it." Review the final redacted snippets before approving disclosure. A configured key does not grant that approval; the helper requires both `--allow-external` and `--packet-reviewed`. If the key is missing or the API fails, Bauer continues the audit and marks Jev unavailable. See [the evidence and credential requirements](skills/bauer/references/jev.md).

## Local use

Load `skills/bauer/SKILL.md` in your agent. Python 3.9+; helpers use only the standard library. Resolve helper paths relative to the installed skill, and inspect each helper's `--help` before invoking it. Keep audit artifacts outside the target repo. The report helper consumes auditor-supplied evidence; it does not scan the repository.

```sh
python -m unittest discover -s tests -v
python skills/bauer/scripts/report.py evidence.json
```

Claude Code and Codex manifests are provided in this repository. Hermes uses the same `skills/bauer/` directory. To install from the public Hermes tap:

```sh
hermes skills tap add luxsolari/lux-solari-hermes-plugins
hermes skills install luxsolari/lux-solari-hermes-plugins/skills/bauer
```

The GitHub download may need authenticated access if the anonymous API quota is exhausted. Keep Hermes's security scanner enabled. Restart your session after installing.

## What we tested

- 74 offline tests passed locally on Python 3.9.6/macOS and in hosted Linux/macOS/Windows CI on Python 3.9 and 3.13 ([run](https://github.com/luxsolari/bauer/actions/runs/36898896800)).
- Actual OWASP source retrieval selected Web 2025 and LLM 2026; the LLM PDF category extraction is an agent step, and the downloaded cover's publication-date placeholder remains an explicit provenance discrepancy.
- Approved synthetic live Jev packet returned a schema-validated response from pinned `jev-1.13.0`; no domain-calibration claim.
- Approved public OSV test inventory (`PyPI/requests/2.19.1`, not project inventory) returned ten source records grouped into five alias groups. Applicability stays unverified.
- Read-only self-audit produced category coverage/evidence and deterministic reports; the mutable CI action finding prompted commit pinning. Known OSV leap-second timestamps fail closed as incomplete; nanosecond fractions are supported.
- Isolated Claude/Codex local-marketplace installs and installed helper execution succeeded. A public Hermes tap install also succeeded through its actual CLI with authenticated GitHub access and normal scanning. All twelve installed files matched the release source; the installed report helper produced JSON/Markdown and identical repeated JSON. The disposable-home launcher had bootstrap failures, so the test used the existing runtime interpreter with automatic runtime repairs disabled; skill scanning stayed enabled.

These checks cover the helpers, API connections and audit procedure. They do not measure how many vulnerabilities Bauer misses. Installation evidence applies to the exact package tested; later changes need another readback.

A bounded source-only audit of OWASP-linked PyGoat at `19d17cc8874861142b330636d068bbde54e86b85` identified ten supported findings. Independent adjudication required two revisions (SQL impact/severity and file-read prerequisites); revised totals are five HIGH, four MEDIUM and one LOW. No target code was executed, no finding was reproduced, and intentional training vulnerabilities are not a production benchmark. All twenty OWASP categories and unqueried feed/framework gaps were recorded.

## Limits

Actual Claude Code session-local plugin execution invoked `bauer:bauer` and read all four helpers. Codex execution loaded the local skill, inspected the native package and exercised bounded offline helper/report checks. Neither run exercised an activated marketplace plugin. Both used cached guidance, left their frozen source trees unchanged and found no new demonstrated security vulnerability.

Claude retained one LOW candidate about publication-status wording heuristics and one INFORMATIONAL secret-filter limitation. The candidate was not reproduced: Web categories are checked exactly, and LLM downloads still require document extraction. Discovery uses a finite wording check, not an authoritative publication-status API. A single official download may be selected without an independently descriptive link label; the agent must verify the document. Secret-pattern screening is best effort and does not replace review of the packet before disclosure. Codex retained the already documented leap-second limitation. These results are scoped reviews, not proof that Bauer is safe under every host or input.

Supply-chain review covers source protections, CI, build inputs, release artifacts and distribution, including AI components where present. Remote settings the agent cannot inspect remain untested. Both report formats come from the same frozen evidence through `report.py --format json|markdown`.

- Read-only inspection by default; executing repository code requires permission and isolation.
- No live-target exploitation, secret access, destructive tests or automatic remediation.
- OWASP publication discovery must not trust a stale landing page alone. Frozen sources have editions and digests; failed freshness checks remain visible.
- Jev cannot erase findings, alter severity or override reproduced failures. Its confidence is not measured Bauer accuracy.
- Deterministic reporting means stable aggregation of frozen evidence, not identical findings from fresh AI runs.
- Zero findings does not mean secure.

Original code and workflow are MIT licensed. OWASP guidance retains its own terms; see NOTICE.md. No affiliation with or endorsement by FIA, Jo Bauer, OWASP or TypeSafe is implied.
