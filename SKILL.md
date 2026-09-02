---
name: scan-untrusted-code
description: Safely assess an untrusted local repository, source tree, script, ZIP, or TAR archive before execution. Use when Codex needs to inspect unknown code or tools, review Git hooks and package lifecycle scripts, detect remote-download-and-execute chains, credential/browser/keychain/wallet access, suspicious networking or cleanup behavior, apply the daam Node-stealer IOC pack, recommend sandbox controls, or produce a pre-execution security gate report. Never execute, install, build, test, import, or check out the target code.
---

# Scan Untrusted Code (V1.1.2)

Perform an offline, read-only security gate before unknown code is opened or run in a trusted environment. Treat a low finding count as “no known high-risk indicator found,” never as proof of safety.

## Safety boundary

- Never execute a target file or import it as code.
- Never run `git`, `npm`, `yarn`, `pnpm`, `pip`, `python`, `node`, `make`, a test runner, an installer, or a build tool inside the target.
- Never open an untrusted IDE workspace or enable its recommended extensions/tasks.
- Never extract an archive merely to scan it; use the scanner's archive reader.
- Never upload private artifacts to a public reputation or malware service without explicit approval.
- Keep dynamic analysis separate. Recommend a disposable VM when execution is necessary.

## Workflow

1. Resolve the exact local path and confirm whether it is a directory, file, ZIP, or TAR archive.
2. State that the scan is static and non-executing.
3. Run the bundled scanner. Use both Markdown and JSON for a formal assessment:

```bash
python3 <skill-dir>/scripts/scan_untrusted_code.py \
  /absolute/path/to/artifact \
  --format both \
  --output-dir /absolute/path/to/report-directory \
  --exit-zero
```

4. Review the highest-severity findings and their file/line evidence. Do not rely on the score alone.
5. Read [references/checks.md](references/checks.md) when explaining covered and uncovered checks.
6. Read [references/risk-model.md](references/risk-model.md) when making a release, block, or escalation decision.
7. Read [references/sandbox-baseline.md](references/sandbox-baseline.md) when sandbox execution is requested or recommended.
8. Report:
   - verdict, score, verdict basis, and any block signals;
   - critical/high findings with exact paths and line numbers;
   - finding context and whether the path is reachable through an auto-execution surface;
   - auto-execution entry points;
   - matched IOCs;
   - sensitive-data access indicators;
   - limitations and required follow-up.

## Scanner behavior

The scanner:

- reads directories, single files, ZIP, TAR, TAR.GZ, TGZ, TAR.BZ2, and TAR.XZ;
- includes `.git/hooks` and `.git/config` while skipping generated dependency/object directories;
- detects unsafe archive paths and symbolic links without extracting them;
- parses npm lifecycle scripts without invoking npm;
- classifies evidence as source, auto-execution, CI, documentation, test, metadata, dependency metadata, or binary context;
- applies generic behavior rules and the default `daam` IOC pack;
- redacts likely secret values from evidence snippets;
- scores unique rule/path pairs and requires an actionable critical signal or confirmed behavior chain for `block`;
- emits Markdown or JSON and deterministic risk exit codes.

Exit codes are `0` for low/no-high-risk, `10` for manual review, `20` for sandbox-only, and `30` for block. Use `--exit-zero` during interactive analysis so a risk verdict does not look like a tool failure.

## Interpretation rules

- Treat an executable or non-sample Git hook in a distributed `.git` directory as high-risk until reviewed.
- Block a Git hook that downloads and executes remote content.
- Treat browser, Keychain, wallet, SSH, cloud, token, or clipboard access combined with network/upload behavior as critical.
- Treat CI, documentation, issue templates, test fixtures, ignore files, and comments as contextual evidence; they must not create a block verdict by score accumulation alone.
- Treat a normal build-only npm lifecycle command as reviewable execution capability, not as proof of maliciousness.
- Treat reputation signals such as stars, age, and comments as context only; they are not implemented in the offline V1.1 scanner and cannot override code evidence.
- Distinguish `Confirmed` static evidence from `High Confidence` behavioral combinations and `Not Confirmed` runtime outcomes.
- Do not claim that data was uploaded, credentials were stolen, or a repository is safe without runtime/network evidence.

## IOC packs

Load [references/ioc-pack-daam-node-stealer.json](references/ioc-pack-daam-node-stealer.json) by default. Add another pack with repeated `--ioc-pack /path/to/pack.json`. Use `--no-default-ioc-pack` only when performing a generic control test.

## Failure handling

- If a file is encrypted, oversized, malformed, or skipped, list the gap explicitly.
- If an archive cannot be parsed, do not extract or run it as a fallback.
- If the target exceeds limits, rerun with deliberate `--max-files` or `--max-file-bytes` values and disclose the change.
- If findings require execution to validate, stop at a sandbox plan unless the user explicitly authorizes isolated dynamic analysis.
