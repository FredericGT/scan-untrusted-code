# Risk model (V1.1)

## Verdicts

| Verdict | Exit | Decision |
|---|---:|---|
| `block` | 30 | Do not run. Escalate to security and preserve the artifact. |
| `sandbox_only` | 20 | Do not run on a workstation. Use an isolated disposable VM after review. |
| `manual_review` | 10 | Require code-owner or security review before any execution. |
| `low_indicators` | 0 | No configured high-risk indicator found. Continue normal controls; do not call the artifact safe. |

Use `--exit-zero` to force exit code 0 without changing the report verdict.

## Severity guidance

- **Critical:** remote download and execution in a Git hook; credential collection combined with upload/network behavior; exact high-confidence malware IOC.
- **High:** active Git hook, package lifecycle execution, browser/keychain/wallet/SSH/cloud access, obfuscated execution, persistence, or destructive cleanup.
- **Medium:** remote fetching outside an auto-execution path, suspicious interpreter use, unsafe symlink, or unsigned/hidden executable requiring review.
- **Low/Info:** contextual capability or weak signal that needs combination with other evidence.

## Score

Assign approximate weights by unique rule/path pair: critical 40, high 20, medium 8, low 3, info 0. Repeated examples of the same rule in one file do not add points. Cap the score at 100.

`block` requires an actionable critical signal: archive path traversal, a confirmed high-confidence behavior chain, a critical IOC in source/auto-execution context, or remote content piped to an interpreter in source/auto-execution context. A score threshold alone must not produce `block`.

CI workflows, documentation, issue templates, tests, ignore files, and comments are contextual evidence. Their findings may remain visible but are downgraded and cannot block by score accumulation alone.

## Evidence language

- **Confirmed:** the file, command, setting, or IOC exists in static content.
- **High Confidence:** multiple confirmed capabilities form a plausible harmful chain.
- **Not Confirmed:** execution, upload success, credential use, persistence success, or impact needs runtime evidence.
