# V1.1 check coverage

## Evidence context

Each finding is classified as `source_code`, `auto_execution`, `ci_workflow`, `documentation`, `test_fixture`, `metadata`, `dependency_metadata`, or `binary`. Context changes severity and scoring so examples in documentation or CI do not look like executable malware.

## Auto-execution surfaces

- Non-sample `.git/hooks/*`, especially `post-checkout`, `post-merge`, `pre-commit`, `post-commit`, and `pre-push`.
- `.git/config` settings for `core.hooksPath`, `core.fsmonitor`, shell aliases, and clean/smudge/process filters.
- `.gitattributes` filters and `.gitmodules` external references.
- npm lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`, and `prepublishOnly`.
- Python `setup.py`, `pyproject.toml`, and `Pipfile`.
- `Makefile`, Gradle/Maven build files, Rust `build.rs`, Go generation directives, Composer scripts, and Ruby extension/install files.
- VS Code tasks/settings, Dev Container definitions, and common shell installers.
- macOS LaunchAgent/LaunchDaemon plist content and persistence commands.

## Behavior patterns

- Remote fetch with `curl`, `wget`, PowerShell web requests, or programmatic URL access.
- Download-to-interpreter and pipe-to-shell chains.
- `node -`, `python -c`, `bash -c`, `eval`, `Function`, base64 decode, and child-process execution.
- Temporary staging under `/tmp`, `/var/folders`, hidden upload directories, or `mktemp`.
- File deletion and cleanup after staging.
- Socket.IO/WebSocket, multipart form, HTTP client, and direct IP indicators.

## Sensitive-data indicators

- Chrome/Edge `Login Data`, `Cookies`, `Web Data`, Local Storage, and Local Extension Settings.
- macOS `login.keychain-db` and `security find-*password` commands.
- `pbpaste` and other clipboard access.
- `.ssh`, `.aws`, kubeconfig, `.env`, `.git-credentials`, `.netrc`, GitHub/GitLab token files.
- MetaMask, Phantom, and OKX extension identifiers.

## Archive checks

- Absolute paths and `..` path traversal.
- Symbolic and hard links.
- Hidden `.git` directories and hooks inside downloaded archives.
- Oversized or unreadable members.

## V1.1 limitations

- Do not perform GitHub/GitLab reputation lookups, malware reputation checks, dependency vulnerability resolution, YARA, binary signing/provenance checks, decompilation, or dynamic execution.
- Do not prove exploitability or successful exfiltration.
- Obfuscated, encrypted, generated, or runtime-fetched payloads may evade content rules.
- Documentation and test fixtures may legitimately contain suspicious strings; review context and auto-execution reachability.
- A clean result means only that configured rules did not find a high-risk indicator in scanned content.
