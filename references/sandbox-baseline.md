# Disposable analysis environment baseline

- Use a disposable full VM or approved malware sandbox, not the employee's normal workstation.
- Create a snapshot before introducing the artifact and destroy/revert it after analysis.
- Use a non-administrator local account with no enterprise identity.
- Do not configure browser profiles, password managers, wallets, SSH keys, cloud CLIs, VPN, Git credentials, or production certificates.
- Disable shared clipboard, drag-and-drop, shared folders, host mounts, USB passthrough, and host keychain access.
- Deny network by default. If network behavior must be observed, route it through an instrumented egress proxy or simulated service and block access to internal/private ranges.
- Collect process creation, file operations, DNS, TCP connections, HTTP/TLS metadata, and packet capture where permitted.
- Prevent access to metadata services such as `169.254.169.254` and local orchestration sockets such as Docker.
- Do not reuse the VM after executing a suspicious artifact.
- Transfer reports out through a controlled path; never transfer executable output back to a trusted workstation without rescanning.
