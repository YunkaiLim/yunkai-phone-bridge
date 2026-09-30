# Security

Yunkai Phone Bridge is intentionally capability-bounded.

## Invariants

- Use only devices the operator is authorized to control.
- Device pairing and ADB authorization remain local user actions.
- Prefer read-only inspection before side-effecting actions.
- Keep semantic identity, policy, expected-postcondition, and verification checks around reflex actions.
- Do not turn the MCP surface into arbitrary `adb shell` or general command execution.
- Keep runtime/tunnel credentials out of MCP arguments, logs, source, and issue reports.

## Public-repository hygiene

Do not commit tunnel IDs, API keys, cookies, OAuth material, device pairing secrets, owner-specific absolute paths, runtime JSON, screenshots, verification captures, binaries, or private logs.

## Reporting

Do not post secrets, device identifiers, or private user data in a public issue. If GitHub private vulnerability reporting is available, use it. Otherwise open a minimal issue without exploit secrets and request a private contact path.
