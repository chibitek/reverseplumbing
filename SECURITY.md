# Security policy

ReversePlumbing parses untrusted files: app bundles, executables, archives and saved browser
traffic. A parser bug that leads to code execution, a read outside an approved `--root`, a network
connection, a process launch other than the opt-in sandboxed Ghidra, or a secret surviving HAR
redaction is a security issue.

## Reporting

Report privately through GitHub's "Report a vulnerability" (Security advisories) on this repository.
Do not open a public issue. Include the version or commit, the tool called, and a minimal input that
reproduces the problem. Do not send real credentials or other people's data; build a synthetic
sample instead.

We aim to acknowledge reports within five business days and to agree a disclosure date with you.

## Supported versions

Only the latest commit on `main` receives fixes.

## Guarantees we treat as security boundaries

- Read-only: no tool writes to, modifies or executes the inspected artifact.
- Stdio only: no HTTP listener, outbound request, updater or package launcher.
- Reads are confined to operator-approved roots and capped in size.
- The only child process is an operator-installed Ghidra, registered only with
  `--allow-ghidra-invoke`, launched under a network-denying macOS sandbox.

`npm test` enforces the no-network and no-process rules. A change that weakens them will not be
accepted without a matching security review.
