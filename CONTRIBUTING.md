# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Ground rules

- **Write it yourself.** Do not paste code from other reverse-engineering tools, decompilers or
  disassemblers, and do not copy code you obtained by decompiling someone else's software. Cite
  public format specifications instead.
- **No third-party artifacts in the repo.** Test fixtures must be built from our own source, with
  the build command documented next to them. Real third-party binaries may be used locally to check
  a parser, but are never committed.
- **Keep the guarantees.** Read-only, stdio only, no network, no new runtime dependencies, and no new
  child processes. `test/no-network.test.mjs` enforces this; do not relax it to make a test pass.
- **Redact by default.** Any tool that reads traffic or strings must drop values, tokens, cookies and
  credentials before output reaches the client, with a test proving it.

## Workflow

```sh
npm ci --ignore-scripts
npm test
```

Open a pull request with a short description of what changed, how you tested it, and which inputs
you used. Keep each pull request to one concern.

By contributing you agree that your contribution is licensed under the Apache License 2.0, the same
license as the project.
