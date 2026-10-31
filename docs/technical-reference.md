# ReversePlumbing technical reference

A local, read-only MCP server that lets an AI agent inspect installed apps and saved browser
traffic so you can understand what a product does, then design your own. Written from scratch by
Chibitek and released under the Apache License 2.0. It uses the official MCP SDK over stdio only. It has no HTTP listener, outbound
request, updater, package launcher or browser connection. The one process it can start is an
operator-installed Ghidra, only when the operator passes `--allow-ghidra-invoke`, and only inside a
macOS sandbox that denies all network (see Ghidra below).

## What runs

Every tool is read-only (`readOnlyHint: true`) and reads only files inside an operator-approved
`--root`. Every tool but the opt-in `analyze_with_ghidra` also declares `openWorldHint: false`; that
one declares `openWorldHint: true` and `_meta.launchesProcess: true` and must never be auto-approved.

| Tool | Reads | Returns |
| --- | --- | --- |
| `inspect_visual_evidence` | Reviewed PNG plus SHA-256 and review attestation | MCP image, dimensions and digest; no automatic redaction or OCR |
| `inspect_workflow_evidence` | Reviewed version 1 evidence ledger and local artifacts | Validated evidence, action sequence, feature claims, declared workflow coverage and gaps |
| `inspect_apple_bundle` | `.app` folder | Identity and version, Sparkle update feed and pinning, frameworks, privacy prompts, seal, notarization ticket, provisioning profile |
| `inspect_apple_macho` | Mach-O, thin or universal | Per-architecture header, load commands, UUID, build target, linked libraries, rpaths, SHA-256 |
| `inspect_apple_signature` | Mach-O | Signing identifier, team, cdhash, hardened runtime, entitlements (structural parse, not cryptographic verification) |
| `inspect_apple_strings` | Mach-O | Embedded hosts and URLs, Objective-C class names, Swift field names |
| `inspect_ios_app` | `.ipa` | Identity, SDK, privacy prompts, extensions, provisioning, executable header, FairPlay status; strings when not encrypted |
| `inspect_electron_app` | `.app` with `app.asar`, or the `.asar` | Package manifest, file tree, hosts in bundled script |
| `inspect_electron_rpc` | Same | Generated service descriptors: services, methods, message schemas |
| `inspect_js_sourcemap` | `.map`, or a script that links one | Original source list, bundled npm packages; `source` returns one original file. Inline `data:` maps and relative files are read; remote map URLs are reported, never fetched |
| `inspect_windows_pe` | `.exe`, `.dll`, `.sys` (x86, x64, ARM64) | Headers, ASLR/DEP/CFG flags, sections, imports and delay imports, exports and forwarders, PDB path, version-resource strings, installer overlay size, SHA-256; for .NET: assembly identity, target framework, referenced assemblies, P/Invoke modules |
| `inspect_windows_signature` | Signed PE | Authenticode signatures including nested ones: signer and certificate details, claimed digest, whether the file hashes to it, timestamp (structural parse, not cryptographic verification) |
| `inspect_linux_elf` | ELF executable or `.so` (ARM, ARM64 little and big endian, any machine) | Class, byte order, kind, interpreter, soname, needed libraries, rpath/runpath, build-id, ABI tag, symbol versions, hardening (RELRO, bind-now, NX stack, stack protector, FORTIFY, BTI/PAC/GCS), ARM float ABI, segments, sections, compiler strings, versioned imports and exports, SHA-256 |
| `inspect_android_app` | `.apk` or `.aab` | Package identity and SDK levels, requested and declared permissions, features, application flags, every activity, service, receiver and provider with exported state and intent filters, DEX class and method inventory with embedded URLs, native libraries per ABI through the ELF reader, v1/v2/v3/v3.1/v4 signing structures (structural parse, not cryptographic verification) |
| `inspect_browser_har` | Saved HAR | Templated endpoints, page call sequences, JSON shapes and observed auth schemes; no raw URLs, headers or body values |
| `detect_installed_hopper` | Nothing but a path check | Whether an existing Hopper executable is present; never launches it |
| `detect_installed_ghidra` | The launcher and Ghidra's own properties file | Whether Ghidra is installed, its version and Java home; never launches it |
| `analyze_with_ghidra` | One file in a root; registered only with `--allow-ghidra-invoke` | Loader, processor language and the functions Ghidra's auto-analysis found, with addresses. Launches headless Ghidra in a network-denied sandbox |

Electron apps that ship their code unpacked (for example Cursor, under `Contents/Resources/app/`)
have no `app.asar`; point `inspect_js_sourcemap` at their script files instead. Source maps stored
inside an `app.asar` are not read yet.

## Windows (Phase 2)

The Windows tools are our own PE/COFF, ECMA-335 metadata and DER readers. They read bounded regions
by file offset, so multi-megabyte installers are never loaded whole, and they use no external tool:
nothing like signtool, osslsigncode, dnSpy, ILSpy or Ghidra is detected, launched or fetched. .NET
assemblies are covered inside `inspect_windows_pe` because a .NET binary is a PE file; IL
decompilation is not, and is flagged for Phase 4 planning alongside native decompilers.

`inspect_windows_signature` parses Authenticode: the WIN_CERTIFICATE table, the PKCS#7 SignedData,
the SpcIndirectData digest, nested signatures, and PKCS#9 or RFC 3161 timestamps. Certificates are
decoded with Node's built-in X.509 parser. `fileDigestMatches` recomputes the Authenticode hash of the
file (skipping the checksum, the security directory entry and the certificate table) and compares it
with the digest the signature claims. That shows the file was not altered after the digest was taken.
It does not check the RSA or ECDSA signature, build or validate the certificate chain, check
revocation, or decide trust; no certificate authority, CRL, OCSP responder or timestamp server is
contacted. Treat the signer fields as claims until verified on Windows.

How Windows parsing is tested on macOS, with no Windows machine:

- **Checked-in fixtures** (`test/fixtures/pe/`): our own C# compiled offline by Roslyn for AnyCPU, x64
  and ARM64. Real compiler output, covering PE32 and PE32+, the CLR header, metadata tables, the
  mscoree import and the version resource. See that folder's README for the exact command.
- **Synthetic edits** of those fixtures: a non-PE file, a header pointer past the end, a truncated
  file, a certificate table outside the file, and a ReadyToRun machine code.
- **Microsoft-signed binaries the .NET SDK installs** for native imports, exports, Authenticode with
  nested signatures and RFC 3161 timestamps, and a one-byte tamper that must break the digest match.
  These tests skip when the SDK is absent; they are not checked in, for licensing.
- **Live stdio proof** under OS network denial against real signed installers.

What cannot be proven here: no binary is ever run, because there is no Windows runtime (and the tools
are read-only by design), and no natively linked fixture is checked in, because this Mac has no PE
linker.

## Linux (Phase 3)

`inspect_linux_elf` is our own ELF reader. It handles ELF32 and ELF64 in either byte order, so 32-bit
ARM (armhf, armel), AArch64 and big-endian AArch64 are all covered, and other machines parse the
same way. It reads the header, program and section headers, the dynamic segment, PT_NOTE (GNU
build-id, ABI tag, and the GNU property note where AArch64 records BTI, PAC and GCS), the dynamic
symbol table with its version tables, and `.comment`. Shared objects are covered by the same tool
because a `.so` is an ELF file: it reports the soname, the versions the library defines and its
exports. Files without section headers, as many release builds ship, still yield their symbols:
the count comes from DT_HASH, or from walking the DT_GNU_HASH chains. Reads are bounded regions by
file offset, so a 122 MB binary is never loaded whole.

`inspect_linux_elf` uses no external tool: nothing like readelf, objdump, nm or IDA is detected,
launched or fetched. Function-level analysis is available separately through the opt-in Ghidra tool
(Phase 4).

How ELF parsing is tested on macOS, with no Linux ARM machine:

- **Checked-in fixtures** (`test/fixtures/elf/`): our own C compiled offline by clang and linked by
  lld for AArch64, big-endian AArch64 and 32-bit ARM hard-float, each as a shared object and a PIE
  that links against it. See that folder's README.
- **Synthetic edits** of those fixtures: section headers removed (DT_HASH fallback, both classes),
  DT_HASH also hidden (DT_GNU_HASH walk), a non-ELF file, a bad class byte, a header pointer past
  the end, a truncated file and an out-of-root path.
- **Real Debian ARM64 binaries** (`ls`, `libc.so.6`, `libz.so.1`, `ld-linux-aarch64.so.1`, and a
  122 MB `node`) copied out of a local `node:22-slim` arm64 image with `docker cp`, no pull. Every
  import, export, needed-library, version-definition and segment count matched `llvm-readelf`, used
  only as a development-time check. These are GPL binaries and are not checked in.
- **Live stdio proof** under OS network denial against those real binaries and the fixtures.

What cannot be proven here: no binary is ever run, because there is no Linux ARM runtime (and the
tools are read-only by design).

## Android (Phase 4)

`inspect_android_app` is our own reader for `.apk` and `.aab`. It walks the zip in place and reads:

- **Manifest.** Binary XML in an APK, aapt2 protobuf in a bundle. Typed attribute values win over raw
  strings, as on a device, because repackaged apps often leave a stale raw string. When an obfuscator
  has emptied attribute names, fifteen framework attribute IDs, each confirmed against a real
  manifest's resource map, fill them back in.
- **DEX.** A structural inventory of every `classes*.dex`: counts, class names in Java form,
  superclasses, access flags, method names, a string sample and embedded URLs. Nothing is
  decompiled or disassembled.
- **Native libraries.** Every `lib/<abi>/*.so` goes through the same ELF reader as
  `inspect_linux_elf`. Stored libraries are read in place by offset; compressed ones are inflated
  under a 32 MiB cap, and a larger one is reported as skipped rather than loaded.
- **Signing.** v1 (META-INF PKCS#7 signer certificates and the `X-Android-APK-Signed` claim), v2,
  v3 and v3.1 from the APK Signing Block (certificates, digests, signature algorithms, SDK ranges,
  attribute IDs), the other known block entries by name, and v4 from a sibling `<name>.apk.idsig`.

**Limits, stated plainly.** Signing is a structural parse only, the same as for Authenticode and
Apple code signing: no signature, digest, certificate chain, key rotation lineage or trust is
verified, and the result always says `verified: false`. The protobuf manifest decoder has been
checked only against bundles we built ourselves, since no bundletool or real `.aab` was available.
Modified UTF-8 in DEX strings is decoded as UTF-8, which differs only for NUL and supplementary
characters. One unreadable member (a corrupt DEX, a broken signing block) is named in
`unreadable` rather than failing the whole package.

How it is tested:

- **Checked-in fixtures** (`test/fixtures/apk/`): an APK and AAB we build ourselves, offline. The
  builder writes the binary XML manifest, a DEX and the protobuf manifest byte by byte, copies in the
  ELF fixtures as `arm64-v8a` and `armeabi-v7a` libraries, signs v1 with the JDK's `jarsigner`, and
  adds v2, v3 and a v4 `.idsig` following the published formats with a key generated per build and
  deleted afterwards. `jarsigner -verify` accepts the result, and the certificate fingerprint our
  reader reports equals `keytool -printcert -jarfile`. Ghidra's own DEX loader independently loads
  the fixture DEX and finds the same four methods. No `apksigner` or Android SDK was available, so
  v2, v3 and v4 were not checked by an Android tool.
- **Real third-party APKs** (four apps, including multidex, four ABIs, v1 plus v2 signing and a
  packed app with section headers outside the file) parsed with nothing unreadable, and every v1
  certificate fingerprint matched `keytool`. They are not checked in.

## Ghidra (Phase 4)

Ghidra is operator-installed only. Nothing here downloads, installs or updates it. Development used
Ghidra 12.2 installed with Homebrew; the default launcher is `/opt/homebrew/bin/ghidraRun`, and `--ghidra`
points at another launcher (a plain release zip layout works too).

`detect_installed_ghidra` reads files only: it resolves the launcher, finds `support/analyzeHeadless`,
and reads the version from `Ghidra/application.properties` and the default Java home from the
Homebrew wrapper. It never starts Ghidra or its JVM.

`analyze_with_ghidra` exists only when the server is started with `--allow-ghidra-invoke`. It runs
`analyzeHeadless` on one in-root file in a throwaway project in a temporary folder, with a small
script of our own that lists functions, and deletes the project afterwards. Every launch goes through
`/usr/bin/sandbox-exec` with `(deny network*)`, so neither Ghidra nor anything it loads can open a
socket; the environment is reduced to `PATH`, `HOME` and `JAVA_HOME`. The artifact itself is never
executed. On the ARM64 fixture library it takes about five seconds.

The sandbox denies network only. Ghidra can still write its own settings and log under
`~/Library/ghidra`. Fast-follows: a profile that also confines writes to the temporary project, and
deeper scripting (decompiled C per function, cross-references, strings by function).

## Hopper

Hopper is in Phase 1. Use only an existing purchased and licensed installation. Detection checks
filesystem presence, not licensing. It does not read license files, fetch a trial, install, update,
or check hopperapp.com. The default path is the standard v5 app executable; `--hopper` supports
another version or location selected by the operator. No installed executable was found at the
default path during this slice's verification. Purchased does not necessarily mean installed here.

## Build and run

Node 22.14 or newer. Review and check out the exact approved commit, not a moving branch.
Install once in a versioned directory such as `~/tools/reverseplumbing/0.1.0`:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run build
node dist/server.js --root /absolute/path/to/isolated-artifacts
```

## Wire it into Claude Code or another MCP client

Pick one artifact folder to approve, for example `~/artifacts`, and copy apps into it, or
approve `/Applications` read-only if you want to inspect installed apps in place. Use a fixed Node 22
path, not a version-manager shim. The server runs under the macOS network-deny sandbox with an empty
environment:

```sh
claude mcp add reverseplumbing -- /usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  /usr/bin/env -i HOME=/tmp/reverseplumbing-empty-home PATH=/usr/bin:/bin \
  /opt/homebrew/opt/node@22/bin/node $HOME/tools/reverseplumbing/0.1.0/dist/server.js \
  --root $HOME/artifacts --root /Applications
```

For any client that takes JSON, the same entry is:

```json
{
  "mcpServers": {
    "reverseplumbing": {
      "command": "/usr/bin/sandbox-exec",
      "args": ["-p", "(version 1)(allow default)(deny network*)",
        "/usr/bin/env", "-i", "HOME=/tmp/reverseplumbing-empty-home", "PATH=/usr/bin:/bin",
        "/opt/homebrew/opt/node@22/bin/node", "/absolute/path/to/tools/reverseplumbing/0.1.0/dist/server.js",
        "--root", "/absolute/path/to/artifacts", "--root", "/Applications"]
    }
  }
}
```

Then ask the agent, for example: "Use reverseplumbing to inspect /Applications/Discord.app".

Install dependencies only in the preparation step; direct dependency versions and the complete
resolved tree are pinned in package.json and package-lock.json. Runtime is the local compiled
entrypoint, never npx, npm latest, curl-to-shell, or self-update. No client configuration is shipped.
For a nonstandard existing Hopper installation, append `--hopper /absolute/path/to/executable`.

Run with an empty environment except HOME and PATH, containing no credentials. On macOS,
network-denied execution can be enforced with the OS sandbox:

```sh
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  /usr/bin/env -i HOME=/tmp/reverseplumbing-empty-home PATH=/usr/bin:/bin \
  /absolute/path/to/node dist/server.js --root /absolute/path/to/isolated-artifacts
```

Only approve isolated artifact folders, never your home, repositories containing secrets, or `/`.
The root allowlist resolves symlinks and rejects files outside the approved roots. Reads are capped
at 32 MiB and regular files only; final-component symlinks are not followed when opened. Work on
stable copies: this path check is not a filesystem sandbox against another process concurrently
replacing ancestor directories. For hostile inputs use a read-only container with only the artifacts
mounted, no credentials, and `--network none`. JSON parsing remains bounded by the file-size cap.

## Verification

```sh
npm test
node scripts/prove-stdio.mjs /absolute/path/to/thin-mach-o
node scripts/prove-stdio.mjs /absolute/path/to/signed.exe
node scripts/prove-stdio.mjs /absolute/path/to/linux-arm64-binary
node scripts/prove-stdio.mjs /absolute/path/to/app.apk
node scripts/prove-stdio.mjs /absolute/path/to/linux-arm64-library.so --ghidra
```

`npm test` includes a no-network gate (`test/no-network.test.mjs`): it fails if any source file imports
a module outside the filesystem, hashing, parsing and MCP stdio set, calls `fetch`, `WebSocket`,
`require` or a dynamic `import()`, if a runtime dependency other than the MCP SDK and zod is added, or
if a live stdio session records any network attempt. Further live sessions run both Windows tools,
the Linux ELF tool and the Android tool against checked-in fixtures under the same guard, and, when
Ghidra is installed, the opt-in Ghidra tool.

`node:child_process` is allowed in `src/ghidra.ts` only. The gate requires exactly one `execFile`
call there, routed through `/usr/bin/sandbox-exec` with the `(deny network*)` profile, and forbids
`spawn`, `exec`, `execSync`, `execFileSync` and `fork`. Because the Node guard cannot see inside a
child process, a further test starts a local listener and shows that `curl` reaches it normally but
is refused under that exact profile.

The proof initializes a real SDK client/server session, lists all fifteen tools (sixteen with
`--ghidra`), checks that only the Ghidra tool declares `openWorldHint` and `launchesProcess`, probes
Hopper detection, rejects an out-of-root read, and inspects the optional artifact (Mach-O;
`.exe`/`.dll`/`.sys` through both Windows tools; `.apk`/`.aab` through the Android tool; or ELF,
recognised by its magic bytes). With `--ghidra` it also detects Ghidra and analyzes the artifact. The server starts with a clean
environment. A test-only guard records attempts at Node network APIs; OS network denial is separate
and is the enforcement boundary. The guard is instrumentation, not a general sandbox.

Validated on macOS with network denied, and in a read-only non-root Linux container using
`--network none --cap-drop ALL --security-opt no-new-privileges`, with no host mounts or credentials.
Both runs completed MCP initialization and native inspection with `networkAttempts=0`.
The native proof artifact was compiled locally from `int main(void) { return 0; }`, never executed.

Phase 2 was proven the same way on macOS with `sandbox-exec` denying all network: four real signed
Windows binaries (Microsoft x86 native DLL with a nested signature, Microsoft ARM64 .NET executable,
two third-party x86 installers with SHA-1 and SHA-256 signatures, one with a 10 MB overlay) each listed
twelve tools, parsed, matched their Authenticode digest, and recorded `networkAttempts=0`.

Phase 3 was proven the same way: under `sandbox-exec` denying all network, the stdio proof listed
thirteen tools and ran `inspect_linux_elf` against real Debian ARM64 `ls`, `libc.so.6`, `libz.so.1`,
`ld-linux-aarch64.so.1` and `node` (88,898 exports, about 0.3 s end to end), plus the 32-bit ARM and
big-endian AArch64 fixtures, each recording `networkAttempts=0`.

Phase 4 was proven the same way: under `sandbox-exec` denying all network, the stdio proof listed
fifteen tools and ran `inspect_android_app` on the fixture APK (manifest, DEX, both ABIs and v1 to v4
signing), then with `--ghidra` listed sixteen, detected Ghidra 12.2 and ran `analyze_with_ghidra` on
the ARM64 fixture library (AARCH64:LE:64:v8A, seven functions), each recording `networkAttempts=0`.
Five deliberate injections (an `https` import, a `fetch` call, an extra `spawn`, a network-allowing
sandbox profile and a runtime `fetch` inside the Android reader) each failed the gate and were removed.

## Deliberately outside the current slices

No live browser attach, browser launch, request replay, extraction to disk, cryptographic
code-signature verification (Apple, Authenticode or Android), decompilation (native, ELF, DEX or
.NET IL; Ghidra currently lists functions only), Hopper launch, or process capture.
These are subsequent slices, not claims of current functionality. If process capture is added,
it must declare `openWorldHint` and `launchesProcess` and must never be auto-approved. Hopper's
own network behavior on launch will need separate containment before a launch bridge exists.

## Clean-room provenance

ReversePlumbing was written from scratch. It does not copy, vendor or import code from other
reverse-engineering toolkits, including REA (`rea-agents`, MIT), which was studied only as a running
tool to understand its behavior. A line-by-line comparison of `src/`, `scripts/` and `test/` against
`rea-agents` 6.7.0 found no shared code beyond format constants and common Node and Ghidra API calls.
Runtime dependencies are the official MCP TypeScript SDK and zod, both MIT.

Official SDK reference: https://github.com/modelcontextprotocol/typescript-sdk/tree/v1.x

## The method

`skills/clean-room-rebuild/SKILL.md` is the process this tool was built for: study an installed app or
a SaaS you legitimately use, label every finding by how you know it, write an original behavior spec,
and decide build versus buy. It works as an agent skill or as a plain checklist.

## Responsible use

Use ReversePlumbing only on software and services you own, license, or are authorized to examine,
and within their terms. It is for interoperability, security review, learning and designing original
products. Do not use it, or the method, to copy code, assets or wording, to bypass licensing, DRM,
logins, paywalls or rate limits, or to extract credentials or other people's data. Tool output passes
through your AI client, so it may reach your model provider; do not inspect confidential targets
without permission. This is not legal advice. Laws on reverse engineering differ by country and
contract, so check with counsel before relying on any exemption.

## Contributing and security

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md). Licensed under the
[Apache License 2.0](../LICENSE).

## Offline SaaS traffic mapping

Export a HAR from your own authorized browser session, keep it outside repos, and call
`inspect_browser_har` on that local file in an approved root. ReversePlumbing never captures
traffic, attaches to a browser, replays requests or contacts the vendor. Raw captures may contain
credentials; restrict access and do not paste them into conversations.

The result retains standard route vocabulary and aliases other path segments to `:id`. Origins
and page references receive local ordinal aliases; query strings, fragments, userinfo and page
titles are omitted. JSON values become types, known schema keys remain, and unknown keys become
positional `field-N` aliases. This fixed vocabulary avoids leaking customer names or tokens
masquerading as keys. It can merge distinct routes and loses unknown field semantics. It does not
claim arbitrary sensitive input is safe to disclose; review summaries before sharing them.

Flows follow HAR capture order within each `pageref`, not inferred causality. Entries without one
are unassigned. Auth reports observed Bearer/Basic/Digest/Negotiate, other authorization, API-key
headers or cookie presence, never credentials. No observed marker does not mean unauthenticated.
JSON and +json bodies (including base64) are inspected offline; absent, invalid, oversized and
unsupported bodies have explicit states. Bodies are limited to 1 MiB, shapes to 200 nodes, depth 8,
50 object keys and 20 array samples, with truncation flags. Detailed inventory covers the first
1,000 entries; totals cover up to 50,000. Omitted entries are counted. No raw capture hash is emitted.

Run `npm test` for canary redaction tests, shape/route mapping checks, bounds, parser errors and
the existing stdio/no-network/Ghidra sandbox gates.


## Visual evidence operator guide

See [Visual and workflow evidence](workflow-evidence.md) for capture, review, ledger schema, image inspection, feature mapping and coverage checks.
