// ReversePlumbing MCP server | Chibitek Engineering | 2026-10-18
// Run: node dist/server.js --root /absolute/artifacts [--hopper /absolute/executable] [--ghidra /absolute/ghidraRun] [--allow-ghidra-invoke]
import { parseArgs } from 'node:util';
import { realpath, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { readArtifact, readMachO, inspectHar, inspectMachO, detectHopper } from './inspect.js';
import { readSignature } from './signature.js';
import { inspectBundle } from './bundle.js';
import { inspectStrings } from './strings.js';
import { inspectElectronApp } from './asar.js';
import { inspectElectronRpc } from './rpc.js';
import { inspectIosApp } from './ipa.js';
import { inspectSourceMap } from './sourcemap.js';
import { inspectPe } from './pe.js';
import { inspectAuthenticode } from './authenticode.js';
import { inspectElf } from './elf.js';
import { inspectAndroidApp } from './android.js';
import { analyzeWithGhidra, detectGhidra } from './ghidra.js';

const { values } = parseArgs({ options: {
  root: { type: 'string', multiple: true }, hopper: { type: 'string' }, ghidra: { type: 'string' },
  'allow-ghidra-invoke': { type: 'boolean' },
} });
if (!values.root?.length) throw new Error('Supply at least one --root /absolute/artifacts directory.');
const roots = await Promise.all(values.root.map(async root => {
  if (!isAbsolute(root)) throw new Error('--root must be absolute.');
  const resolved = await realpath(root);
  if (!(await stat(resolved)).isDirectory()) throw new Error('--root must be a directory.');
  return resolved;
}));
if (values.hopper && !isAbsolute(values.hopper)) throw new Error('--hopper must be an absolute executable path.');
const hopperPaths = values.hopper ? [values.hopper] : ['/Applications/Hopper Disassembler v5.app/Contents/MacOS/Hopper Disassembler v5'];
if (values.ghidra && !isAbsolute(values.ghidra)) throw new Error('--ghidra must be an absolute launcher path.');
const ghidraPaths = values.ghidra ? [values.ghidra] : ['/opt/homebrew/bin/ghidraRun'];
const server = new McpServer({ name: 'reverseplumbing-mcp-server', version: '0.1.0' });
const annotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
async function result(action: () => Promise<object>) {
  try {
    const data = await action();
    return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
  } catch {
    // No file content or parser diagnostics from untrusted captures in MCP errors.
    return { isError: true, content: [{ type: 'text' as const, text: 'Inspection failed. Check the format, the approved root, and file permissions.' }] };
  }
}
const inputSchema = z.object({ path: z.string().min(1).max(4096).describe('Absolute local file path inside an operator-approved root.') }).strict();
server.registerTool('inspect_browser_har', {
  title: 'Inspect saved browser traffic', description: 'Map a local HAR export: conservative templated endpoints, capture-order calls grouped by page, bounded JSON keys/types, and observed auth schemes. Values, raw origins, headers, cookies, queries and non-vocabulary names are omitted. Never connects to a browser or replays requests.',
  inputSchema, annotations,
}, ({ path }) => result(async () => inspectHar(await readArtifact(path, roots))));
server.registerTool('inspect_apple_macho', {
  title: 'Inspect Apple native executable', description: 'Read every architecture in a Mach-O or universal binary: header, load-command inventory, UUID, build target, linked and weakly linked libraries, and runtime search paths, with SHA-256 of the whole file. Only header regions are loaded, so binaries of any size are supported. Does not execute the artifact. Decompilation is not supported.',
  inputSchema, annotations,
}, ({ path }) => result(async () => {
  const { fat, slices, sha256, bytes } = await readMachO(path, roots);
  return { sha256, bytes, universal: fat,
    architectures: slices.map(slice => {
      // Only the slice header is read, so whole-file identity stays at the top level, not per slice.
      const { sha256: _file, bytes: _size, ...arch } = inspectMachO(slice.prefix, { sha256, bytes });
      return { sliceOffset: slice.offset, sliceBytes: slice.size, ...arch };
    }) };
}));
server.registerTool('inspect_apple_signature', {
  title: 'Inspect embedded code signature', description: 'Read the code signature sealed into each architecture of a Mach-O: signing identifier, team, cdhash, hardened-runtime and executable-segment flags, and the entitlements the binary claims. Structural parse only: the CMS signature, certificate chain and page hashes are not cryptographically verified.',
  inputSchema, annotations,
}, ({ path }) => result(async () => {
  const { fat, slices, sha256, bytes } = await readMachO(path, roots);
  return { sha256, bytes, universal: fat, architectures: await Promise.all(slices.map(async slice => {
    const { architecture, codeSignature } = inspectMachO(slice.prefix, { sha256, bytes });
    return { architecture, signed: codeSignature !== null,
      signature: codeSignature ? await readSignature(path, roots, { offset: slice.offset + codeSignature.offset, size: codeSignature.size }, slice.size) : null };
  })) };
}));
server.registerTool('inspect_apple_bundle', {
  title: 'Inspect application bundle', description: 'Read an .app bundle as files: identity and version from Info.plist, the Sparkle self-update channel including its feed URL and whether updates are signature-pinned, bundled frameworks, declared privacy prompts, and whether a resource seal, notarization ticket and provisioning profile are present. Does not launch the application or contact any update feed.',
  inputSchema, annotations,
}, ({ path }) => result(() => inspectBundle(path, roots)));
const limitSchema = inputSchema.extend({
  limit: z.number().int().min(1).max(5000).default(200).describe('Maximum entries returned per category.'),
}).strict();
server.registerTool('inspect_apple_strings', {
  title: 'Inspect embedded text and symbols', description: 'Read the readable text sections of a Mach-O binary: the hosts and URLs it embeds, Objective-C class names, and Swift field names from reflection metadata. Reads only the named text sections by their own file offsets, never the whole binary. Does not execute the binary or resolve any host.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectStrings(path, roots, limit)));
server.registerTool('inspect_electron_app', {
  title: 'Inspect Electron application', description: 'Read an Electron app.asar archive as bytes: the package manifest and its dependencies, the file tree with sizes, and the hosts embedded in bundled scripts. Nothing is extracted to disk and the application is not launched.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectElectronApp(path, roots, limit)));
server.registerTool('inspect_electron_rpc', {
  title: 'Inspect Electron service surface', description: 'Recover the remote service surface an Electron application was built against: its services, their method names and streaming kinds, and the request and response message schemas with field names, numbers and types. Read from generated descriptors in bundled script; nothing is extracted to disk, the application is not launched, and no service is contacted.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectElectronRpc(path, roots, limit)));
server.registerTool('inspect_ios_app', {
  title: 'Inspect iOS application archive', description: 'Read an .ipa archive in place: bundle identity and build SDK, declared privacy prompts and background modes, app extensions, frameworks and watch apps, the provisioning profile it was signed against, the executable header, and whether that executable is FairPlay-encrypted. When it is not encrypted, the hosts, Objective-C class names and Swift field names it embeds are read too. Nothing is extracted to disk and the application is not installed or launched.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectIosApp(path, roots, limit)));
server.registerTool('inspect_js_sourcemap', {
  title: 'Inspect JavaScript source map', description: 'Read a local .map file, or the source map a local script links to (inline data: maps and relative files inside an approved root). Lists the original source files, bundled npm packages and name count, and with `source` returns one original file from the map. A remote map URL is reported, never fetched.',
  inputSchema: limitSchema.extend({
    source: z.string().min(1).max(4096).optional().describe('Original source path (or trailing part of it) to return in full from sourcesContent.'),
  }).strict(), annotations,
}, ({ path, limit, source }) => result(() => inspectSourceMap(path, roots, limit, source)));
server.registerTool('inspect_windows_pe', {
  title: 'Inspect Windows executable', description: 'Read a Windows PE/COFF file (.exe, .dll, .sys) for x86, x64 or ARM64: headers, security flags (ASLR, DEP, CFG), sections, imported and delay-loaded DLLs with their functions, exports, the PDB path, version-resource strings, installer overlay size, and SHA-256. For .NET assemblies it also reads the assembly identity, target framework, referenced assemblies and P/Invoke modules. Read in bounded regions; the file is never executed.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectPe(path, roots, limit)));
server.registerTool('inspect_windows_signature', {
  title: 'Inspect Authenticode signature', description: 'Read the Authenticode signatures in a Windows PE file, including nested ones: signer and certificate subjects, issuers, serials and validity, the digest the signature claims, whether the file hashes to that digest, and the timestamp. Structural parse only: signatures, certificate chains, revocation and trust are not verified, and no certificate authority is contacted.',
  inputSchema, annotations,
}, ({ path }) => result(() => inspectAuthenticode(path, roots)));
server.registerTool('inspect_linux_elf', {
  title: 'Inspect Linux ELF binary', description: 'Read a Linux ELF executable or shared object (.so) for ARM, ARM64 (including big-endian) or any other machine: class, byte order, kind (PIE, executable, shared object), interpreter, soname, needed libraries, rpath and runpath, build-id, ABI tag, symbol versions needed and defined, hardening (RELRO, bind-now, NX stack, stack protector, FORTIFY, BTI/PAC/GCS), ARM float ABI, segments, sections, compiler strings, and versioned imports and exports from the dynamic symbol table. Read in bounded regions; the file is never executed.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectElf(path, roots, limit)));
server.registerTool('detect_installed_hopper', {
  title: 'Detect installed Hopper', description: 'Check only the operator-configured executable or standard v5 installation path. Does not launch Hopper, verify a license, install, update, download, or use a trial.',
  inputSchema: z.object({}).strict(), annotations,
}, () => result(() => detectHopper(hopperPaths)));
server.registerTool('inspect_android_app', {
  title: 'Inspect Android application', description: 'Read an Android .apk or .aab in place: package identity and SDK levels from the manifest, requested and declared permissions, features, application flags (debuggable, backup, cleartext traffic), every activity, service, receiver and provider with its exported state and intent filters, the DEX class and method inventory with embedded URLs, native libraries per ABI read as ELF, and the v1, v2, v3, v3.1 and v4 signing structures with certificate subjects and fingerprints. Structural parse only: signatures and digests are not verified and trust is not evaluated. Nothing is decompiled, extracted to disk, installed or launched.',
  inputSchema: limitSchema, annotations,
}, ({ path, limit }) => result(() => inspectAndroidApp(path, roots, limit)));
server.registerTool('detect_installed_ghidra', {
  title: 'Detect installed Ghidra', description: 'Check only the operator-configured launcher or the Homebrew path for an installed Ghidra and report its version and Java home. Reads files only: does not launch Ghidra, install, update or download anything.',
  inputSchema: z.object({}).strict(), annotations,
}, () => result(() => detectGhidra(ghidraPaths)));
// Launching a process is opt-in and never auto-approved (see README, Process launching).
if (values['allow-ghidra-invoke']) server.registerTool('analyze_with_ghidra', {
  title: 'Analyze with Ghidra', description: 'Launch the operator-installed Ghidra headless analyzer on one file inside an approved root, in a throwaway project, with network access denied by the macOS sandbox. Returns the loader, processor language and the functions Ghidra found with their addresses. The artifact itself is never executed. Takes seconds to minutes.',
  inputSchema: limitSchema,
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  _meta: { launchesProcess: true },
}, ({ path, limit }) => result(() => analyzeWithGhidra(path, roots, ghidraPaths, limit)));
await server.connect(new StdioServerTransport());
