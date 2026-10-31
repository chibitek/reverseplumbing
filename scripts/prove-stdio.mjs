// Stdio smoke proof | Chibitek Engineering | 2026-10-18
// Run: node scripts/prove-stdio.mjs [absolute Mach-O, ELF, .exe, .dll, .apk, .aab or .har path] [--ghidra]
// --ghidra also enables and runs the opt-in Ghidra tool on the artifact (Ghidra must be installed).
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { dirname, resolve } from 'node:path';
import { openSync, readSync } from 'node:fs';
const ghidra = process.argv.includes('--ghidra');
const artifact = process.argv.slice(2).find(arg => arg !== '--ghidra');
const root = artifact ? dirname(resolve(artifact)) : process.cwd();
const transport = new StdioClientTransport({ command: process.execPath,
  args: ['--import', resolve('scripts/network-guard.mjs'), resolve('dist/server.js'), '--root', root, ...(ghidra ? ['--allow-ghidra-invoke'] : [])],
  env: { HOME: '/tmp/reverseplumbing-empty-home', PATH: '/usr/bin:/bin' }, stderr: 'pipe' });
let stderr = '';
transport.stderr?.on('data', data => { stderr += data; });
const client = new Client({ name: 'reverseplumbing-local-proof', version: '0.1.0' });
try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  assert.equal(tools.length, ghidra ? 18 : 17);
  // Only the opt-in Ghidra tool launches a process, and it says so.
  const launcher = tools.filter(tool => tool.annotations.openWorldHint);
  assert.deepEqual(launcher.map(tool => [tool.name, tool._meta?.launchesProcess]), ghidra ? [['analyze_with_ghidra', true]] : []);
  assert(tools.every(tool => tool.annotations.readOnlyHint));
  const hopper = await client.callTool({ name: 'detect_installed_hopper', arguments: {} });
  assert(!hopper.isError);
  console.log(JSON.stringify({ initialized: true, tools: tools.map(tool => tool.name), hopper }));
  const refused = await client.callTool({ name: 'inspect_browser_har', arguments: { path: '/etc/hosts' } });
  assert.equal(refused.isError, true);
  // Windows files go through both PE tools, ELF is recognised by its magic (it rarely has an extension),
  // anything else is treated as a Mach-O.
  const magic = Buffer.alloc(4);
  if (artifact) readSync(openSync(resolve(artifact)), magic, 0, 4, 0);
  const names = /\.har$/i.test(artifact ?? '') ? ['inspect_browser_har'] : /\.(exe|dll|sys)$/i.test(artifact ?? '') ? ['inspect_windows_pe', 'inspect_windows_signature']
    : /\.(apk|aab)$/i.test(artifact ?? '') ? ['inspect_android_app']
    : magic.toString('latin1') === '\x7fELF' ? ['inspect_linux_elf'] : artifact ? ['inspect_apple_macho'] : [];
  if (ghidra && artifact) names.push('detect_installed_ghidra', 'analyze_with_ghidra');
  for (const name of names) {
    const native = await client.callTool({ name, arguments: name === 'detect_installed_ghidra' ? {} : { path: resolve(artifact) } });
    assert(!native.isError, JSON.stringify(native));
    console.log(JSON.stringify({ [name]: native }));
  }
} finally { await client.close(); }
// Transport close awaits child exit; guard prints before EOF.
assert.match(stderr, /networkAttempts=0/);
console.log(stderr.trim());
