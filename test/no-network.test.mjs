// No-network gate | Chibitek Engineering | 2026-10-24
// Fails npm test if source gains a network-capable import, global or dependency.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';

const ALLOWED = new Set(['node:crypto', 'node:fs', 'node:fs/promises', 'node:os', 'node:path', 'node:util', 'node:zlib',
  '@modelcontextprotocol/sdk/server/mcp.js', '@modelcontextprotocol/sdk/server/stdio.js', 'zod']);
// (?<!-) skips a command-line flag such as Ghidra's '-import'.
const SPECIFIER = /(?:\bfrom|(?<!-)\bimport)\s*\(?\s*['"]([^'"]+)['"]/g;
const FORBIDDEN = /\b(?:fetch|WebSocket|XMLHttpRequest|EventSource|sendBeacon|require|process\.binding|process\.dlopen)\s*\(|\bnew\s+(?:WebSocket|EventSource|Worker)\b|\bimport\s*\(/;

test('source imports only filesystem, hashing, parsing and the MCP stdio server', async () => {
  for (const name of await readdir('src')) {
    const text = await readFile(`src/${name}`, 'utf8');
    for (const [, spec] of text.matchAll(SPECIFIER)) {
      // Launching a process is confined to the Ghidra module, checked below.
      const launcher = spec === 'node:child_process' && name === 'ghidra.ts';
      assert(launcher || spec.startsWith('./') || ALLOWED.has(spec), `src/${name} imports ${spec}`);
    }
    assert.doesNotMatch(text, FORBIDDEN, `src/${name} uses a network or dynamic-load API`);
  }
});

// The Node guard cannot see inside a child process, so the one launch site must go through the
// macOS sandbox with network denied, and nothing else may start a process.
test('the only process launch is Ghidra under a network-denying sandbox', async () => {
  const text = await readFile('src/ghidra.ts', 'utf8');
  assert.equal(text.match(/\bexecFile\s*\(/g)?.length, 1);
  assert.match(text, /execFile\(file, args,/);
  assert.match(text, /launch\(SANDBOX_EXEC, \['-p', NO_NETWORK, /);
  assert.match(text, /export const SANDBOX_EXEC = '\/usr\/bin\/sandbox-exec';/);
  assert.match(text, /export const NO_NETWORK = '\(version 1\)\(allow default\)\(deny network\*\)';/);
  assert.doesNotMatch(text, /\b(?:spawn|spawnSync|exec|execSync|execFileSync|fork)\s*\(/);
  assert.equal(text.match(/\blaunch\(/g)?.length, 2, 'one definition and one call of launch()');
});

test('the sandbox profile Ghidra runs under refuses a local connection', async () => {
  const { NO_NETWORK, SANDBOX_EXEC } = await import('../dist/ghidra.js');
  const server = createServer(socket => socket.end('HTTP/1.0 200 OK\r\n\r\nok'));
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const url = `http://127.0.0.1:${server.address().port}/`;
  // execFile, not a sync call: the server needs the event loop to answer.
  const curl = (...prefix) => new Promise(done => execFile(prefix[0], [...prefix.slice(1), '/usr/bin/curl', '-s', '-m', '5', url],
    (error, stdout) => done({ ok: !error, stdout })));
  try {
    assert.deepEqual(await curl('/usr/bin/env'), { ok: true, stdout: 'ok' }, 'control: the server answers without the sandbox');
    assert.equal((await curl(SANDBOX_EXEC, '-p', NO_NETWORK)).ok, false, 'the sandbox must refuse the connection');
  } finally { server.close(); }
});

test('runtime dependencies stay pinned to the MCP SDK and zod', async () => {
  const { dependencies } = JSON.parse(await readFile('package.json', 'utf8'));
  assert.deepEqual(Object.keys(dependencies).sort(), ['@modelcontextprotocol/sdk', 'zod']);
  assert(Object.values(dependencies).every(v => /^\d+\.\d+\.\d+$/.test(v)), 'dependency versions must be exact');
});

test('a live stdio session makes zero network attempts', () => {
  const out = execFileSync(process.execPath, ['scripts/prove-stdio.mjs'], { encoding: 'utf8' });
  assert.match(out, /networkAttempts=0/);
});

// Certificate parsing is where a PE reader would be tempted to fetch (AIA issuers, CRLs, OCSP, timestamp
// authorities), so the Windows tools run live under the guard on every test run.
test('the Windows PE and signature tools make zero network attempts', () => {
  const out = execFileSync(process.execPath, ['scripts/prove-stdio.mjs', resolve('test/fixtures/pe/fixture-anycpu.dll')], { encoding: 'utf8' });
  assert.match(out, /inspect_windows_pe/);
  assert.match(out, /inspect_windows_signature/);
  assert.match(out, /networkAttempts=0/);
});

test('the Linux ELF tool makes zero network attempts', () => {
  const out = execFileSync(process.execPath, ['scripts/prove-stdio.mjs', resolve('test/fixtures/elf/fixture-aarch64')], { encoding: 'utf8' });
  assert.match(out, /inspect_linux_elf/);
  assert.match(out, /networkAttempts=0/);
});

test('the Android tool makes zero network attempts', () => {
  const out = execFileSync(process.execPath, ['scripts/prove-stdio.mjs', resolve('test/fixtures/apk/chibitek-fixture.apk')], { encoding: 'utf8' });
  assert.match(out, /inspect_android_app/);
  assert.match(out, /com\.chibitek\.fixture/);
  assert.match(out, /networkAttempts=0/);
});

test('the opt-in Ghidra tool runs under the guard and the sandbox', { skip: !existsSync('/opt/homebrew/bin/ghidraRun') && 'Ghidra is not installed' }, () => {
  const out = execFileSync(process.execPath, ['scripts/prove-stdio.mjs', resolve('test/fixtures/elf/libchibi-aarch64.so'), '--ghidra'], { encoding: 'utf8', timeout: 600_000 });
  assert.match(out, /chibi_hello/);
  assert.match(out, /networkAttempts=0/);
});
