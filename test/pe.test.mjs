// Windows PE and Authenticode checks | Chibitek Engineering | 2026-10-24
// Fixtures are our own C# compiled offline by Roslyn (see test/fixtures/pe/README.md). Signed native
// coverage uses Microsoft-signed binaries the .NET SDK installs, and skips when they are absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { access, copyFile, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { inspectPe } from '../dist/pe.js';
import { inspectAuthenticode } from '../dist/authenticode.js';

const fixtures = await realpath('test/fixtures/pe');
const fixture = name => join(fixtures, name);
const SDK = '/usr/local/share/dotnet/sdk/6.0.420';
const signedNative = `${SDK}/Microsoft.VisualStudio.TestTools.CppUnitTestFramework.x64.dll`;
const exists = path => access(path).then(() => true, () => false);

async function scratch(action) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'rp-pe-')));
  try { return await action(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('each fixture reports its architecture and PE format', async () => {
  for (const [name, machine, format] of [['fixture-anycpu.dll', 'x86', 'PE32'], ['fixture-x64.dll', 'x64', 'PE32+'], ['fixture-arm64.dll', 'arm64', 'PE32+']]) {
    const pe = await inspectPe(fixture(name), [fixtures]);
    assert.equal(pe.machine, machine, name);
    assert.equal(pe.format, format, name);
    assert.equal(pe.reproducible, true);
    assert.equal(pe.timestamp, null);
    assert.equal(pe.signed, false);
    assert.match(pe.sha256, /^[0-9a-f]{64}$/);
  }
});

test('an AnyCPU assembly imports the CLR loader and carries its version resource', async () => {
  const pe = await inspectPe(fixture('fixture-anycpu.dll'), [fixtures]);
  assert.deepEqual(pe.imports, [{ dll: 'mscoree.dll', count: 1, functions: ['_CorDllMain'] }]);
  assert.ok(pe.dllCharacteristics.includes('dynamicBase') && pe.dllCharacteristics.includes('nxCompat'));
  assert.deepEqual(pe.sections.map(s => s.name), ['.text', '.rsrc', '.reloc']);
  assert.equal(pe.version.fileVersion, '1.2.3.4');
  assert.equal(pe.version.strings.CompanyName, 'Chibitek');
  assert.equal(pe.version.strings.FileDescription, 'ReversePlumbing PE fixture');
});

test('.NET metadata yields the assembly identity and its references', async () => {
  const { dotnet } = await inspectPe(fixture('fixture-x64.dll'), [fixtures]);
  assert.deepEqual(dotnet.flags, ['ilOnly']);
  assert.equal(dotnet.runtimeVersion, 'v4.0.30319');
  assert.deepEqual(dotnet.assembly, { name: 'fixture-x64', version: '1.2.3.4', culture: null, publicKeyToken: null });
  assert.deepEqual(dotnet.references.map(r => r.name), ['System.Runtime', 'System.Net.Http', 'System.Text.Json']);
  assert.equal(dotnet.references[0].publicKeyToken, 'b03f5f7f11d50a3a');
  assert.equal(dotnet.typeCount, 2);
  const limited = await inspectPe(fixture('fixture-x64.dll'), [fixtures], 1);
  assert.equal(limited.dotnet.references.length, 1);
  assert.equal(limited.dotnet.referenceCount, 3);
});

test('an unsigned file reports no signature', async () => {
  const sig = await inspectAuthenticode(fixture('fixture-arm64.dll'), [fixtures]);
  assert.equal(sig.signed, false);
  assert.match(sig.limits, /not verified/);
});

test('ReadyToRun machine codes name the target OS', () => scratch(async dir => {
  const bytes = await readFile(fixture('fixture-x64.dll'));
  bytes.writeUInt16LE(0x8664 ^ 0x4644, bytes.readUInt32LE(0x3c) + 4);
  await writeFile(join(dir, 'r2r.dll'), bytes);
  assert.equal((await inspectPe(join(dir, 'r2r.dll'), [dir])).machine, 'x64 (ReadyToRun, macOS)');
}));

test('malformed and out-of-root files are refused', () => scratch(async dir => {
  const bytes = await readFile(fixture('fixture-x64.dll'));
  await writeFile(join(dir, 'not-pe.bin'), Buffer.from('#!/bin/sh\necho hi\n'));
  await assert.rejects(inspectPe(join(dir, 'not-pe.bin'), [dir]), /MZ/);
  const farHeader = Buffer.from(bytes);
  farHeader.writeUInt32LE(0x7fff0000, 0x3c);
  await writeFile(join(dir, 'far.dll'), farHeader);
  await assert.rejects(inspectPe(join(dir, 'far.dll'), [dir]), /outside the file/);
  await writeFile(join(dir, 'cut.dll'), bytes.subarray(0, 0x200));
  await assert.rejects(inspectPe(join(dir, 'cut.dll'), [dir]));
  const badCert = Buffer.from(bytes);
  const pe = badCert.readUInt32LE(0x3c);
  badCert.writeUInt32LE(bytes.length - 4, pe + 24 + 112 + 4 * 8);
  badCert.writeUInt32LE(4096, pe + 24 + 112 + 4 * 8 + 4);
  await writeFile(join(dir, 'bad-cert.dll'), badCert);
  await assert.rejects(inspectAuthenticode(join(dir, 'bad-cert.dll'), [dir]), /outside the file/);
  await assert.rejects(inspectPe(fixture('fixture-x64.dll'), [dir]));
  await assert.rejects(inspectPe(fixture('fixture-x64.dll'), [fixtures], 0), /limit/);
}));

test('a Microsoft-signed native DLL: imports, exports and a matching Authenticode digest', { skip: !(await exists(signedNative)) && 'SDK binary absent' }, async () => {
  const roots = [dirname(signedNative)];
  const pe = await inspectPe(signedNative, roots, 5);
  assert.equal(pe.machine, 'x64');
  assert.equal(pe.signed, true);
  assert.equal(pe.imports[0].dll, 'KERNEL32.dll');
  assert.ok(pe.exports.nameCount > 0 && pe.exports.symbols.length === 5);
  assert.equal(pe.version.strings.CompanyName, 'Microsoft Corporation');
  const sig = await inspectAuthenticode(signedNative, roots);
  assert.equal(sig.signatures[0].digestAlgorithm, 'sha256');
  assert.equal(sig.signatures[0].fileDigestMatches, true);
  assert.match(sig.signatures[0].signer.subject, /CN=Microsoft Corporation/);
  assert.equal(sig.signatures[0].timestamp.kind, 'rfc3161');
});

test('a single changed byte breaks the digest match', { skip: !(await exists(signedNative)) && 'SDK binary absent' }, () => scratch(async dir => {
  const copy = join(dir, 'tampered.dll');
  const bytes = await readFile(signedNative);
  const textAt = bytes.indexOf('.text');
  bytes[bytes.readUInt32LE(textAt + 20) + 16] ^= 0xff;
  await writeFile(copy, bytes);
  const sig = await inspectAuthenticode(copy, [dir]);
  assert.equal(sig.signatures[0].fileDigestMatches, false);
  await copyFile(signedNative, copy);
  assert.equal((await inspectAuthenticode(copy, [dir])).signatures[0].fileDigestMatches, true);
}));

test('a signed .NET Framework executable reports its target framework', { skip: !(await exists(`${SDK}/TestHost/datacollector.exe`)) && 'SDK binary absent' }, async () => {
  const path = resolve(`${SDK}/TestHost/datacollector.exe`);
  const { dotnet, pdb } = await inspectPe(path, [dirname(path)]);
  assert.equal(dotnet.targetFramework, '.NETFramework,Version=v4.7.2');
  assert.ok(dotnet.flags.includes('strongNameSigned'));
  assert.equal(dotnet.assembly.publicKeyToken, 'b03f5f7f11d50a3a');
  assert.match(pdb.path, /datacollector\.pdb$/);
});
