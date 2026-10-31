// Linux ELF checks | Chibitek Engineering | 2026-10-24
// Fixtures are our own C compiled offline by clang and linked by lld (see test/fixtures/elf/README.md).
// Real Debian ARM64 binaries were checked against llvm-readelf by hand; they are GPL and not checked in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectElf } from '../dist/elf.js';

const fixtures = await realpath('test/fixtures/elf');
const fixture = name => join(fixtures, name);
const ARCHES = [['aarch64', 'ELF64', 'little', 'aarch64'], ['aarch64_be', 'ELF64', 'big', 'aarch64'], ['armhf', 'ELF32', 'little', 'arm']];

async function scratch(action) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'rp-elf-')));
  try { return await action(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('each fixture reports its class, byte order and machine', async () => {
  for (const [arch, cls, endian, machine] of ARCHES) {
    for (const name of [`fixture-${arch}`, `libchibi-${arch}.so`]) {
      const elf = await inspectElf(fixture(name), [fixtures]);
      assert.equal(elf.class, cls, name);
      assert.equal(elf.endian, endian, name);
      assert.match(elf.machine, new RegExp(machine), name);
      assert.match(elf.sha256, /^[0-9a-f]{64}$/);
      assert.match(elf.buildId, /^[0-9a-f]{40}$/);
      assert.equal(elf.stripped, false);
    }
  }
});

test('a shared object reports its soname, version definition and exports', async () => {
  for (const [arch] of ARCHES) {
    const so = await inspectElf(fixture(`libchibi-${arch}.so`), [fixtures]);
    assert.equal(so.type, 'shared-object');
    assert.equal(so.soname, 'libchibi.so.1');
    assert.equal(so.interpreter, null);
    assert.deepEqual(so.versionsDefined, ['CHIBI_1.0']);
    assert.equal(so.exports.count, 4);
    assert.deepEqual(so.exports.symbols.map(s => s.name).sort(), ['chibi_add', 'chibi_hello', 'chibi_name', 'chibi_weak']);
    assert(so.exports.symbols.every(s => s.version === 'CHIBI_1.0' && s.type === 'func'));
    assert.equal(so.exports.symbols.find(s => s.name === 'chibi_weak').bind, 'weak');
    assert.deepEqual(so.imports.symbols.map(s => s.name), ['puts']);
  }
});

test('an executable reports its loader, needed library, versions and hardening', async () => {
  for (const [arch] of ARCHES) {
    const exe = await inspectElf(fixture(`fixture-${arch}`), [fixtures]);
    assert.equal(exe.type, 'pie-executable');
    assert.match(exe.interpreter, /^\/lib\/ld-linux-/);
    assert.deepEqual(exe.needed, ['libchibi.so.1']);
    assert.equal(exe.runpath, '$ORIGIN');
    assert.deepEqual(exe.versionsNeeded, [{ library: 'libchibi.so.1', versions: ['CHIBI_1.0'] }]);
    assert.deepEqual(exe.imports.symbols, [{ name: 'chibi_add', type: 'func', bind: 'global', version: 'CHIBI_1.0', library: 'libchibi.so.1' }]);
    const h = exe.hardening;
    assert.equal(h.pie, true);
    assert.equal(h.relro, 'full');
    assert.equal(h.bindNow, true);
    assert.equal(h.nxStack, true);
    assert.equal(h.textRelocations, false);
    assert(exe.segments.some(s => s.type === 'GNU_RELRO'));
  }
  const arm64 = await inspectElf(fixture('fixture-aarch64'), [fixtures]);
  assert.equal(arm64.buildId, '0336751535973dcd33096d16b8b9ecd15f389dbf');
  assert.deepEqual(arm64.hardening.branchProtection, ['BTI', 'PAC', 'GCS']);
  assert.equal(arm64.armAbi, null);
});

test('32-bit ARM reports its EABI version and hard-float ABI', async () => {
  const arm = await inspectElf(fixture('fixture-armhf'), [fixtures]);
  assert.deepEqual(arm.armAbi, { eabiVersion: 5, floatAbi: 'hard' });
  assert.equal(arm.buildId, 'a21fd5ab9040a54135dad17c900febebf47e6042');
});

test('limit caps the section and symbol lists but not their counts', async () => {
  const so = await inspectElf(fixture('libchibi-aarch64.so'), [fixtures], 1);
  assert.equal(so.exports.symbols.length, 1);
  assert.equal(so.exports.count, 4);
  assert.equal(so.sections.length, 1);
  assert(so.sectionCount > 1);
});

// Release builds often ship without section headers. Symbols must then come from the dynamic segment:
// DT_HASH when present, else the DT_GNU_HASH chains.
test('a binary without section headers still yields its symbols', () => scratch(async dir => {
  for (const [name, wide] of [['libchibi-aarch64.so', true], ['libchibi-armhf.so', false]]) {
    const b = await readFile(fixture(name));
    if (wide) { b.writeBigUInt64LE(0n, 40); b.writeUInt32LE(0, 60); } else { b.writeUInt32LE(0, 32); b.writeUInt32LE(0, 48); }
    await writeFile(join(dir, name), b);
    const elf = await inspectElf(join(dir, name), [dir]);
    assert.equal(elf.sectionCount, 0);
    assert.equal(elf.exports.count, 4, name);
    assert.equal(elf.soname, 'libchibi.so.1');
  }
  // Hide DT_HASH (retag it as an unknown OS-specific entry) so only DT_GNU_HASH remains.
  const b = await readFile(fixture('libchibi-aarch64.so'));
  b.writeBigUInt64LE(0n, 40); b.writeUInt32LE(0, 60);
  const phoff = Number(b.readBigUInt64LE(32));
  for (let i = 0; i < b.readUInt16LE(56); i++) {
    const ph = phoff + i * 56;
    if (b.readUInt32LE(ph) !== 2) continue;
    for (let at = Number(b.readBigUInt64LE(ph + 8)); b.readBigUInt64LE(at); at += 16) {
      if (b.readBigUInt64LE(at) === 4n) b.writeBigUInt64LE(0x6fffff00n, at);
    }
  }
  await writeFile(join(dir, 'gnu-only.so'), b);
  const gnu = await inspectElf(join(dir, 'gnu-only.so'), [dir]);
  assert.equal(gnu.exports.count, 4);
  assert.deepEqual(gnu.exports.symbols.map(s => s.version), Array(4).fill('CHIBI_1.0'));
}));

test('malformed, truncated and out-of-root files are refused', () => scratch(async dir => {
  const bytes = await readFile(fixture('fixture-aarch64'));
  await writeFile(join(dir, 'not-elf'), Buffer.from('#!/bin/sh\necho hi\n'));
  await assert.rejects(inspectElf(join(dir, 'not-elf'), [dir]), /ELF/);
  const badClass = Buffer.from(bytes);
  badClass[4] = 9;
  await writeFile(join(dir, 'bad-class'), badClass);
  await assert.rejects(inspectElf(join(dir, 'bad-class'), [dir]), /class or byte order/);
  const farHeaders = Buffer.from(bytes);
  farHeaders.writeBigUInt64LE(0x7fff0000n, 32);
  await writeFile(join(dir, 'far'), farHeaders);
  await assert.rejects(inspectElf(join(dir, 'far'), [dir]));
  await writeFile(join(dir, 'cut'), bytes.subarray(0, 40));
  await assert.rejects(inspectElf(join(dir, 'cut'), [dir]));
  await assert.rejects(inspectElf(fixture('fixture-aarch64'), [dir]));
  await assert.rejects(inspectElf(fixture('fixture-aarch64'), [fixtures], 0), /limit/);
}));
