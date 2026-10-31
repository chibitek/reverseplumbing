// Android package checks | Chibitek Engineering | 2026-10-24
// Fixtures are our own, built offline by test/fixtures/apk/build.mjs (see its README). Real third-party
// APKs were checked by hand (multidex, four ABIs, v1+v2, a packed app, keytool fingerprints); they are not checked in.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectAndroidApp, parseBinaryXml } from '../dist/android.js';

const fixtures = await realpath('test/fixtures/apk');
const apk = join(fixtures, 'chibitek-fixture.apk');
const aab = join(fixtures, 'chibitek-fixture.aab');

async function scratch(action) {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'rp-apk-')));
  try { return await action(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}

test('the manifest yields identity, permissions and every component with its intent filters', async () => {
  const { format, manifest: m, unreadable } = await inspectAndroidApp(apk, [fixtures]);
  assert.equal(format, 'apk');
  assert.deepEqual(unreadable, []);
  assert.deepEqual([m.package, m.versionCode, m.versionName, m.minSdk, m.targetSdk], ['com.chibitek.fixture', 7, '1.0.7', 24, 34]);
  assert.deepEqual(m.permissionsRequested.map(p => p.name), ['android.permission.INTERNET', 'android.permission.RECEIVE_BOOT_COMPLETED']);
  assert.deepEqual(m.permissionsDeclared, [{ name: 'com.chibitek.fixture.permission.SYNC', protectionLevel: 2 }]);
  assert.equal(m.application.allowBackup, false);
  assert.deepEqual(m.componentCounts, { activity: 1, 'activity-alias': 0, service: 1, receiver: 1, provider: 1 });
  const [main] = m.components.activity;
  assert.equal(main.exported, true);
  assert.deepEqual(main.intentFilters[0], { actions: ['android.intent.action.MAIN'], categories: ['android.intent.category.LAUNCHER'], data: [] });
  assert.deepEqual(main.intentFilters[1].data, [{ scheme: 'https', host: 'fixture.chibitek.com' }]);
  assert.equal(m.components.service[0].permission, 'com.chibitek.fixture.permission.SYNC');
  assert.deepEqual(m.components.receiver[0].intentFilters[0].actions, ['android.intent.action.BOOT_COMPLETED']);
  assert.deepEqual([m.components.provider[0].authorities, m.components.provider[0].grantUriPermissions], ['com.chibitek.fixture.files', true]);
});

test('DEX is inventoried: classes, methods, strings and embedded URLs', async () => {
  const { dex: [d] } = await inspectAndroidApp(apk, [fixtures]);
  assert.equal(d.version, '035');
  assert.deepEqual(d.counts, { strings: 14, types: 8, protos: 3, fields: 0, methods: 6, classes: 2 });
  assert.deepEqual(d.classes.map(c => [c.name, c.superclass, c.methods]), [
    ['com.chibitek.fixture.MainActivity', 'android.app.Activity', ['<init>', 'onCreate']],
    ['com.chibitek.fixture.BootReceiver', 'android.content.BroadcastReceiver', ['<init>', 'onReceive']]]);
  assert.deepEqual(d.urls, ['https://api.chibitek.com/fixture/v1']);
});

test('native libraries per ABI go through the ELF reader in place', async () => {
  const { nativeLibraries, abis } = await inspectAndroidApp(apk, [fixtures]);
  assert.deepEqual(abis, ['arm64-v8a', 'armeabi-v7a']);
  for (const lib of nativeLibraries) {
    assert.equal(lib.stored, true);
    assert.equal(lib.soname, 'libchibi.so.1');
    assert.equal(lib.exports.count, 4);
  }
  assert.deepEqual(nativeLibraries.map(l => l.machine), ['aarch64', 'arm']);
  // A stored library is hashed in place and must equal the ELF fixture it was copied from.
  const { createHash } = await import('node:crypto');
  const elf = await readFile('test/fixtures/elf/libchibi-aarch64.so');
  assert.equal(nativeLibraries[0].sha256, createHash('sha256').update(elf).digest('hex'));
});

test('v1, v2, v3 and v4 signing structures are read and never claimed verified', async () => {
  const { signing: s } = await inspectAndroidApp(apk, [fixtures]);
  assert.deepEqual(s.schemes, ['v1', 'v2', 'v3', 'v4']);
  assert.equal(s.verified, false);
  const fp = s.v1.signers[0].certificates[0].sha256Fingerprint;
  assert.match(s.v1.signers[0].certificates[0].subject, /CN=Chibitek ReversePlumbing Fixture/);
  assert.equal(s.signingBlock.v2[0].certificates[0].sha256Fingerprint, fp);
  assert.equal(s.signingBlock.v3[0].certificates[0].sha256Fingerprint, fp);
  assert.deepEqual(s.signingBlock.v3[0].sdk, { min: 24, max: 0x7fffffff });
  assert.equal(s.signingBlock.v2[0].signatureAlgorithms[0], 'RSASSA-PKCS1-v1_5 with SHA2-256');
  assert.equal(s.v4.version, 2);
  assert.equal(s.v4.apkDigest, s.signingBlock.v3[0].digests[0].digest);
  assert.equal(s.v4.certificate.sha256Fingerprint, fp);
});

test('a bundle reads its protobuf manifest per module', async () => {
  const r = await inspectAndroidApp(aab, [fixtures]);
  assert.equal(r.format, 'aab');
  assert.deepEqual(r.unreadable, []);
  const [base] = r.modules;
  assert.equal(base.module, 'base');
  assert.deepEqual([base.manifest.package, base.manifest.versionCode, base.manifest.targetSdk], ['com.chibitek.fixture', 7, 34]);
  assert.equal(base.manifest.components.activity[0].exported, true);
  assert.equal(base.manifest.application.allowBackup, false);
  assert.equal(base.dex[0].counts.classes, 2);
  assert.deepEqual(base.abis, ['arm64-v8a']);
  assert.deepEqual(r.signing.schemes, []);
});

test('blanked attribute names fall back to framework resource IDs', async () => {
  const { readMember, readCentralDirectory } = await import('../dist/ipa.js');
  const { entries } = await readCentralDirectory(apk, [fixtures]);
  const xml = Buffer.from(await readMember(apk, [fixtures], entries.find(e => e.name === 'AndroidManifest.xml')));
  // Obfuscators empty the names that have resource IDs; the first pool string is "name".
  const at = xml.indexOf(Buffer.from('\x04\x04name\0', 'latin1'));
  xml.fill(0, at, at + 2);
  const m = parseBinaryXml(xml);
  assert.equal(m.children.find(c => c.tag === 'uses-permission').attrs.name, 'android.permission.INTERNET');
});

test('limit caps lists, and malformed or out-of-root packages are refused or reported', () => scratch(async dir => {
  const small = await inspectAndroidApp(apk, [fixtures], 1);
  assert.equal(small.dex[0].classes.length, 1);
  assert.equal(small.dex[0].counts.classes, 2);
  await assert.rejects(inspectAndroidApp(apk, [fixtures], 0), /limit/);
  await assert.rejects(inspectAndroidApp(apk, [dir]), /outside/);
  await writeFile(join(dir, 'not.apk'), 'PK not really');
  await assert.rejects(inspectAndroidApp(join(dir, 'not.apk'), [dir]));
  // A wrong length in the signing block footer must be refused as such, not read past the block.
  const broken = await readFile(apk);
  const magic = broken.lastIndexOf(Buffer.from('APK Sig Block 42'));
  broken.writeBigUInt64LE(0xffffffn, magic - 8);
  await writeFile(join(dir, 'broken.apk'), broken);
  const r = await inspectAndroidApp(join(dir, 'broken.apk'), [dir]);
  // The rest of the package still reads; only the block is named as unreadable.
  assert.deepEqual(r.unreadable, ['APK Signing Block']);
  assert.equal(r.manifest.package, 'com.chibitek.fixture');
}));
