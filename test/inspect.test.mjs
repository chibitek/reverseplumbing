// ReversePlumbing checks | Chibitek Engineering | 2026-10-18
// Run: npm test. Fixtures are test-only; nothing is written to a product service.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, symlink, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { inspectHar, inspectMachO, machOSections, readArtifact, readMachO, detectHopper } from '../dist/inspect.js';
import { inspectStrings } from '../dist/strings.js';
import { inspectElectronApp } from '../dist/asar.js';
import { inspectElectronRpc } from '../dist/rpc.js';
import { inspectIosApp } from '../dist/ipa.js';
import { deflateRawSync } from 'node:zlib';
import { parsePlist } from '../dist/plist.js';
import { inspectSignatureBlob } from '../dist/signature.js';

test('HAR summaries strip sensitive fields and reject malformed entries', () => {
  const bytes = Buffer.from(JSON.stringify({ log: { entries: [{ request: { method: 'GET', url: 'https://example.com/private?token=test-only', headers: [{ name: 'Authorization', value: 'test-only' }] }, response: { status: 200, content: { text: 'private body' } }, time: 3 }] } }));
  const summary = inspectHar(bytes);
  assert.equal(summary.entries, 1);
  assert.deepEqual(summary.methods, { GET: 1 });
  assert.equal(summary.durationMs, 3);
  assert.doesNotMatch(JSON.stringify(summary), /test-only|private body|example.com/);
  assert.throws(() => inspectHar(Buffer.from('{"log":{"entries":[{}]}}')));
});

test('Mach-O bounds fail closed and valid minimal header parses', () => {
  const bytes = Buffer.alloc(32);
  bytes.writeUInt32LE(0xfeedfacf, 0);
  bytes.writeUInt32LE(0x0100000c, 4);
  bytes.writeUInt32LE(2, 12);
  assert.equal(inspectMachO(bytes).bits, 64);
  bytes.writeUInt32LE(1, 16);
  assert.throws(() => inspectMachO(bytes), /bounds/);
  assert.throws(() => inspectMachO(Buffer.alloc(5)), /Truncated/);
  assert.throws(() => inspectMachO(Buffer.alloc(32)), /thin/);
});

test('artifact roots reject traversal, symlink escapes, directories and oversized files', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-test-')));
  try {
    await writeFile(join(root, 'inside'), 'ok');
    assert.equal((await readArtifact(join(root, 'inside'), [root])).toString(), 'ok');
    await symlink('/etc/hosts', join(root, 'escape'));
    await assert.rejects(readArtifact(join(root, 'escape'), [root]), /outside/);
    await assert.rejects(readArtifact('/etc/hosts', [root]), /outside/);
    await assert.rejects(readArtifact(root, [root]), /regular/);
    await assert.rejects(readArtifact('inside', [root]), /absolute/);
    await writeFile(join(root, 'large'), Buffer.alloc(32 * 1024 * 1024 + 1));
    await assert.rejects(readArtifact(join(root, 'large'), [root]), /32 MiB/);
    assert.equal((await detectHopper([join(root, 'missing')])).installed, false);
    // An existing executable exercises detection only; no process is launched.
    const detected = await detectHopper([process.execPath]);
    assert.equal(detected.installed, true);
    assert.equal(detected.launched, false);
    assert.equal((await detectHopper([join(root, 'inside')])).installed, false);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('Mach-O larger than the HAR cap parses from a bounded header read with a whole-file hash', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-macho-')));
  try {
    // Thin arm64-shaped header: one 16-byte load command, then padding past the 32 MiB HAR cap.
    const header = Buffer.alloc(48);
    header.writeUInt32LE(0xfeedfacf, 0);
    header.writeUInt32LE(0x0100000c, 4);
    header.writeUInt32LE(2, 12);
    header.writeUInt32LE(1, 16);
    header.writeUInt32LE(16, 20);
    header.writeUInt32LE(0x1, 32);
    header.writeUInt32LE(16, 36);
    const body = Buffer.concat([header, Buffer.alloc(33 * 1024 * 1024)]);
    const target = join(root, 'big-thin-macho');
    await writeFile(target, body);

    // The shared whole-document reader still refuses it; the Mach-O path no longer does.
    await assert.rejects(readArtifact(target, [root]), /32 MiB/);
    const { slices, sha256, bytes } = await readMachO(target, [root]);
    assert.equal(slices.length, 1, 'a thin binary is a single slice');
    const prefix = slices[0].prefix;
    assert.equal(prefix.length, 48, 'only the header region is loaded');
    assert.equal(bytes, body.length);
    assert.equal(sha256, createHash('sha256').update(body).digest('hex'), 'hash covers the whole file');

    const summary = inspectMachO(prefix, { sha256, bytes });
    assert.equal(summary.bits, 64);
    assert.equal(summary.commandCount, 1);
    assert.equal(summary.bytes, body.length);
    assert.equal(summary.sha256, sha256);

    // Root and symlink rules are shared, so they must still hold on this path.
    await symlink('/bin/ls', join(root, 'macho-escape'));
    await assert.rejects(readMachO(join(root, 'macho-escape'), [root]), /outside/);
    await assert.rejects(readMachO('/bin/ls', [root]), /outside/);
    await assert.rejects(readMachO('relative', [root]), /absolute/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

// A thin arm64-shaped slice: 32-byte header plus one 16-byte load command.
function thinSlice(cpuSubtype = 0) {
  const slice = Buffer.alloc(64);
  slice.writeUInt32LE(0xfeedfacf, 0);
  slice.writeUInt32LE(0x0100000c, 4);
  slice.writeUInt32LE(cpuSubtype, 8);
  slice.writeUInt32LE(2, 12);
  slice.writeUInt32LE(1, 16);
  slice.writeUInt32LE(16, 20);
  slice.writeUInt32LE(0x1, 32);
  slice.writeUInt32LE(16, 36);
  return slice;
}

test('XML and binary property lists parse to the same values', async () => {
  const xml = Buffer.from(`<?xml version="1.0"?>
<plist version="1.0"><dict>
<key>SUFeedURL</key><string>https://example.com/appcast.xml</string>
<key>CFBundleIdentifier</key><string>com.example.Caf&#233; &amp; Co</string>
<key>NSCameraUsageDescription</key><string>Camera</string>
<key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><true/></dict>
<key>CFBundleURLTypes</key><array><string>x</string></array>
<key>NSPrincipalClass</key><dict/>
<key>SUEnableAutomaticChecks</key><true/>
<key>SUScheduledCheckInterval</key><integer>86400</integer>
</dict></plist>`);
  // Same document, converted to binary1, so both readers are held to one answer.
  const binary = Buffer.from('YnBsaXN0MDDYAQIDBAUGBwgJCgsMDw4SE1lTVUZlZWRVUkxfEBJDRkJ1bmRsZUlkZW50aWZpZXJfEBhOU0NhbWVyYVVzYWdlRGVzY3JpcHRpb25fEBZOU0FwcFRyYW5zcG9ydFNlY3VyaXR5XxAQQ0ZCdW5kbGVVUkxUeXBlc18QF1NVRW5hYmxlQXV0b21hdGljQ2hlY2tzXxAQTlNQcmluY2lwYWxDbGFzc18QGFNVU2NoZWR1bGVkQ2hlY2tJbnRlcnZhbF8QH2h0dHBzOi8vZXhhbXBsZS5jb20vYXBwY2FzdC54bWxvEBUAYwBvAG0ALgBlAHgAYQBtAHAAbABlAC4AQwBhAGYA6QAgACYAIABDAG9WQ2FtZXJh0Q0OXxAWTlNBbGxvd3NBcmJpdHJhcnlMb2FkcwmhEFF4CdASAAFRgAAIABkAIwA4AFMAbAB/AJkArADHAOkBFgEdASABOQE6ATwBPgE/AUAAAAAAAAACAQAAAAAAAAAUAAAAAAAAAAAAAAAAAAABRQ==', 'base64');

  for (const [label, parsed] of [['xml', parsePlist(xml)], ['binary', parsePlist(binary)]]) {
    assert.equal(parsed.SUFeedURL, 'https://example.com/appcast.xml', label);
    assert.equal(parsed.CFBundleIdentifier, 'com.example.Café & Co', `${label} decodes entities and UTF-16`);
    assert.equal(parsed.SUEnableAutomaticChecks, true, label);
    assert.equal(parsed.SUScheduledCheckInterval, 86400, label);
    assert.deepEqual(parsed.NSAppTransportSecurity, { type: 'dict' }, `${label} reports nested containers by shape, identically in both formats`);
    assert.equal(parsed.CFBundleURLTypes.type, 'array', label);
    assert.equal(parsed.NSCameraUsageDescription, 'Camera', label);
    // A self-closing <dict/> is a value, not an unclosed level: 11 apps in /Applications use one.
    assert.deepEqual(parsed.NSPrincipalClass, { type: 'dict' }, `${label} reads an empty container`);
  }
  assert.throws(() => parsePlist(Buffer.from('not a plist')), /property list/);
});

test('universal binaries report every architecture from one bounded read', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-fat-')));
  try {
    const fat = Buffer.alloc(8192 + 64);
    fat.writeUInt32BE(0xcafebabe, 0);
    fat.writeUInt32BE(2, 4);
    // arm64 is cpusubtype 0, arm64e is 2.
    for (const [i, [offset, subtype]] of [[4096, 0], [8192, 2]].entries()) {
      const at = 8 + i * 20;
      fat.writeUInt32BE(0x0100000c, at);      // cputype
      fat.writeUInt32BE(subtype, at + 4);     // cpusubtype
      fat.writeUInt32BE(offset, at + 8);
      fat.writeUInt32BE(64, at + 12);         // size
      fat.writeUInt32BE(12, at + 16);         // align
      thinSlice(subtype).copy(fat, offset);
    }
    const target = join(root, 'universal');
    await writeFile(target, fat);

    const { fat: isFat, slices, sha256, bytes } = await readMachO(target, [root]);
    assert.equal(isFat, true);
    assert.equal(slices.length, 2);
    assert.deepEqual(slices.map(s => s.offset), [4096, 8192]);
    assert.equal(bytes, fat.length);
    assert.equal(sha256, createHash('sha256').update(fat).digest('hex'), 'hash covers the container, not a slice');
    assert.deepEqual(slices.map(s => inspectMachO(s.prefix).architecture), ['arm64', 'arm64e']);

    // A slice pointing past the end of the file must not be read.
    const liar = Buffer.from(fat);
    liar.writeUInt32BE(0x7fffffff, 8 + 8);
    await writeFile(join(root, 'liar'), liar);
    await assert.rejects(readMachO(join(root, 'liar'), [root]), /outside the file/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('code signature SuperBlob yields identity, runtime flags and entitlements', () => {
  const entitlementsXml = '<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.security.app-sandbox</key><true/><key>com.apple.security.network.client</key><true/></dict></plist>';

  const directory = Buffer.alloc(123);
  directory.writeUInt32BE(0xfade0c02, 0);
  directory.writeUInt32BE(directory.length, 4);
  directory.writeUInt32BE(0x20400, 8);        // version with an executable segment
  directory.writeUInt32BE(0x10000, 12);       // CS_RUNTIME
  directory.writeUInt32BE(96, 20);            // identOffset
  directory.writeUInt32BE(7, 28);             // nCodeSlots
  directory.writeUInt32BE(4096, 32);          // codeLimit
  directory.writeUInt8(32, 36);               // hashSize
  directory.writeUInt8(2, 37);                // sha256
  directory.writeUInt8(12, 39);               // pageSize log2
  directory.writeUInt32BE(112, 48);           // teamOffset
  directory.writeBigUInt64BE(1n, 80);         // execSegFlags: main binary
  directory.write('com.example.app\0', 96, 'latin1');
  directory.write('ABCDE12345\0', 112, 'latin1');

  const entitlements = Buffer.concat([Buffer.alloc(8), Buffer.from(entitlementsXml)]);
  entitlements.writeUInt32BE(0xfade7171, 0);
  entitlements.writeUInt32BE(entitlements.length, 4);
  const cms = Buffer.alloc(8 + 40);
  cms.writeUInt32BE(0xfade0b01, 0);
  cms.writeUInt32BE(cms.length, 4);

  const blobs = [[0, directory], [5, entitlements], [0x10000, cms]];
  const indexBytes = 12 + blobs.length * 8;
  const header = Buffer.alloc(indexBytes);
  header.writeUInt32BE(0xfade0cc0, 0);
  header.writeUInt32BE(blobs.length, 8);
  let at = indexBytes;
  for (const [i, [slot, blob]] of blobs.entries()) {
    header.writeUInt32BE(slot, 12 + i * 8);
    header.writeUInt32BE(at, 12 + i * 8 + 4);
    at += blob.length;
  }
  header.writeUInt32BE(at, 4);
  const superBlob = Buffer.concat([header, ...blobs.map(([, blob]) => blob)]);

  const parsed = inspectSignatureBlob(superBlob);
  assert.equal(parsed.identifier, 'com.example.app');
  assert.equal(parsed.teamId, 'ABCDE12345');
  assert.equal(parsed.hardenedRuntime, true);
  assert.equal(parsed.adHoc, false);
  assert.equal(parsed.signedBy, 'cms-present-unverified');
  assert.equal(parsed.cmsBytes, 40);
  assert.equal(parsed.hashType, 'sha256');
  assert.equal(parsed.pageSize, 4096);
  assert.deepEqual(parsed.flagNames, ['hardenedRuntime']);
  assert.deepEqual(parsed.executableSegmentFlags, ['mainBinary']);
  assert.equal(parsed.entitlements['com.apple.security.app-sandbox'], true);
  // The cdhash seals the CodeDirectory alone, not the SuperBlob around it.
  assert.equal(parsed.cdHash, createHash('sha256').update(directory).digest('hex').slice(0, 40));

  // A blob index pointing outside the SuperBlob must fail closed.
  const truncated = Buffer.from(superBlob);
  truncated.writeUInt32BE(superBlob.length + 8, 12 + 4);
  assert.throws(() => inspectSignatureBlob(truncated), /out of range/);
});

// A thin 64-bit Mach-O carrying one segment whose sections point at a region
// further down the file. This is the shape `machOSections` has to walk.
function sectioned(sections, regionAt) {
  const header = 32, cmdHeader = 72, entry = 80;
  const cmdSize = cmdHeader + sections.length * entry;
  const file = Buffer.alloc(regionAt + 512);
  file.writeUInt32LE(0xfeedfacf, 0);
  file.writeUInt32LE(0x0100000c, 4);
  file.writeUInt32LE(2, 12);
  file.writeUInt32LE(1, 16);
  file.writeUInt32LE(cmdSize, 20);
  file.writeUInt32LE(0x19, header);
  file.writeUInt32LE(cmdSize, header + 4);
  file.write('__TEXT', header + 8);
  file.writeUInt32LE(sections.length, header + 64);
  let at = regionAt;
  for (const [i, [name, body]] of sections.entries()) {
    const base = header + cmdHeader + i * entry;
    file.write(name, base);
    file.write('__TEXT', base + 16);
    file.writeBigUInt64LE(BigInt(body.length), base + 40);
    file.writeUInt32LE(at, base + 48);
    body.copy(file, at);
    at += body.length;
  }
  return file;
}

test('section walk reads only the named text sections', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-sections-')));
  try {
    const cstring = Buffer.from(
      'https://api.example.com/v1/ping\0/api/health\0abc\0\x01\x02\x03\x04\x05\0plainstring\0',
      'binary');
    const classes = Buffer.from('MyClass\0OtherClass\0');
    const file = sectioned([['__cstring', cstring], ['__objc_classname', classes]], 4096);
    const target = join(root, 'sectioned');
    await writeFile(target, file);

    assert.deepEqual([...machOSections(file)].map(s => [s.segment, s.section, s.bytes]), [
      ['__TEXT', '__cstring', cstring.length],
      ['__TEXT', '__objc_classname', classes.length],
    ]);

    const found = await inspectStrings(target, [root]);
    assert.deepEqual(found.urls, ['https://api.example.com/v1/ping']);
    assert.deepEqual(found.hosts, ['api.example.com']);
    // An API route is kept; a bare absolute path would not be.
    assert.deepEqual(found.endpoints, ['/api/health']);
    assert.deepEqual(found.objcClasses, ['MyClass', 'OtherClass']);
    // 'abc' is under the minimum length and the control bytes are not text.
    assert.equal(found.counts.strings, 5);

    // A segment claiming more sections than it holds must fail closed.
    const liar = Buffer.from(file);
    liar.writeUInt32LE(99, 32 + 64);
    assert.throws(() => [...machOSections(liar)], /more sections/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('asar archives are read in place, unpacked entries are not', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-asar-')));
  try {
    const manifest = Buffer.from(JSON.stringify({
      name: 'sample', version: '1.2.3', main: 'dist/main.js',
      dependencies: { zod: '^3', '@scope/thing': '^1' }, devDependencies: { tsc: '^5' },
    }));
    const main = Buffer.from('fetch("https://api.example.com/v1/ping"); connect("wss://live.example.net/s")');
    const files = {
      'package.json': { size: manifest.length, offset: '0' },
      dist: { files: {
        'main.js': { size: main.length, offset: String(manifest.length) },
        'big.bin': { size: 9, unpacked: true },
      } },
    };
    const json = Buffer.from(JSON.stringify({ files }));
    const padded = json.length + ((4 - json.length % 4) % 4);
    const head = Buffer.alloc(16);
    head.writeUInt32LE(4, 0);
    head.writeUInt32LE(8 + padded, 4);
    head.writeUInt32LE(4 + json.length, 8);
    head.writeUInt32LE(json.length, 12);
    const archive = Buffer.concat([head, json, Buffer.alloc(padded - json.length), manifest, main]);
    const target = join(root, 'app.asar');
    await writeFile(target, archive);

    const found = await inspectElectronApp(target, [root]);
    assert.equal(found.app.name, 'sample');
    assert.equal(found.app.version, '1.2.3');
    assert.deepEqual(found.app.dependencies, ['@scope/thing', 'zod']);
    assert.equal(found.contents.files, 3);
    assert.equal(found.contents.unpacked, 1, 'an unpacked entry is listed');
    assert.deepEqual(found.hosts, ['api.example.com', 'live.example.net']);
    // package.json and main.js are scripts; the unpacked binary is not read.
    assert.equal(found.scan.files, 2);

    const wrong = join(root, 'not.asar');
    await writeFile(wrong, Buffer.alloc(32));
    await assert.rejects(() => inspectElectronApp(wrong, [root]), /Not an asar/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('service descriptors in bundled script recover the schema', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-rpc-')));
  try {
    // The shape a protobuf-es build leaves behind: each message class binds its
    // own compact descriptor plus the classes its message-typed fields use.
    const bundle = Buffer.from([
      'var aa=class e extends M{static $(){return["Ping|1 note 9|2 tags 9*"]}};',
      'var bb=class e extends M{static $(){return["Pong|1 ok 8|3 ping #0|4 count 5?",aa]}},',
      'cc={typeName:"demo.v1.Demo",methods:{ping:{name:"Ping",I:aa,O:bb,kind:i.Unary},',
      'watch:{name:"Watch",I:aa,O:bb,kind:i.ServerStreaming}}};',
    ].join(''));
    const manifest = Buffer.from(JSON.stringify({ name: 'demo', version: '1' }));
    const files = { 'package.json': { size: manifest.length, offset: '0' },
      'app.js': { size: bundle.length, offset: String(manifest.length) } };
    const json = Buffer.from(JSON.stringify({ files }));
    const padded = json.length + ((4 - json.length % 4) % 4);
    const head = Buffer.alloc(16);
    head.writeUInt32LE(4, 0);
    head.writeUInt32LE(8 + padded, 4);
    head.writeUInt32LE(4 + json.length, 8);
    head.writeUInt32LE(json.length, 12);
    const target = join(root, 'app.asar');
    await writeFile(target, Buffer.concat([head, json, Buffer.alloc(padded - json.length), manifest, bundle]));

    const found = await inspectElectronRpc(target, [root]);
    assert.equal(found.counts.services, 1);
    assert.deepEqual(found.services[0].calls, [
      { method: 'Ping', kind: 'Unary', input: 'Ping', output: 'Pong' },
      { method: 'Watch', kind: 'ServerStreaming', input: 'Ping', output: 'Pong' },
    ]);
    // A '#0' field resolves through the class's own dependency list, and the
    // repeated and optional suffixes are not part of the type code.
    assert.deepEqual(found.schema, [
      { name: 'Ping', fields: [
        { number: 1, name: 'note', type: 'string', repeated: false, optional: false },
        { number: 2, name: 'tags', type: 'string', repeated: true, optional: false },
      ] },
      { name: 'Pong', fields: [
        { number: 1, name: 'ok', type: 'bool', repeated: false, optional: false },
        { number: 3, name: 'ping', type: 'Ping', repeated: false, optional: false },
        { number: 4, name: 'count', type: 'int32', repeated: false, optional: true },
      ] },
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// A zip written by hand, so the reader is checked against the format rather
// than against whatever a zip library happens to emit.
function zipArchive(files) {
  const bodies = [];
  const directory = [];
  let offset = 0;
  for (const file of files) {
    const name = Buffer.from(file.name);
    const deflated = deflateRawSync(file.data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(deflated.length, 18);
    local.writeUInt32LE(file.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(deflated.length, 20);
    central.writeUInt32LE(file.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    bodies.push(local, name, deflated);
    directory.push(central, name);
    offset += 30 + name.length + deflated.length;
  }
  const dir = Buffer.concat(directory);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...bodies, dir, end]);
}

test('an iOS archive is read in place and an encrypted executable is not scanned', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-ipa-')));
  try {
    const executable = Buffer.alloc(56);
    executable.writeUInt32LE(0xfeedfacf, 0);
    executable.writeUInt32LE(0x0100000c, 4);
    executable.writeUInt32LE(2, 12);
    executable.writeUInt32LE(1, 16);
    executable.writeUInt32LE(24, 20);
    executable.writeUInt32LE(0x2c, 32);
    executable.writeUInt32LE(24, 36);
    executable.writeUInt32LE(16384, 40);
    executable.writeUInt32LE(4096, 44);
    executable.writeUInt32LE(1, 48);
    const info = Buffer.from(`<?xml version="1.0"?><plist version="1.0"><dict>
      <key>CFBundleIdentifier</key><string>com.example.test</string>
      <key>CFBundleExecutable</key><string>Test</string>
      <key>CFBundleShortVersionString</key><string>1.2.3</string>
      <key>MinimumOSVersion</key><string>17.0</string>
      <key>NSCameraUsageDescription</key><string>test only</string>
    </dict></plist>`);
    const path = join(root, 'Test.ipa');
    await writeFile(path, zipArchive([
      { name: 'Payload/Test.app/Info.plist', data: info },
      { name: 'Payload/Test.app/Test', data: executable },
      { name: 'Payload/Test.app/PlugIns/Share.appex/Info.plist', data: info },
      { name: 'Payload/Test.app/_CodeSignature/CodeResources', data: Buffer.from('seal') },
    ]));

    const report = await inspectIosApp(path, [root]);
    assert.equal(report.members, 4);
    assert.equal(report.app.identifier, 'com.example.test');
    assert.equal(report.app.shortVersion, '1.2.3');
    assert.deepEqual(report.privacyUsage, ['NSCameraUsageDescription']);
    assert.deepEqual(report.structure.appExtensions, ['Share.appex']);
    assert.equal(report.signing.resourceSeal, true);
    assert.equal(report.signing.provisioningProfile, false);
    assert.equal(report.binary.architecture, 'arm64');
    // Encrypted __TEXT is ciphertext: the scan must be declined, not attempted.
    assert.equal(report.fairplay.encrypted, true);
    assert.equal(report.strings, null);
    assert.match(report.unread, /FairPlay/);

    // An archive that is not an application fails closed rather than guessing.
    const stray = join(root, 'Other.ipa');
    await writeFile(stray, zipArchive([{ name: 'notes.txt', data: Buffer.from('test only') }]));
    await assert.rejects(() => inspectIosApp(stray, [root]), /Payload/);
    await assert.rejects(() => inspectIosApp(path, ['/tmp/rp-not-a-root']), /outside|ENOENT/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
