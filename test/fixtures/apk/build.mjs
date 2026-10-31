// Builds our own Android fixtures | Chibitek Engineering | 2026-10-24
// Run offline: sandbox-exec -p '(version 1)(allow default)(deny network*)' node build.mjs
// Writes chibitek-fixture.apk (v1 by jarsigner, v2 and v3 by this script), its .idsig (v4) and
// chibitek-fixture.aab. The signing key is generated per build in a temp directory and deleted;
// it is never checked in. Every byte here is our own: binary XML, DEX and protobuf are written by hand.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const elf = join(here, '..', 'elf');
const JDK = '/opt/homebrew/opt/openjdk@25/bin';
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const lp = (...parts) => { const body = Buffer.concat(parts); return Buffer.concat([u32(body.length), body]); };
const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();

// ---- The app, described once ----

const PKG = 'com.chibitek.fixture';
const A = 'http://schemas.android.com/apk/res/android';
// [tag, attrs, children]; attrs are [name, value, android namespace?]. Numbers are ints, booleans booleans.
const el = (tag, attrs, ...children) => ({ tag, attrs, children });
const an = (name, value) => [name, value, true];
const named = (tag, name) => el(tag, [an('name', name)]);
const MANIFEST = el('manifest', [['package', PKG], an('versionCode', 7), an('versionName', '1.0.7')],
  el('uses-sdk', [an('minSdkVersion', 24), an('targetSdkVersion', 34)]),
  named('uses-permission', 'android.permission.INTERNET'),
  named('uses-permission', 'android.permission.RECEIVE_BOOT_COMPLETED'),
  el('permission', [an('name', `${PKG}.permission.SYNC`), an('protectionLevel', 2)]),
  named('uses-feature', 'android.hardware.camera'),
  el('application', [an('allowBackup', false)],
    el('activity', [an('name', `${PKG}.MainActivity`), an('exported', true)],
      el('intent-filter', [], named('action', 'android.intent.action.MAIN'), named('category', 'android.intent.category.LAUNCHER')),
      el('intent-filter', [], named('action', 'android.intent.action.VIEW'), named('category', 'android.intent.category.DEFAULT'),
        named('category', 'android.intent.category.BROWSABLE'), el('data', [an('scheme', 'https'), an('host', 'fixture.chibitek.com')]))),
    el('service', [an('name', `${PKG}.SyncService`), an('exported', false), an('permission', `${PKG}.permission.SYNC`)]),
    el('receiver', [an('name', `${PKG}.BootReceiver`), an('exported', true)],
      el('intent-filter', [], named('action', 'android.intent.action.BOOT_COMPLETED'))),
    el('provider', [an('name', `${PKG}.FixtureProvider`), an('authorities', `${PKG}.files`), an('exported', false),
      an('grantUriPermissions', true)])));
// Framework attribute IDs (android.R.attr), the same ones the reader knows.
const ATTR_IDS = { name: 0x01010003, permission: 0x01010006, protectionLevel: 0x01010009, exported: 0x01010010,
  authorities: 0x01010018, grantUriPermissions: 0x0101001b, scheme: 0x01010027, host: 0x01010028, minSdkVersion: 0x0101020c,
  versionCode: 0x0101021b, versionName: 0x0101021c, targetSdkVersion: 0x01010270, allowBackup: 0x01010280 };

// ---- Binary XML (APK manifest) ----

function binaryXml(root) {
  const walk = (n, f) => { f(n); n.children.forEach(c => walk(c, f)); };
  // Attribute names with a resource ID come first, in resource-map order; then everything else.
  const attrNames = Object.keys(ATTR_IDS);
  const strings = [...attrNames];
  const idx = s => { let i = strings.indexOf(s); if (i < 0) i = strings.push(s) - 1; return i; };
  idx('android'); idx(A);
  walk(root, n => { idx(n.tag); n.attrs.forEach(([k, v]) => { idx(k); if (typeof v === 'string') idx(v); }); });
  const pool = (() => {
    const offsets = [], data = [];
    let at = 0;
    for (const s of strings) {
      const b = Buffer.from(s, 'utf8');
      if (b.length > 0x7f) throw new Error('fixture strings stay short');
      offsets.push(u32(at));
      const item = Buffer.concat([Buffer.from([s.length, b.length]), b, Buffer.from([0])]);
      data.push(item); at += item.length;
    }
    let body = Buffer.concat(data);
    body = Buffer.concat([body, Buffer.alloc((4 - body.length % 4) % 4)]);
    const start = 28 + offsets.length * 4;
    return Buffer.concat([u16(1), u16(28), u32(start + body.length), u32(strings.length), u32(0), u32(0x100), u32(start), u32(0), ...offsets, body]);
  })();
  const resMap = Buffer.concat([u16(0x180), u16(8), u32(8 + attrNames.length * 4), ...attrNames.map(k => u32(ATTR_IDS[k]))]);
  const NONE = 0xffffffff, ns = idx(A);
  const chunks = [Buffer.concat([u16(0x100), u16(16), u32(24), u32(1), u32(NONE), u32(idx('android')), u32(ns)])];
  let line = 1;
  const emit = n => {
    const attrs = n.attrs.map(([k, v, android]) => {
      const [type, data, raw] = typeof v === 'string' ? [0x03, idx(v), idx(v)] : typeof v === 'boolean' ? [0x12, v ? NONE : 0, NONE] : [0x10, v, NONE];
      return Buffer.concat([u32(android ? ns : NONE), u32(idx(k)), u32(raw), u16(8), Buffer.from([0, type]), u32(data)]);
    });
    chunks.push(Buffer.concat([u16(0x102), u16(16), u32(36 + attrs.length * 20), u32(line++), u32(NONE),
      u32(NONE), u32(idx(n.tag)), u16(20), u16(20), u16(attrs.length), u16(0), u16(0), u16(0), ...attrs]));
    n.children.forEach(emit);
    chunks.push(Buffer.concat([u16(0x103), u16(16), u32(24), u32(line++), u32(NONE), u32(NONE), u32(idx(n.tag))]));
  };
  emit(root);
  chunks.push(Buffer.concat([u16(0x101), u16(16), u32(24), u32(line), u32(NONE), u32(idx('android')), u32(ns)]));
  const body = Buffer.concat([pool, resMap, ...chunks]);
  return Buffer.concat([u16(3), u16(8), u32(8 + body.length), body]);
}

// ---- Protobuf XML (AAB manifest, aapt2 Resources.proto XmlNode) ----

const varint = n => { const out = []; do { let b = n % 128; n = Math.floor(n / 128); if (n) b |= 0x80; out.push(b); } while (n); return Buffer.from(out); };
const field = (f, v) => typeof v === 'number' ? Buffer.concat([varint(f * 8), varint(v)])
  : Buffer.concat([varint(f * 8 + 2), varint(Buffer.byteLength(v)), Buffer.from(v)]);
function protoXml(n) {
  const attrs = n.attrs.map(([k, v, android]) => {
    // Item.prim (7): int_decimal_value 6, boolean_value 8. Strings keep their value (3) only.
    const item = typeof v === 'string' ? null : field(7, typeof v === 'boolean' ? field(8, v ? 1 : 0) : field(6, v));
    return field(4, Buffer.concat([...(android ? [field(1, A)] : []), field(2, k), field(3, typeof v === 'string' ? v : String(v)),
      ...(android && ATTR_IDS[k] ? [field(5, ATTR_IDS[k])] : []), ...(item ? [field(6, item)] : [])]));
  });
  const element = Buffer.concat([field(3, n.tag), ...attrs, ...n.children.map(c => field(5, protoXml(c)))]);
  return field(1, element);
}

// ---- DEX ----

const uleb = n => varint(n);
const NO_INDEX = 0xffffffff;
const CLASSES = [
  { name: `L${PKG.replaceAll('.', '/')}/MainActivity;`, super: 'Landroid/app/Activity;', access: 0x1,
    direct: [{ name: '<init>', ret: 'V', params: [], access: 0x10001, init: true }],
    virtual: [{ name: 'onCreate', ret: 'V', params: ['Landroid/os/Bundle;'], access: 0x4, url: 'https://api.chibitek.com/fixture/v1' }] },
  { name: `L${PKG.replaceAll('.', '/')}/BootReceiver;`, super: 'Landroid/content/BroadcastReceiver;', access: 0x11,
    direct: [{ name: '<init>', ret: 'V', params: [], access: 0x10001, init: true }],
    virtual: [{ name: 'onReceive', ret: 'V', params: ['Landroid/content/Context;', 'Landroid/content/Intent;'], access: 0x1 }] },
];

function dex() {
  const shorty = (ret, params) => [ret, ...params].map(t => t[0] === 'L' || t[0] === '[' ? 'L' : t).join('');
  const methods = CLASSES.flatMap(c => [...c.direct, ...c.virtual].map(m => ({ ...m, cls: c.name })));
  // Each <init> calls its superclass constructor, so those method references exist too.
  const refs = [...methods, ...CLASSES.map(c => ({ cls: c.super, name: '<init>', ret: 'V', params: [] }))];
  const cmp = (a, b) => a < b ? -1 : a > b ? 1 : 0;
  const cmpList = (a, b) => { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; };
  const strings = [...new Set([...CLASSES.flatMap(c => [c.name, c.super]), ...refs.flatMap(m => [m.name, m.ret, ...m.params, shorty(m.ret, m.params)]),
    ...methods.filter(m => m.url).map(m => m.url)])].sort(cmp);
  const sIdx = s => strings.indexOf(s);
  const types = [...new Set([...CLASSES.flatMap(c => [c.name, c.super]), ...refs.flatMap(m => [m.ret, ...m.params])])].sort((a, b) => sIdx(a) - sIdx(b));
  const tIdx = t => types.indexOf(t);
  const protoKey = m => JSON.stringify([m.ret, m.params]);
  const protos = [...new Map(refs.map(m => [protoKey(m), m])).values()]
    .sort((a, b) => tIdx(a.ret) - tIdx(b.ret) || cmpList(a.params.map(tIdx), b.params.map(tIdx)));
  const pIdx = m => protos.findIndex(p => protoKey(p) === protoKey(m));
  const mKey = m => `${m.cls}|${m.name}|${protoKey(m)}`;
  const mrefs = [...new Map(refs.map(m => [mKey(m), m])).values()].sort((a, b) => tIdx(a.cls) - tIdx(b.cls) || sIdx(a.name) - sIdx(b.name) || pIdx(a) - pIdx(b));
  const mIdx = m => mrefs.findIndex(r => mKey(r) === mKey(m));

  const header = 0x70;
  const at = { strings: header };
  at.types = at.strings + strings.length * 4;
  at.protos = at.types + types.length * 4;
  at.methods = at.protos + protos.length * 12;
  at.classes = at.methods + mrefs.length * 8;
  at.data = at.classes + CLASSES.length * 32;
  const data = [];
  let cursor = at.data;
  const put = (buf, align = 1) => { const pad = (align - cursor % align) % align; if (pad) { data.push(Buffer.alloc(pad)); cursor += pad; } const off = cursor; data.push(buf); cursor += buf.length; return off; };

  // code_item: registers, ins, outs, tries, debug_info_off, insns_size, insns.
  const codeAt = new Map();
  for (const m of methods) {
    const ins = m.params.length + 1;
    let insns, regs = ins, outs = 0;
    if (m.init) { insns = [0x1070, mIdx({ cls: CLASSES.find(c => c.name === m.cls).super, name: '<init>', ret: 'V', params: [] }), 0x0000, 0x000e]; outs = 1; }
    else if (m.url) { regs = ins + 1; insns = [0x001a, sIdx(m.url), 0x000e]; } // const-string v0, url; return-void
    else insns = [0x000e];
    codeAt.set(mKey(m), put(Buffer.concat([u16(regs), u16(ins), u16(outs), u16(0), u32(0), u32(insns.length), ...insns.map(u16)]), 4));
  }
  const codeItems = [codeAt.get(mKey(methods[0])), methods.length];
  const listAt = new Map();
  for (const p of protos.filter(p => p.params.length)) {
    const key = p.params.join(',');
    if (!listAt.has(key)) listAt.set(key, put(Buffer.concat([u32(p.params.length), ...p.params.map(t => u16(tIdx(t)))]), 4));
  }
  const typeLists = [[...listAt.values()][0], listAt.size];
  const stringAt = strings.map(s => put(Buffer.concat([uleb(s.length), Buffer.from(s, 'utf8'), Buffer.from([0])])));
  const classAt = CLASSES.map(c => {
    const enc = list => { let prev = 0; return list.map(m => { const i = mIdx({ ...m, cls: c.name }); const b = Buffer.concat([uleb(i - prev), uleb(m.access), uleb(codeAt.get(mKey({ ...m, cls: c.name })))]); prev = i; return b; }); };
    const sorted = list => [...list].sort((a, b) => mIdx({ ...a, cls: c.name }) - mIdx({ ...b, cls: c.name }));
    return put(Buffer.concat([uleb(0), uleb(0), uleb(c.direct.length), uleb(c.virtual.length), ...enc(sorted(c.direct)), ...enc(sorted(c.virtual))]));
  });
  const map = [[0x0000, 1, 0], [0x0001, strings.length, at.strings], [0x0002, types.length, at.types], [0x0003, protos.length, at.protos],
    [0x0005, mrefs.length, at.methods], [0x0006, CLASSES.length, at.classes], [0x2001, codeItems[1], codeItems[0]],
    [0x1001, typeLists[1], typeLists[0]], [0x2002, strings.length, stringAt[0]], [0x2000, CLASSES.length, classAt[0]]];
  const pad = (4 - cursor % 4) % 4;
  const mapAt = cursor + pad;
  map.push([0x1000, 1, mapAt]);
  map.sort((a, b) => a[2] - b[2]);
  put(Buffer.concat([u32(map.length), ...map.map(([type, size, off]) => Buffer.concat([u16(type), u16(0), u32(size), u32(off)]))]), 4);

  const ids = Buffer.concat([
    ...stringAt.map(u32), ...types.map(t => u32(sIdx(t))),
    ...protos.map(p => Buffer.concat([u32(sIdx(shorty(p.ret, p.params))), u32(tIdx(p.ret)), u32(p.params.length ? listAt.get(p.params.join(',')) : 0)])),
    ...mrefs.map(m => Buffer.concat([u16(tIdx(m.cls)), u16(pIdx(m)), u32(sIdx(m.name))])),
    ...CLASSES.map((c, i) => Buffer.concat([u32(tIdx(c.name)), u32(c.access), u32(tIdx(c.super)), u32(0), u32(NO_INDEX), u32(0), u32(classAt[i]), u32(0)])),
  ]);
  const body = Buffer.concat([ids, ...data]);
  const size = header + body.length;
  const head = Buffer.concat([Buffer.from('dex\n035\0', 'latin1'), u32(0), Buffer.alloc(20), u32(size), u32(header), u32(0x12345678),
    u32(0), u32(0), u32(mapAt), u32(strings.length), u32(at.strings), u32(types.length), u32(at.types), u32(protos.length), u32(at.protos),
    u32(0), u32(0), u32(mrefs.length), u32(at.methods), u32(CLASSES.length), u32(at.classes), u32(size - at.data), u32(at.data)]);
  const file = Buffer.concat([head, body]);
  createHash('sha1').update(file.subarray(32)).digest().copy(file, 12);
  let a = 1, b = 0;
  for (const byte of file.subarray(12)) { a = (a + byte) % 65521; b = (b + a) % 65521; }
  file.writeUInt32LE(((b << 16) | a) >>> 0, 8);
  return file;
}

// ---- APK Signing Block (v2, v3) and v4 ----

const RSA_PKCS1_SHA256 = 0x0103;
/** v2/v3 content digest: 1 MiB chunks of entries, central directory and EOCD, each hashed, then hashed together. */
function contentDigest(sections) {
  const chunks = sections.flatMap(s => Array.from({ length: Math.ceil(s.length / 1048576) }, (_, i) => s.subarray(i * 1048576, (i + 1) * 1048576)));
  return sha256(Buffer.from([0x5a]), u32(chunks.length), ...chunks.map(c => sha256(Buffer.from([0xa5]), u32(c.length), c)));
}
function schemeBlock(v3, digest, certDer, spki, key) {
  const digests = lp(lp(u32(RSA_PKCS1_SHA256), lp(digest)));
  const signed = Buffer.concat([digests, lp(lp(certDer)), ...(v3 ? [u32(24), u32(0x7fffffff)] : []), lp()]);
  const signature = sign('sha256', signed, key);
  const signer = Buffer.concat([lp(signed), ...(v3 ? [u32(24), u32(0x7fffffff)] : []), lp(lp(u32(RSA_PKCS1_SHA256), lp(signature))), lp(spki)]);
  return lp(lp(signer));
}
/** fs-verity style Merkle tree over 4 KiB blocks, no salt: returns [root hash, tree with the top level first]. */
function merkle(file) {
  const levels = [];
  let data = file;
  for (;;) {
    const blocks = Math.max(1, Math.ceil(data.length / 4096));
    const level = Buffer.concat(Array.from({ length: blocks }, (_, i) => { const b = Buffer.alloc(4096); data.copy(b, 0, i * 4096, (i + 1) * 4096); return sha256(b); }));
    const padded = Buffer.concat([level, Buffer.alloc((4096 - level.length % 4096) % 4096)]);
    levels.unshift(padded);
    if (padded.length === 4096) return [sha256(padded), Buffer.concat(levels)];
    data = padded;
  }
}

// ---- Build ----

const work = mkdtempSync(join(tmpdir(), 'rp-apk-'));
try {
  const stage = join(work, 'apk');
  const write = (rel, bytes) => { const p = join(stage, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, bytes); utimesSync(p, 1792800000, 1792800000); };
  const classes = dex();
  write('AndroidManifest.xml', binaryXml(MANIFEST));
  write('classes.dex', classes);
  write('assets/fixture.txt', 'Chibitek ReversePlumbing Android fixture\n');
  write('lib/arm64-v8a/libchibi.so', readFileSync(join(elf, 'libchibi-aarch64.so')));
  write('lib/armeabi-v7a/libchibi.so', readFileSync(join(elf, 'libchibi-armhf.so')));
  const apk = join(work, 'unsigned.apk');
  // Native libraries stay stored (uncompressed), as extractNativeLibs=false expects; everything else is deflated.
  execFileSync('/usr/bin/zip', ['-X', '-q', '-D', apk, 'AndroidManifest.xml', 'classes.dex', 'assets/fixture.txt'], { cwd: stage });
  execFileSync('/usr/bin/zip', ['-X', '-q', '-D', '-0', apk, 'lib/arm64-v8a/libchibi.so', 'lib/armeabi-v7a/libchibi.so'], { cwd: stage });

  const ks = join(work, 'ks.p12'), pass = 'fixture-build-only';
  execFileSync(join(JDK, 'keytool'), ['-genkeypair', '-keystore', ks, '-storetype', 'PKCS12', '-alias', 'chibi', '-keyalg', 'RSA', '-keysize', '2048',
    '-dname', 'CN=Chibitek ReversePlumbing Fixture, O=Chibitek, C=US', '-validity', '3650', '-storepass', pass, '-keypass', pass], { stdio: 'ignore' });
  execFileSync(join(JDK, 'jarsigner'), ['-keystore', ks, '-storepass', pass, '-digestalg', 'SHA-256', '-sigalg', 'SHA256withRSA', apk, 'chibi'], { stdio: 'ignore' });
  const certDer = execFileSync(join(JDK, 'keytool'), ['-exportcert', '-keystore', ks, '-storepass', pass, '-alias', 'chibi']);
  const key = createPrivateKey(execFileSync('/usr/bin/openssl', ['pkcs12', '-in', ks, '-nocerts', '-nodes', '-passin', `pass:${pass}`]));
  const spki = createPublicKey(key).export({ type: 'spki', format: 'der' });

  const signed = readFileSync(apk);
  const eocd = signed.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const cdAt = signed.readUInt32LE(eocd + 16);
  const digest = contentDigest([signed.subarray(0, cdAt), signed.subarray(cdAt, eocd), signed.subarray(eocd)]);
  const pairs = [[0x7109871a, schemeBlock(false, digest, certDer, spki, key)], [0xf05368c0, schemeBlock(true, digest, certDer, spki, key)]]
    .map(([id, value]) => Buffer.concat([u64(4 + value.length), u32(id), value]));
  const inner = Buffer.concat(pairs);
  const blockSize = inner.length + 8 + 16;
  const block = Buffer.concat([u64(blockSize), inner, u64(blockSize), Buffer.from('APK Sig Block 42', 'latin1')]);
  const tail = Buffer.from(signed.subarray(eocd));
  tail.writeUInt32LE(cdAt + block.length, 16);
  const final = Buffer.concat([signed.subarray(0, cdAt), block, signed.subarray(cdAt, eocd), tail]);
  writeFileSync(join(here, 'chibitek-fixture.apk'), final);

  // v4: hashing info and signing info, signed over the file size, both infos' fields, as apksigner lays them out.
  const [rootHash, tree] = merkle(final);
  const salt = Buffer.alloc(0), extra = Buffer.alloc(0);
  const v4signed = Buffer.concat([u64(final.length), u32(1), Buffer.from([12]), lp(salt), lp(rootHash), lp(digest), lp(certDer), lp(extra)]);
  const v4data = Buffer.concat([u32(v4signed.length + 4), v4signed]);
  const hashing = lp(u32(1), Buffer.from([12]), lp(salt), lp(rootHash));
  const signing = lp(lp(digest), lp(certDer), lp(extra), lp(spki), u32(RSA_PKCS1_SHA256), lp(sign('sha256', v4data, key)));
  writeFileSync(join(here, 'chibitek-fixture.apk.idsig'), Buffer.concat([u32(2), hashing, signing, lp(tree)]));

  // A one-module bundle: protobuf manifest, the same DEX and one ABI. Bundles are uploaded unsigned by v2/v3.
  const bundle = join(work, 'aab');
  const put = (rel, bytes) => { const p = join(bundle, rel); mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, bytes); utimesSync(p, 1792800000, 1792800000); };
  put('BundleConfig.pb', field(1, field(2, '1.17.2')));
  put('base/manifest/AndroidManifest.xml', protoXml(MANIFEST));
  put('base/dex/classes.dex', classes);
  put('base/lib/arm64-v8a/libchibi.so', readFileSync(join(elf, 'libchibi-aarch64.so')));
  const aab = join(work, 'fixture.aab');
  execFileSync('/usr/bin/zip', ['-X', '-q', '-D', '-r', aab, 'BundleConfig.pb', 'base'], { cwd: bundle });
  copyFileSync(aab, join(here, 'chibitek-fixture.aab'));
  console.log(`apk ${final.length} bytes, idsig, aab written to ${here}`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
