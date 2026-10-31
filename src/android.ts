// Android package reader for .apk and .aab. Walks the zip in place and reads the manifest (binary
// XML in an APK, aapt2 protobuf in a bundle), every signing scheme present (v1 JAR, v2, v3 and v3.1
// from the APK Signing Block, v4 from a sibling .idsig), a structural inventory of each DEX file and
// the native libraries under lib/<abi>/, which go through the same ELF parser as inspect_linux_elf.
// Signatures are parsed, not verified; DEX is inventoried, not decompiled; nothing is installed or run.
import { createHash, X509Certificate } from 'node:crypto';
import { certInfo, children, der, signedData } from './authenticode.js';
import { readElf } from './elf.js';
import { artifactSize, readRegion } from './inspect.js';
import { MAX_MEMBER_BYTES, readCentralDirectory, readMember, type ZipEntry } from './ipa.js';
import { digestRanges, regionReader } from './pe.js';

const MAX_SIGNING_BLOCK = 16 * 1024 * 1024;
const MAX_NODES = 200_000;
const MAX_IDSIG_HEADER = 1024 * 1024;
const SIG_BLOCK_MAGIC = 'APK Sig Block 42';
const BLOCKS: Record<number, string> = { 0x7109871a: 'v2', 0xf05368c0: 'v3', 0x1b93ad61: 'v3.1', 0x42726577: 'padding',
  0x6dff800d: 'source-stamp-v2', 0x2b09189e: 'source-stamp-v1', 0x504b4453: 'dependency-info', 0x2146444e: 'play-metadata', 0x71777777: 'walle-channel' };
const SIGNATURE_ALGORITHMS: Record<number, string> = { 0x0101: 'RSASSA-PSS with SHA2-256', 0x0102: 'RSASSA-PSS with SHA2-512',
  0x0103: 'RSASSA-PKCS1-v1_5 with SHA2-256', 0x0104: 'RSASSA-PKCS1-v1_5 with SHA2-512', 0x0201: 'ECDSA with SHA2-256',
  0x0202: 'ECDSA with SHA2-512', 0x0301: 'DSA with SHA2-256', 0x0421: 'RSASSA-PKCS1-v1_5 with SHA2-256 (verity)',
  0x0423: 'ECDSA with SHA2-256 (verity)', 0x0425: 'DSA with SHA2-256 (verity)' };
// Framework attribute IDs, used when an obfuscator has blanked the attribute names in the string pool. Each was
// confirmed against the resource map of a real manifest; add others the same way.
const ATTRIBUTE_IDS: Record<number, string> = { 0x01010003: 'name', 0x01010006: 'permission', 0x01010009: 'protectionLevel',
  0x0101000e: 'enabled', 0x01010010: 'exported', 0x01010018: 'authorities', 0x0101001b: 'grantUriPermissions',
  0x01010027: 'scheme', 0x01010028: 'host', 0x0101002c: 'pathPattern', 0x0101020c: 'minSdkVersion', 0x0101021b: 'versionCode',
  0x0101021c: 'versionName', 0x01010270: 'targetSdkVersion', 0x01010280: 'allowBackup' };
const ACCESS = [[0x1, 'public'], [0x2, 'private'], [0x4, 'protected'], [0x8, 'static'], [0x10, 'final'], [0x200, 'interface'],
  [0x400, 'abstract'], [0x1000, 'synthetic'], [0x2000, 'annotation'], [0x4000, 'enum']] as const;
const COMPONENTS = ['activity', 'activity-alias', 'service', 'receiver', 'provider'];

type Value = string | number | boolean;
type XmlNode = { tag: string; attrs: Record<string, Value>; children: XmlNode[] };

/** Length-prefixed (uint32 LE) items, back to back, as the signing block nests everything. */
function prefixed(buf: Buffer) {
  const out: Buffer[] = [];
  for (let at = 0; at < buf.length;) {
    const n = buf.readUInt32LE(at);
    if (at + 4 + n > buf.length) throw new Error('Length-prefixed item runs past its parent.');
    out.push(buf.subarray(at + 4, at + 4 + n));
    at += 4 + n;
  }
  return out;
}
const lp = (buf: Buffer, at: number) => {
  const n = buf.readUInt32LE(at);
  if (at + 4 + n > buf.length) throw new Error('Length-prefixed item runs past its parent.');
  return buf.subarray(at + 4, at + 4 + n);
};

// ---- Manifest, binary XML (APK) ----

function stringPool(chunk: Buffer) {
  const count = chunk.readUInt32LE(8), utf8 = (chunk.readUInt32LE(16) & 0x100) !== 0, start = chunk.readUInt32LE(20);
  const offsets = chunk.subarray(chunk.readUInt16LE(2), chunk.readUInt16LE(2) + count * 4);
  if (offsets.length < count * 4) throw new Error('String pool offsets run past the chunk.');
  return Array.from({ length: count }, (_, i) => {
    let at = start + offsets.readUInt32LE(i * 4);
    if (utf8) {
      at += chunk[at] & 0x80 ? 2 : 1; // UTF-16 length, unused
      let n = chunk[at++];
      if (n & 0x80) n = ((n & 0x7f) << 8) | chunk[at++];
      return chunk.toString('utf8', at, at + n);
    }
    let n = chunk.readUInt16LE(at); at += 2;
    if (n & 0x8000) { n = ((n & 0x7fff) << 16) | chunk.readUInt16LE(at); at += 2; }
    return chunk.toString('utf16le', at, at + n * 2);
  });
}

export function parseBinaryXml(buf: Buffer): XmlNode {
  if (buf.readUInt16LE(0) !== 0x0003) throw new Error('Expected Android binary XML.');
  let strings: string[] = [], ids: number[] = [], nodes = 0;
  const root: XmlNode = { tag: '', attrs: {}, children: [] }, stack = [root];
  for (let at = buf.readUInt16LE(2); at + 8 <= buf.length;) {
    const type = buf.readUInt16LE(at), headerBytes = buf.readUInt16LE(at + 2), size = buf.readUInt32LE(at + 4);
    if (size < 8 || at + size > buf.length) throw new Error('Binary XML chunk runs past the file.');
    const chunk = buf.subarray(at, at + size);
    if (type === 0x0001) strings = stringPool(chunk);
    else if (type === 0x0180) ids = Array.from({ length: (size - headerBytes) / 4 | 0 }, (_, i) => chunk.readUInt32LE(headerBytes + i * 4));
    else if (type === 0x0102) {
      if (++nodes > MAX_NODES) throw new Error('Refusing a manifest with more elements than expected.');
      const ext = headerBytes, attrStart = chunk.readUInt16LE(ext + 8), attrSize = chunk.readUInt16LE(ext + 10);
      const node: XmlNode = { tag: strings[chunk.readUInt32LE(ext + 4)] ?? '', attrs: {}, children: [] };
      for (let i = 0; i < chunk.readUInt16LE(ext + 12); i++) {
        const a = ext + attrStart + i * attrSize, nameIndex = chunk.readUInt32LE(a + 4), raw = chunk.readUInt32LE(a + 8);
        const kind = chunk[a + 15], data = chunk.readUInt32LE(a + 16);
        const name = strings[nameIndex] || ATTRIBUTE_IDS[ids[nameIndex]] || `0x${(ids[nameIndex] ?? nameIndex).toString(16)}`;
        // Typed data wins, as on a device: some repackagers leave a stale raw string beside an integer.
        node.attrs[name] = kind === 0x03 ? strings[data] ?? '' : kind === 0x00 ? (raw !== 0xffffffff ? strings[raw] ?? '' : '')
          : kind === 0x12 ? data !== 0 : kind === 0x10 ? data | 0 : kind === 0x11 ? `0x${data.toString(16)}`
          : kind === 0x01 ? `@0x${data.toString(16).padStart(8, '0')}` : kind === 0x02 ? `?0x${data.toString(16).padStart(8, '0')}`
          : kind === 0x04 ? chunk.readFloatLE(a + 16) : data;
      }
      stack[stack.length - 1].children.push(node);
      stack.push(node);
    } else if (type === 0x0103 && stack.length > 1) stack.pop();
    at += size;
  }
  const manifest = root.children[0];
  if (!manifest) throw new Error('Binary XML has no root element.');
  return manifest;
}

// ---- Manifest, aapt2 protobuf (AAB) ----

/** Fields of one protobuf message: number -> raw values (varint as number, length-delimited as Buffer). */
function protoFields(buf: Buffer) {
  const out = new Map<number, (number | Buffer)[]>();
  const varint = () => {
    let value = 0, scale = 1;
    for (;;) {
      const b = buf[at++];
      if (b === undefined) throw new Error('Truncated protobuf varint.');
      value += (b & 0x7f) * scale; scale *= 128;
      if (!(b & 0x80)) return value;
      if (scale > 2 ** 63) throw new Error('Protobuf varint too long.');
    }
  };
  let at = 0;
  while (at < buf.length) {
    const key = varint(), field = Math.floor(key / 8), wire = key & 7;
    let value: number | Buffer;
    if (wire === 0) value = varint();
    else if (wire === 2) { const n = varint(); if (at + n > buf.length) throw new Error('Protobuf field runs past its message.'); value = buf.subarray(at, at += n); }
    else if (wire === 5) { value = buf.readUInt32LE(at); at += 4; }
    else if (wire === 1) { value = Number(buf.readBigUInt64LE(at)); at += 8; }
    else throw new Error('Unsupported protobuf wire type.');
    out.set(field, [...(out.get(field) ?? []), value]);
  }
  return out;
}
const pbString = (m: Map<number, (number | Buffer)[]>, f: number) => { const v = m.get(f)?.[0]; return Buffer.isBuffer(v) ? v.toString('utf8') : ''; };
const pbMessage = (m: Map<number, (number | Buffer)[]>, f: number) => { const v = m.get(f)?.[0]; return Buffer.isBuffer(v) ? protoFields(v) : null; };

/** aapt2 XmlNode: element 1 { name 3, attribute 4 { name 2, value 3, resource_id 5, compiled_item 6 }, child 5 }. */
export function parseProtoXml(buf: Buffer): XmlNode {
  let nodes = 0;
  const element = (m: Map<number, (number | Buffer)[]>): XmlNode => {
    if (++nodes > MAX_NODES) throw new Error('Refusing a manifest with more elements than expected.');
    const node: XmlNode = { tag: pbString(m, 3), attrs: {}, children: [] };
    for (const raw of m.get(4) ?? []) {
      const a = protoFields(raw as Buffer), id = a.get(5)?.[0] as number | undefined;
      const name = pbString(a, 2) || (id !== undefined && ATTRIBUTE_IDS[id]) || `0x${(id ?? 0).toString(16)}`;
      // Item { ref 1 { id 2, name 3 }, str 2 { value 1 }, prim 7 { int_decimal 6, int_hex 7, boolean 8 } }
      const item = pbMessage(a, 6), prim = item && pbMessage(item, 7), ref = item && pbMessage(item, 1);
      node.attrs[name] = prim?.has(8) ? prim.get(8)![0] === 1 : prim?.has(6) ? (prim.get(6)![0] as number) | 0
        : prim?.has(7) ? `0x${(prim.get(7)![0] as number).toString(16)}`
        : ref ? (pbString(ref, 3) ? `@${pbString(ref, 3)}` : `@0x${((ref.get(2)?.[0] as number) ?? 0).toString(16).padStart(8, '0')}`)
        : pbString(a, 3);
    }
    for (const child of m.get(5) ?? []) {
      const inner = pbMessage(protoFields(child as Buffer), 1);
      if (inner) node.children.push(element(inner));
    }
    return node;
  };
  const root = pbMessage(protoFields(buf), 1);
  if (!root) throw new Error('Protobuf manifest has no root element.');
  return element(root);
}

// ---- Manifest summary ----

const all = (node: XmlNode, tag: string) => node.children.filter(c => c.tag === tag);
const attr = (node: XmlNode | undefined, name: string) => node?.attrs[name] ?? null;
const names = (node: XmlNode, tag: string) => all(node, tag).map(c => attr(c, 'name'));

function summarizeManifest(m: XmlNode, limit: number) {
  if (m.tag !== 'manifest') throw new Error('Manifest root is not <manifest>.');
  const sdk = all(m, 'uses-sdk')[0], app = all(m, 'application')[0];
  const components = Object.fromEntries(COMPONENTS.map(tag => [tag, (app ? all(app, tag) : []).slice(0, limit).map(c => ({
    name: attr(c, 'name'), exported: attr(c, 'exported'), permission: attr(c, 'permission'), enabled: attr(c, 'enabled'),
    ...(tag === 'activity-alias' ? { targetActivity: attr(c, 'targetActivity') } : {}),
    ...(tag === 'provider' ? { authorities: attr(c, 'authorities'), grantUriPermissions: attr(c, 'grantUriPermissions') } : {}),
    intentFilters: all(c, 'intent-filter').map(f => ({ actions: names(f, 'action'), categories: names(f, 'category'),
      data: all(f, 'data').map(d => Object.fromEntries(['scheme', 'host', 'port', 'path', 'pathPrefix', 'pathPattern', 'mimeType']
        .filter(k => k in d.attrs).map(k => [k, d.attrs[k]]))) })),
  }))]));
  const counts = Object.fromEntries(COMPONENTS.map(tag => [tag, app ? all(app, tag).length : 0]));
  return {
    package: attr(m, 'package'), versionCode: attr(m, 'versionCode'), versionName: attr(m, 'versionName'),
    minSdk: attr(sdk, 'minSdkVersion'), targetSdk: attr(sdk, 'targetSdkVersion'), maxSdk: attr(sdk, 'maxSdkVersion'),
    compileSdk: attr(m, 'compileSdkVersion'),
    permissionsRequested: [...all(m, 'uses-permission'), ...all(m, 'uses-permission-sdk-23')]
      .map(p => ({ name: attr(p, 'name'), maxSdk: attr(p, 'maxSdkVersion') })),
    permissionsDeclared: all(m, 'permission').map(p => ({ name: attr(p, 'name'), protectionLevel: attr(p, 'protectionLevel') })),
    features: all(m, 'uses-feature').map(f => ({ name: attr(f, 'name'), required: attr(f, 'required') })),
    application: app ? { name: attr(app, 'name'), debuggable: attr(app, 'debuggable'), allowBackup: attr(app, 'allowBackup'),
      usesCleartextTraffic: attr(app, 'usesCleartextTraffic'), networkSecurityConfig: attr(app, 'networkSecurityConfig'),
      extractNativeLibs: attr(app, 'extractNativeLibs') } : null,
    componentCounts: counts, components,
  };
}

// ---- DEX ----

export function inspectDex(name: string, d: Buffer, limit: number) {
  const magic = d.toString('latin1', 0, 8);
  if (!/^dex\n\d{3}\0$/.test(magic)) throw new Error('Expected a DEX file.');
  if (d.readUInt32LE(40) !== 0x12345678) throw new Error('Unsupported DEX byte order.');
  const count = (o: number) => d.readUInt32LE(o), off = (o: number) => d.readUInt32LE(o + 4);
  const [strings, types, protos, fields, methods, classes] = [56, 64, 72, 80, 88, 96].map(count);
  if (off(56) + strings * 4 > d.length || off(64) + types * 4 > d.length || off(88) + methods * 8 > d.length || off(96) + classes * 32 > d.length) {
    throw new Error('DEX tables fall outside the file.');
  }
  let at = 0;
  const uleb = () => {
    let value = 0, shift = 0;
    for (;;) {
      const b = d[at++];
      if (b === undefined || shift > 28) throw new Error('Bad DEX uleb128.');
      value |= (b & 0x7f) << shift; shift += 7;
      if (!(b & 0x80)) return value >>> 0;
    }
  };
  // ponytail: MUTF-8 decoded as UTF-8, so supplementary characters (encoded as surrogate pairs) show as U+FFFD.
  const string = (i: number) => {
    if (i >= strings) return null;
    at = d.readUInt32LE(off(56) + i * 4);
    uleb();
    const end = d.indexOf(0, at);
    return d.toString('utf8', at, end < 0 ? d.length : end);
  };
  const type = (i: number) => i < types ? string(d.readUInt32LE(off(64) + i * 4)) : null;
  const javaName = (descriptor: string | null) => descriptor?.startsWith('L') && descriptor.endsWith(';') ? descriptor.slice(1, -1).replaceAll('/', '.') : descriptor;
  const methodName = (i: number) => i < methods ? string(d.readUInt32LE(off(88) + i * 8 + 4)) : null;
  const flags = (bits: number) => ACCESS.filter(([bit]) => bits & bit).map(([, n]) => n);

  const classList = [];
  for (let i = 0; i < Math.min(classes, limit); i++) {
    const c = off(96) + i * 32, dataOff = d.readUInt32LE(c + 24), superIndex = d.readUInt32LE(c + 8);
    let direct = 0, virtual = 0;
    const methodNames: string[] = [];
    if (dataOff) {
      at = dataOff;
      const staticFields = uleb(), instanceFields = uleb();
      direct = uleb(); virtual = uleb();
      for (let f = 0; f < staticFields + instanceFields; f++) { uleb(); uleb(); }
      // method_idx is delta-encoded within each of the two lists.
      for (const [n] of [[direct], [virtual]]) {
        for (let m = 0, index = 0; m < n; m++) {
          index += uleb(); uleb(); uleb();
          if (methodNames.length < limit) { const saved = at; methodNames.push(methodName(index) ?? `#${index}`); at = saved; }
        }
      }
    }
    classList.push({ name: javaName(type(d.readUInt32LE(c))), superclass: superIndex === 0xffffffff ? null : javaName(type(superIndex)),
      access: flags(d.readUInt32LE(c + 4)), directMethods: direct, virtualMethods: virtual, methods: methodNames });
  }
  const sample: string[] = [], urls: string[] = [];
  for (let i = 0; i < strings && (sample.length < limit || urls.length < limit); i++) {
    const s = string(i) ?? '';
    if (sample.length < limit) sample.push(s);
    if (urls.length < limit && /^https?:\/\/[^\s]+$/i.test(s)) urls.push(s);
  }
  return { name, version: magic.slice(4, 7), bytes: d.length, sha1: d.subarray(12, 32).toString('hex'),
    counts: { strings, types, protos, fields, methods, classes }, classes: classList, strings: sample, urls };
}

// ---- Signing ----

async function v1Signature(path: string, roots: string[], entries: ZipEntry[]) {
  const blocks = entries.filter(e => /^META-INF\/[^/]+\.(RSA|DSA|EC)$/i.test(e.name));
  if (!blocks.length) return null;
  const manifest = entries.find(e => e.name === 'META-INF/MANIFEST.MF');
  const signers = [];
  for (const block of blocks) {
    const { certificates } = signedData(der(await readMember(path, roots, block), 0));
    const sf = entries.find(e => e.name === block.name.replace(/\.[^.]+$/, '.SF'));
    // A v1 signature file names the newer schemes the signer also applied, so stripping them is detectable.
    const apkSigned = sf ? (await readMember(path, roots, sf)).toString('utf8').match(/^X-Android-APK-Signed:\s*(.+?)\r?$/m)?.[1] ?? null : null;
    signers.push({ signatureFile: sf?.name ?? null, block: block.name, androidSchemesClaimed: apkSigned, certificates: certificates.map(certInfo) });
  }
  const entryCount = manifest ? ((await readMember(path, roots, manifest)).toString('utf8').match(/^Name: /gm)?.length ?? 0) : null;
  return { manifestEntries: entryCount, signers };
}

const algorithm = (b: Buffer) => SIGNATURE_ALGORITHMS[b.readUInt32LE(0)] ?? `0x${b.readUInt32LE(0).toString(16)}`;

/** v2/v3 signer: signed data { digests, certificates, [v3: min/max SDK], attributes }, [v3: min/max SDK], signatures, public key. */
function schemeSigners(value: Buffer, v3: boolean) {
  return prefixed(lp(value, 0)).map(signer => {
    const signed = lp(signer, 0);
    const digests = lp(signed, 0);
    const certificates = lp(signed, 4 + digests.length);
    let at = 8 + digests.length + certificates.length;
    const sdk = v3 ? { min: signed.readUInt32LE(at), max: signed.readUInt32LE(at + 4) } : null;
    if (v3) at += 8;
    const attributes = lp(signed, at);
    const after = 4 + signed.length + (v3 ? 8 : 0);
    return {
      certificates: prefixed(certificates).map(c => certInfo(new X509Certificate(c))),
      digests: prefixed(digests).map(d => ({ algorithm: algorithm(d), digest: lp(d, 4).toString('hex') })),
      signatureAlgorithms: prefixed(lp(signer, after)).map(algorithm),
      ...(v3 ? { sdk, platformSdk: { min: signer.readUInt32LE(4 + signed.length), max: signer.readUInt32LE(8 + signed.length) } } : {}),
      // IDs only: 0xbeeff00d is v2 stripping protection, 0x3ba06f8c the v3 proof-of-rotation lineage.
      additionalAttributes: prefixed(attributes).map(a => `0x${a.readUInt32LE(0).toString(16)}`),
    };
  });
}

/** The APK Signing Block sits immediately before the central directory, framed by its size and magic. */
async function signingBlock(path: string, roots: string[], dirOffset: number) {
  if (dirOffset < 32) return null;
  const footer = await readRegion(path, roots, dirOffset - 24, 24);
  if (footer.toString('latin1', 8) !== SIG_BLOCK_MAGIC) return null;
  const size = Number(footer.readBigUInt64LE(0));
  if (size < 24 || size + 8 > dirOffset || size > MAX_SIGNING_BLOCK) throw new Error('APK Signing Block size is out of range.');
  const block = await readRegion(path, roots, dirOffset - size - 8, size + 8);
  if (Number(block.readBigUInt64LE(0)) !== size) throw new Error('APK Signing Block sizes disagree.');
  const pairs: { id: number; value: Buffer }[] = [];
  for (let at = 8; at < block.length - 24;) {
    const n = Number(block.readBigUInt64LE(at));
    if (n < 4 || at + 8 + n > block.length - 24) throw new Error('APK Signing Block entry runs past the block.');
    pairs.push({ id: block.readUInt32LE(at + 8), value: block.subarray(at + 12, at + 8 + n) });
    at += 8 + n;
  }
  const scheme = (id: number, v3: boolean) => { const p = pairs.find(p => p.id === id); return p ? schemeSigners(p.value, v3) : null; };
  return { offset: dirOffset - size - 8, bytes: size + 8,
    entries: pairs.map(p => ({ id: `0x${p.id.toString(16)}`, kind: BLOCKS[p.id] ?? 'unknown', bytes: p.value.length })),
    v2: scheme(0x7109871a, false), v3: scheme(0xf05368c0, true), v31: scheme(0x1b93ad61, true) };
}

/** v4 lives beside the APK as <name>.idsig: version, hashing info, signing info, then the Merkle tree. */
async function v4Signature(path: string, roots: string[]) {
  const sibling = `${path}.idsig`;
  let size: number;
  try { size = await artifactSize(sibling, roots); } catch { return null; }
  const b = await readRegion(sibling, roots, 0, Math.min(size, MAX_IDSIG_HEADER));
  const hashing = lp(b, 4), signing = lp(b, 8 + hashing.length);
  const salt = lp(hashing, 5), rootHash = lp(hashing, 9 + salt.length);
  const apkDigest = lp(signing, 0), cert = lp(signing, 4 + apkDigest.length);
  const extra = lp(signing, 8 + apkDigest.length + cert.length), key = lp(signing, 12 + apkDigest.length + cert.length + extra.length);
  return { file: sibling, bytes: size, version: b.readUInt32LE(0),
    hashAlgorithm: hashing.readUInt32LE(0) === 1 ? 'SHA-256' : `0x${hashing.readUInt32LE(0).toString(16)}`, log2BlockSize: hashing[4],
    rootHash: rootHash.toString('hex'), apkDigest: apkDigest.toString('hex'), certificate: certInfo(new X509Certificate(cert)),
    signatureAlgorithm: algorithm(signing.subarray(16 + apkDigest.length + cert.length + extra.length + key.length)) };
}

// ---- Native libraries and the archive ----

/** A bounded reader over one member: stored members are read in place, deflated ones inflated (capped). */
async function memberReader(path: string, roots: string[], entry: ZipEntry, apkSize: number) {
  if (entry.method === 0) {
    const local = await readRegion(path, roots, entry.headerOffset, 30);
    const dataAt = entry.headerOffset + 30 + local.readUInt16LE(26) + local.readUInt16LE(28);
    if (dataAt + entry.bytes > apkSize) throw new Error('Archive member falls outside the file.');
    const file = regionReader(path, roots, apkSize);
    const read = (offset: number, length: number) => {
      if (offset < 0 || length < 0 || offset + length > entry.bytes) throw new Error('Region falls outside the file.');
      return file(dataAt + offset, length);
    };
    return { read, size: entry.bytes, sha256: async () => (await digestRanges(path, roots, [[dataAt, dataAt + entry.bytes]], ['sha256'])).sha256 };
  }
  const bytes = await readMember(path, roots, entry);
  const read = async (offset: number, length: number) => {
    if (offset < 0 || length < 0 || offset + length > bytes.length) throw new Error('Region falls outside the file.');
    return bytes.subarray(offset, offset + length);
  };
  return { read, size: bytes.length, sha256: async () => createHash('sha256').update(bytes).digest('hex') };
}

export async function inspectAndroidApp(path: string, roots: string[], limit = 200) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Refusing an out-of-range limit.');
  const { size, entries, dirOffset } = await readCentralDirectory(path, roots);
  const byName = new Map(entries.map(e => [e.name, e]));
  const bundle = byName.has('BundleConfig.pb') || byName.has('base/manifest/AndroidManifest.xml');
  if (!bundle && !byName.has('AndroidManifest.xml')) throw new Error('No AndroidManifest.xml: not an Android package.');
  const unreadable: string[] = [];
  /** One malformed member is reported by name rather than failing the whole package. */
  async function attempt<T>(name: string, action: () => Promise<T>) {
    try { return await action(); } catch { unreadable.push(name); return null; }
  }

  const modules = bundle ? [...new Set(entries.map(e => e.name.match(/^([^/]+)\/manifest\/AndroidManifest\.xml$/)?.[1]).filter(Boolean))] as string[] : [''];
  const prefix = (m: string) => bundle ? `${m.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/` : '';
  const perModule = [];
  for (const m of modules) {
    const manifestName = bundle ? `${m}/manifest/AndroidManifest.xml` : 'AndroidManifest.xml';
    const manifest = await attempt(manifestName, async () => {
      const raw = await readMember(path, roots, byName.get(manifestName)!);
      return summarizeManifest(bundle ? parseProtoXml(raw) : parseBinaryXml(raw), limit);
    });
    const dexPattern = bundle ? new RegExp(`^${prefix(m)}dex/classes\\d*\\.dex$`) : /^classes\d*\.dex$/;
    const dex = [];
    for (const e of entries.filter(e => dexPattern.test(e.name))) {
      dex.push(await attempt(e.name, async () => inspectDex(e.name, await readMember(path, roots, e), limit)));
    }
    const libPattern = new RegExp(`^${prefix(m)}lib/([^/]+)/[^/]+\\.so$`);
    const libs = [];
    for (const e of entries.filter(e => libPattern.test(e.name))) {
      if (e.method !== 0 && e.bytes > MAX_MEMBER_BYTES) {
        libs.push({ path: e.name, abi: e.name.match(libPattern)![1], stored: false, bytes: e.bytes, skipped: 'Compressed and larger than the in-memory cap.' });
        continue;
      }
      libs.push(await attempt(e.name, async () => {
        const member = await memberReader(path, roots, e, size);
        const { segments: _s, sections: _x, ...elf } = await readElf(member.read, member.size, limit);
        return { path: e.name, abi: e.name.match(libPattern)![1], stored: e.method === 0, sha256: await member.sha256(), bytes: member.size, ...elf };
      }));
    }
    const under = (dir: string) => entries.filter(e => e.name.startsWith(`${prefix(m)}${dir}/`)).length;
    perModule.push({ ...(bundle ? { module: m } : {}), manifest, dex: dex.filter(Boolean), nativeLibraries: libs.filter(Boolean),
      abis: [...new Set(libs.filter(Boolean).map(l => l!.abi))], assets: under('assets'), resources: under('res'),
      resourceTable: byName.has(bundle ? `${m}/resources.pb` : 'resources.arsc') });
  }

  const v1 = await attempt('META-INF signature', () => v1Signature(path, roots, entries));
  const block = await attempt('APK Signing Block', () => signingBlock(path, roots, dirOffset));
  const v4 = bundle ? null : await attempt(`${path}.idsig`, () => v4Signature(path, roots));
  return { ...(await digestRanges(path, roots, [[0, size]], ['sha256'])), bytes: size, format: bundle ? 'aab' : 'apk',
    entries: entries.length, uncompressedBytes: entries.reduce((n, e) => n + e.bytes, 0),
    ...(bundle ? { modules: perModule } : perModule[0]),
    signing: { schemes: [v1 && 'v1', block?.v2 && 'v2', block?.v3 && 'v3', block?.v31 && 'v3.1', v4 && 'v4'].filter(Boolean),
      v1, signingBlock: block, v4, verified: false,
      note: 'Structural parse only: signatures, digests, certificate chains and key rotation are not cryptographically verified.' },
    unreadable };
}
