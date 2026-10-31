// ECMA-335 metadata reader: the assembly identity, the assemblies and native modules it references,
// and the target framework it was built for. Only the tables needed to reach those rows are sized.
import { createHash } from 'node:crypto';

// Column kinds: 'u2'/'u4' fixed, 's'/'g'/'b' heap indexes, a number is a row index into that table,
// any other string is a coded index named in CODED.
const SCHEMA: (string | number)[][] = [
  ['u2', 's', 'g', 'g', 'g'], ['rs', 's', 's'], ['u4', 's', 's', 'tdor', 0x04, 0x06], [0x04], ['u2', 's', 'b'], [0x06],
  ['u4', 'u2', 'u2', 's', 'b', 0x08], [0x08], ['u2', 'u2', 's'], [0x02, 'tdor'], ['mrp', 's', 'b'], ['u2', 'hc', 'b'],
  ['hca', 'cat', 'b'], ['hfm', 'b'], ['u2', 'hds', 'b'], ['u2', 'u4', 0x02], ['u4', 0x04], ['b'], [0x02, 0x14], [0x14],
  ['u2', 's', 'tdor'], [0x02, 0x17], [0x17], ['u2', 's', 'b'], ['u2', 0x06, 'hs'], [0x02, 'mdor', 'mdor'], ['s'], ['b'],
  ['u2', 'mf', 's', 0x1a], ['u4', 0x04], ['u4', 'u4'], ['u4'], ['u4', 'u2', 'u2', 'u2', 'u2', 'u4', 'b', 's', 's'], ['u4'],
  ['u4', 'u4', 'u4'], ['u2', 'u2', 'u2', 'u2', 'u4', 'b', 's', 's', 'b'],
];
const CODED: Record<string, number[]> = {
  rs: [0x00, 0x1a, 0x23, 0x01], tdor: [0x02, 0x01, 0x1b], mrp: [0x02, 0x01, 0x1a, 0x06, 0x1b], hc: [0x04, 0x08, 0x17],
  hca: [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
  cat: [-1, -1, 0x06, 0x0a, -1], hfm: [0x04, 0x08], hds: [0x02, 0x06, 0x20], hs: [0x14, 0x17], mdor: [0x06, 0x0a], mf: [0x04, 0x06],
};
const T = { module: 0x00, typeRef: 0x01, typeDef: 0x02, memberRef: 0x0a, customAttribute: 0x0c, moduleRef: 0x1a, assembly: 0x20, assemblyRef: 0x23 };

export function parseClrMetadata(md: Buffer, limit: number) {
  if (md.readUInt32LE(0) !== 0x424a5342) throw new Error('Missing .NET metadata signature.');
  const versionLength = md.readUInt32LE(12);
  const runtimeVersion = md.toString('latin1', 16, 16 + versionLength).replace(/\0+$/, '');
  let at = 16 + versionLength + 2;
  const streams: Record<string, Buffer> = {};
  for (let i = md.readUInt16LE(at), cursor = at + 2; i > 0; i--) {
    const offset = md.readUInt32LE(cursor), size = md.readUInt32LE(cursor + 4);
    const end = md.indexOf(0, cursor + 8);
    const name = md.toString('latin1', cursor + 8, end);
    if (offset + size > md.length) throw new Error('.NET stream falls outside metadata.');
    streams[name] = md.subarray(offset, offset + size);
    cursor = (end + 4) & ~3;
  }
  const tables = streams['#~'] ?? streams['#-'], strings = streams['#Strings'], blobs = streams['#Blob'];
  if (!tables || !strings || !blobs) throw new Error('Incomplete .NET metadata streams.');

  const heapSizes = tables[6], valid = tables.readBigUInt64LE(8);
  const rows: number[] = [];
  at = 24;
  for (let i = 0; i < 64; i++) {
    rows[i] = valid >> BigInt(i) & 1n ? tables.readUInt32LE(at) : 0;
    if (rows[i]) at += 4;
  }
  if (heapSizes & 0x40) at += 4;
  const width = (kind: string | number): number => {
    if (typeof kind === 'number') return rows[kind] < 0x10000 ? 2 : 4;
    if (kind === 'u2' || kind === 'u4') return Number(kind[1]);
    if (kind === 's') return heapSizes & 1 ? 4 : 2;
    if (kind === 'g') return heapSizes & 2 ? 4 : 2;
    if (kind === 'b') return heapSizes & 4 ? 4 : 2;
    const targets = CODED[kind], bits = Math.ceil(Math.log2(targets.length));
    return Math.max(...targets.map(t => rows[t] ?? 0)) < 2 ** (16 - bits) ? 2 : 4;
  };
  const starts: number[] = [];
  for (let t = 0; t < SCHEMA.length; t++) {
    starts[t] = at;
    at += rows[t] * SCHEMA[t].reduce<number>((sum, kind) => sum + width(kind), 0);
  }
  /** Column values of one row (1-based, as metadata tokens count them). */
  const row = (table: number, index: number) => {
    if (index < 1 || index > rows[table]) throw new Error('.NET row index out of range.');
    let cursor = starts[table] + (index - 1) * SCHEMA[table].reduce<number>((sum, kind) => sum + width(kind), 0);
    return SCHEMA[table].map(kind => {
      const w = width(kind);
      const value = w === 2 ? tables.readUInt16LE(cursor) : tables.readUInt32LE(cursor);
      cursor += w;
      return value;
    });
  };
  const str = (index: number) => strings.toString('utf8', index, strings.indexOf(0, index));
  const blob = (index: number) => {
    const b = blobs[index];
    const [length, skip] = b < 0x80 ? [b, 1] : b < 0xc0 ? [((b & 0x3f) << 8) | blobs[index + 1], 2] : [blobs.readUInt32BE(index) & 0x1fffffff, 4];
    return blobs.subarray(index + skip, index + skip + length);
  };
  const hex = (b: Buffer) => b.length ? b.toString('hex') : null;
  // A full public key is shortened to its token: the last 8 bytes of its SHA-1, reversed.
  const token = (key: Buffer) => key.length > 8 ? hex(Buffer.from(createHash('sha1').update(key).digest().subarray(-8)).reverse()) : hex(key);
  const version = (r: number[]) => r.slice(0, 4).join('.');

  const assembly = rows[T.assembly] ? (() => {
    const r = row(T.assembly, 1);
    return { name: str(r[7]), version: r.slice(1, 5).join('.'), culture: str(r[8]) || null, publicKeyToken: token(blob(r[6])) };
  })() : null;
  const references = Array.from({ length: Math.min(rows[T.assemblyRef], limit) }, (_, i) => {
    const r = row(T.assemblyRef, i + 1);
    return { name: str(r[6]), version: version(r), culture: str(r[7]) || null, publicKeyToken: token(blob(r[5])) };
  });
  const nativeModules = Array.from({ length: Math.min(rows[T.moduleRef], limit) }, (_, i) => str(row(T.moduleRef, i + 1)[0]));

  // [assembly: TargetFramework(".NETCoreApp,Version=v8.0")] is a custom attribute whose constructor is a
  // MemberRef on a TypeRef with that name; its blob is prolog 0x0001 then one length-prefixed string.
  let targetFramework = null;
  for (let i = 1; i <= rows[T.customAttribute] && !targetFramework; i++) {
    const [, type, value] = row(T.customAttribute, i);
    if ((type & 7) !== 3) continue;
    const [parent] = row(T.memberRef, type >> 3);
    if ((parent & 7) !== 1 || str(row(T.typeRef, parent >> 3)[1]) !== 'TargetFrameworkAttribute') continue;
    const b = blob(value);
    if (b.length > 3 && b.readUInt16LE(0) === 1 && b[2] < 0x80) targetFramework = b.toString('utf8', 3, 3 + b[2]);
  }
  return {
    runtimeVersion, module: rows[T.module] ? str(row(T.module, 1)[1]) : null, assembly, targetFramework,
    typeCount: rows[T.typeDef], referenceCount: rows[T.assemblyRef], references,
    nativeModuleCount: rows[T.moduleRef], nativeModules,
  };
}
