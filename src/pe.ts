// Windows PE/COFF reader. Headers, sections, imports, exports, debug record,
// version resource and the .NET header, read by bounded regions so installers
// and large binaries are never loaded whole.
import { createHash } from 'node:crypto';
import { artifactSize, readRegion } from './inspect.js';
import { parseClrMetadata } from './dotnet.js';

const CHUNK = 64 * 1024;
const HASH_CHUNK = 1024 * 1024;
const MAX_SECTIONS = 96;
const MAX_IMPORT_DLLS = 4096;
const MAX_THUNKS = 65536;
const MAX_METADATA_BYTES = 32 * 1024 * 1024;

const MACHINES: Record<number, string> = { 0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'arm64', 0x1c0: 'arm', 0x1c4: 'arm-thumb2',
  0xa641: 'arm64ec', 0x200: 'ia64', 0x5064: 'riscv64' };
// .NET ReadyToRun images built for another OS store the machine XORed with an OS marker.
const R2R_OS: Record<number, string> = { 0x4644: 'macOS', 0x7b79: 'Linux', 0xadc4: 'FreeBSD', 0x1993: 'NetBSD' };
const SUBSYSTEMS: Record<number, string> = { 1: 'native', 2: 'windowsGui', 3: 'windowsConsole', 7: 'posixConsole', 9: 'windowsCeGui',
  10: 'efiApplication', 11: 'efiBootServiceDriver', 12: 'efiRuntimeDriver', 13: 'efiRom', 14: 'xbox', 16: 'windowsBootApplication' };
const FILE_FLAGS: [number, string][] = [[0x1, 'relocsStripped'], [0x2, 'executable'], [0x20, 'largeAddressAware'],
  [0x100, '32bitMachine'], [0x200, 'debugStripped'], [0x1000, 'system'], [0x2000, 'dll']];
const DLL_FLAGS: [number, string][] = [[0x20, 'highEntropyVa'], [0x40, 'dynamicBase'], [0x80, 'forceIntegrity'], [0x100, 'nxCompat'],
  [0x200, 'noIsolation'], [0x400, 'noSeh'], [0x800, 'noBind'], [0x1000, 'appContainer'], [0x2000, 'wdmDriver'],
  [0x4000, 'guardCf'], [0x8000, 'terminalServerAware']];
const CLR_FLAGS: [number, string][] = [[0x1, 'ilOnly'], [0x2, 'requires32Bit'], [0x8, 'strongNameSigned'],
  [0x10, 'nativeEntryPoint'], [0x20000, 'prefers32Bit']];
const DIR = { export: 0, import: 1, resource: 2, security: 4, debug: 6, delayImport: 13, clr: 14 };

const names = (table: [number, string][], value: number) => table.filter(([bit]) => value & bit).map(([, name]) => name);

function machineName(code: number) {
  if (MACHINES[code]) return MACHINES[code];
  for (const [marker, os] of Object.entries(R2R_OS)) {
    const arch = MACHINES[code ^ Number(marker)];
    if (arch) return `${arch} (ReadyToRun, ${os})`;
  }
  return `0x${code.toString(16)}`;
}

/** Hash byte ranges of an approved file with several algorithms in one pass. */
export async function digestRanges(path: string, roots: string[], ranges: [number, number][], algorithms: string[]) {
  const hashes = algorithms.map(a => createHash(a));
  for (const [start, end] of ranges) {
    for (let at = start; at < end; at += HASH_CHUNK) {
      const chunk = await readRegion(path, roots, at, Math.min(HASH_CHUNK, end - at));
      for (const hash of hashes) hash.update(chunk);
    }
  }
  return Object.fromEntries(algorithms.map((a, i) => [a, hashes[i].digest('hex')]));
}

/** Bounded random access to an approved file through cached 64 KiB chunks. */
export function regionReader(path: string, roots: string[], size: number) {
  const chunks = new Map<number, Promise<Buffer>>();
  return async function fileBytes(offset: number, length: number) {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > size) {
      throw new Error('Region falls outside the file.');
    }
    const out = Buffer.alloc(length);
    for (let done = 0; done < length;) {
      const index = Math.floor((offset + done) / CHUNK);
      let chunk = chunks.get(index);
      if (!chunk) chunks.set(index, chunk = readRegion(path, roots, index * CHUNK, Math.min(CHUNK, size - index * CHUNK)));
      const buffer = await chunk, from = offset + done - index * CHUNK;
      done += buffer.copy(out, done, from, Math.min(buffer.length, from + length - done));
    }
    return out;
  };
}

/** Parse the PE headers and return a reader that resolves RVAs through the section table. */
export async function loadPe(path: string, roots: string[]) {
  const size = await artifactSize(path, roots);
  const fileBytes = regionReader(path, roots, size);

  const dos = await fileBytes(0, Math.min(size, 64));
  if (dos.length < 64 || dos.readUInt16LE(0) !== 0x5a4d) throw new Error('Expected a PE file (no MZ header).');
  const pe = dos.readUInt32LE(0x3c);
  const coff = await fileBytes(pe, 24);
  if (coff.readUInt32LE(0) !== 0x4550) throw new Error('Expected a PE file (no PE signature).');
  const sectionCount = coff.readUInt16LE(6), optionalBytes = coff.readUInt16LE(20);
  if (sectionCount > MAX_SECTIONS || optionalBytes < 2) throw new Error('Invalid PE header bounds.');
  const opt = await fileBytes(pe + 24, optionalBytes);
  const magic = opt.readUInt16LE(0);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error('Unknown PE optional header.');
  const wide = magic === 0x20b;
  const dirsAt = wide ? 112 : 96;
  if (optionalBytes < dirsAt) throw new Error('Truncated PE optional header.');
  const dirCount = Math.min(opt.readUInt32LE(dirsAt - 4), 16, (optionalBytes - dirsAt) / 8);
  const dirs = Array.from({ length: 16 }, (_, i) => i < dirCount
    ? { rva: opt.readUInt32LE(dirsAt + i * 8), size: opt.readUInt32LE(dirsAt + i * 8 + 4), entryOffset: pe + 24 + dirsAt + i * 8 }
    : { rva: 0, size: 0, entryOffset: -1 });
  const table = await fileBytes(pe + 24 + optionalBytes, sectionCount * 40);
  const sections = Array.from({ length: sectionCount }, (_, i) => {
    const at = i * 40, raw = table.subarray(at, at + 8);
    const end = raw.indexOf(0);
    return { name: raw.subarray(0, end < 0 ? 8 : end).toString('latin1'), virtualSize: table.readUInt32LE(at + 8),
      virtualAddress: table.readUInt32LE(at + 12), rawSize: table.readUInt32LE(at + 16), rawOffset: table.readUInt32LE(at + 20),
      characteristics: table.readUInt32LE(at + 36) };
  });
  const headerBytes = opt.readUInt32LE(60);

  function offsetOf(rva: number, length: number) {
    if (rva + length <= headerBytes) return rva;
    const s = sections.find(s => rva >= s.virtualAddress && rva + length <= s.virtualAddress + s.rawSize);
    if (!s) throw new Error('RVA is not backed by file data.');
    return s.rawOffset + rva - s.virtualAddress;
  }
  const at = (rva: number, length: number) => fileBytes(offsetOf(rva, length), length);
  async function cString(rva: number, max = 512) {
    const s = sections.find(s => rva >= s.virtualAddress && rva < s.virtualAddress + s.rawSize);
    const room = s ? s.virtualAddress + s.rawSize - rva : headerBytes - rva;
    const bytes = await at(rva, Math.max(0, Math.min(max, room)));
    const end = bytes.indexOf(0);
    return bytes.subarray(0, end < 0 ? bytes.length : end).toString('latin1');
  }
  return { size, pe, coff, opt, wide, dirs, sections, headerBytes, fileBytes, at, cString };
}
type Pe = Awaited<ReturnType<typeof loadPe>>;

async function readImports(p: Pe, limit: number) {
  const dir = p.dirs[DIR.import];
  if (!dir.rva) return [];
  const thunkBytes = p.wide ? 8 : 4;
  const out = [];
  for (let i = 0; i < MAX_IMPORT_DLLS; i++) {
    const d = await p.at(dir.rva + i * 20, 20);
    if (d.every(b => b === 0)) break;
    const lookup = d.readUInt32LE(0) || d.readUInt32LE(16);
    const functions: string[] = [];
    let count = 0;
    for (let k = 0; k < MAX_THUNKS; k++) {
      const t = await p.at(lookup + k * thunkBytes, thunkBytes);
      const value = p.wide ? t.readBigUInt64LE(0) : BigInt(t.readUInt32LE(0));
      if (value === 0n) break;
      count++;
      if (functions.length >= limit) continue;
      const byOrdinal = p.wide ? value >> 63n : value >> 31n;
      functions.push(byOrdinal ? `#${Number(value & 0xffffn)}` : await p.cString(Number(value & 0x7fffffffn) + 2));
    }
    out.push({ dll: await p.cString(d.readUInt32LE(12)), count, functions });
  }
  return out;
}

async function readDelayImports(p: Pe) {
  const dir = p.dirs[DIR.delayImport];
  const out: string[] = [];
  for (let i = 0; dir.rva && i < MAX_IMPORT_DLLS; i++) {
    const d = await p.at(dir.rva + i * 32, 32);
    if (!d.readUInt32LE(4)) break;
    out.push(await p.cString(d.readUInt32LE(4)));
  }
  return out;
}

async function readExports(p: Pe, limit: number) {
  const dir = p.dirs[DIR.export];
  if (!dir.rva) return null;
  const e = await p.at(dir.rva, 40);
  const functionCount = e.readUInt32LE(20), nameCount = e.readUInt32LE(24);
  const functionsAt = e.readUInt32LE(28), namesAt = e.readUInt32LE(32), ordinalsAt = e.readUInt32LE(36);
  const shown = Math.min(nameCount, limit);
  const nameRvas = shown ? await p.at(namesAt, shown * 4) : Buffer.alloc(0);
  const ordinals = shown ? await p.at(ordinalsAt, shown * 2) : Buffer.alloc(0);
  const symbols = [];
  for (let i = 0; i < shown; i++) {
    const ordinal = ordinals.readUInt16LE(i * 2);
    if (ordinal >= functionCount) throw new Error('Export ordinal out of range.');
    const target = (await p.at(functionsAt + ordinal * 4, 4)).readUInt32LE(0);
    // A target inside the export directory itself is a forwarder string like "NTDLL.RtlAllocateHeap".
    const forwarded = target >= dir.rva && target < dir.rva + dir.size;
    symbols.push({ name: await p.cString(nameRvas.readUInt32LE(i * 4)), ordinal: ordinal + e.readUInt32LE(16),
      ...(forwarded && { forwardsTo: await p.cString(target) }) });
  }
  return { dll: await p.cString(e.readUInt32LE(12)), functionCount, nameCount, symbols };
}

async function readDebug(p: Pe) {
  const dir = p.dirs[DIR.debug];
  let pdb = null, reproducible = false;
  for (let i = 0; dir.rva && i < Math.min(dir.size / 28, 32); i++) {
    const d = await p.at(dir.rva + i * 28, 28);
    const type = d.readUInt32LE(12), length = d.readUInt32LE(16), offset = d.readUInt32LE(24);
    if (type === 16) reproducible = true;
    if (type === 2 && length >= 24 && length < 4096) {
      const cv = await p.fileBytes(offset, length);
      if (cv.toString('latin1', 0, 4) !== 'RSDS') continue;
      const g = cv.subarray(4, 20);
      const guid = [g.readUInt32LE(0).toString(16).padStart(8, '0'), g.readUInt16LE(4).toString(16).padStart(4, '0'),
        g.readUInt16LE(6).toString(16).padStart(4, '0'), g.subarray(8, 10).toString('hex'), g.subarray(10).toString('hex')].join('-');
      const end = cv.indexOf(0, 24);
      pdb = { path: cv.toString('utf8', 24, end < 0 ? cv.length : end), guid, age: cv.readUInt32LE(20) };
    }
  }
  return { pdb, reproducible };
}

/** Walk resource directory levels type -> name -> language to the first RT_VERSION data entry. */
async function versionResource(p: Pe) {
  const dir = p.dirs[DIR.resource];
  if (!dir.rva) return null;
  let node = 0;
  for (const wanted of [16, null, null]) {
    const header = await p.at(dir.rva + node, 16);
    const count = Math.min(header.readUInt16LE(12) + header.readUInt16LE(14), 4096);
    const entries = await p.at(dir.rva + node + 16, count * 8);
    let next = -1;
    for (let i = 0; i < entries.length; i += 8) {
      if (wanted === null || entries.readUInt32LE(i) === wanted) { next = entries.readUInt32LE(i + 4); break; }
    }
    if (next < 0) return null;
    // Type and name levels point at subdirectories (high bit set); the language level points at the data entry.
    if (wanted === null && node && !(next & 0x8000_0000)) {
      const data = await p.at(dir.rva + next, 8);
      return p.at(data.readUInt32LE(0), Math.min(data.readUInt32LE(4), 64 * 1024));
    }
    if (!(next & 0x8000_0000)) return null;
    node = next & 0x7fff_ffff;
  }
  return null;
}

/** VS_VERSIONINFO: a tree of {length, valueLength, type, key, value, children} nodes in UTF-16. */
export function parseVersionInfo(bytes: Buffer) {
  const strings: Record<string, string> = {};
  let fixed: { fileVersion: string; productVersion: string } | null = null;
  const align = (n: number) => (n + 3) & ~3;
  function walk(start: number, end: number) {
    for (let at = start; at + 6 <= end;) {
      const length = bytes.readUInt16LE(at), valueLength = bytes.readUInt16LE(at + 2), text = bytes.readUInt16LE(at + 4) === 1;
      if (length < 6 || at + length > end) return;
      let keyEnd = at + 6;
      while (keyEnd + 1 < at + length && bytes.readUInt16LE(keyEnd)) keyEnd += 2;
      const key = bytes.toString('utf16le', at + 6, keyEnd);
      const valueAt = align(keyEnd + 2), valueBytes = text ? valueLength * 2 : valueLength;
      if (key === 'VS_VERSION_INFO' && valueBytes >= 52 && bytes.readUInt32LE(valueAt) === 0xfeef04bd) {
        const v = (o: number) => `${bytes.readUInt16LE(valueAt + o + 2)}.${bytes.readUInt16LE(valueAt + o)}.${bytes.readUInt16LE(valueAt + o + 6)}.${bytes.readUInt16LE(valueAt + o + 4)}`;
        fixed = { fileVersion: v(8), productVersion: v(16) };
      } else if (text && valueBytes && Object.keys(strings).length < 64) {
        strings[key] = bytes.toString('utf16le', valueAt, Math.min(valueAt + valueBytes, at + length)).replace(/\0+$/, '').slice(0, 256);
      }
      walk(align(valueAt + valueBytes), at + length);
      at = align(at + length);
    }
  }
  walk(0, bytes.length);
  return { ...(fixed ?? { fileVersion: null, productVersion: null }), strings };
}

async function readClr(p: Pe, limit: number) {
  const dir = p.dirs[DIR.clr];
  if (!dir.rva) return null;
  const h = await p.at(dir.rva, 72);
  const mdRva = h.readUInt32LE(8), mdSize = h.readUInt32LE(12), flags = h.readUInt32LE(16);
  if (mdSize > MAX_METADATA_BYTES) throw new Error('Refusing oversized .NET metadata.');
  return { headerVersion: `${h.readUInt16LE(4)}.${h.readUInt16LE(6)}`, flags: names(CLR_FLAGS, flags),
    ...parseClrMetadata(await p.at(mdRva, mdSize), limit) };
}

export async function inspectPe(path: string, roots: string[], limit = 200) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Refusing an out-of-range limit.');
  const p = await loadPe(path, roots);
  const { coff, opt, wide, dirs, sections } = p;
  const debug = await readDebug(p);
  const stamp = coff.readUInt32LE(8);
  const rawEnd = Math.max(p.headerBytes, ...sections.map(s => s.rawOffset + s.rawSize));
  const cert = dirs[DIR.security];
  const version = await versionResource(p);
  return {
    ...(await digestRanges(path, roots, [[0, p.size]], ['sha256'])), bytes: p.size,
    format: wide ? 'PE32+' : 'PE32', machine: machineName(coff.readUInt16LE(4)),
    characteristics: names(FILE_FLAGS, coff.readUInt16LE(18)),
    // Reproducible builds write a content hash here instead of a time.
    timestamp: debug.reproducible ? null : new Date(stamp * 1000).toISOString(), reproducible: debug.reproducible,
    subsystem: SUBSYSTEMS[opt.readUInt16LE(68)] ?? opt.readUInt16LE(68),
    linkerVersion: `${opt[2]}.${opt[3]}`, osVersion: `${opt.readUInt16LE(40)}.${opt.readUInt16LE(42)}`,
    imageBase: `0x${(wide ? opt.readBigUInt64LE(24) : BigInt(opt.readUInt32LE(28))).toString(16)}`,
    entryPoint: `0x${opt.readUInt32LE(16).toString(16)}`,
    dllCharacteristics: names(DLL_FLAGS, opt.readUInt16LE(70)),
    sections: sections.map(s => ({ name: s.name, virtualAddress: `0x${s.virtualAddress.toString(16)}`, virtualSize: s.virtualSize,
      rawSize: s.rawSize, access: `${s.characteristics & 0x4000_0000 ? 'r' : '-'}${s.characteristics & 0x8000_0000 ? 'w' : '-'}${s.characteristics & 0x2000_0000 ? 'x' : '-'}` })),
    imports: await readImports(p, limit), delayImports: await readDelayImports(p), exports: await readExports(p, limit),
    pdb: debug.pdb, version: version ? parseVersionInfo(version) : null,
    signed: cert.size > 0,
    // Installers append their payload after the last section; Authenticode data sits at the very end.
    overlayBytes: Math.max(0, (cert.size ? cert.rva : p.size) - rawEnd),
    dotnet: await readClr(p, limit),
  };
}
