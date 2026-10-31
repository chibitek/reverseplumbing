import { constants } from 'node:fs';
import { access, open, readdir, realpath, stat } from 'node:fs/promises';
import { isAbsolute, relative, sep } from 'node:path';
import { createHash } from 'node:crypto';

const MAX_BYTES = 32 * 1024 * 1024;
// A Mach-O header plus its load commands sits at the front of the file and is
// kilobytes in practice. Bound it generously rather than reading the whole binary.
const MAX_HEADER_BYTES = 16 * 1024 * 1024;
const HASH_CHUNK_BYTES = 1024 * 1024;

function inRoots(resolved: string, roots: string[]) {
  return roots.some(root => {
    const child = relative(root, resolved);
    return child !== '..' && !child.startsWith(`..${sep}`) && !isAbsolute(child);
  });
}

/** The real path of an artifact, refused unless it sits inside an approved root. */
export async function resolveInRoot(path: string, roots: string[]) {
  if (!isAbsolute(path)) throw new Error('Use an absolute artifact path.');
  const resolved = await realpath(path);
  if (!inRoots(resolved, roots)) throw new Error('Artifact is outside the operator-approved roots.');
  return resolved;
}

async function openInRoot(path: string, roots: string[]) {
  return open(await resolveInRoot(path, roots), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
}

/** Directory listing under the same root and symlink rules as a file read. */
export async function listInRoot(path: string, roots: string[]) {
  const resolved = await realpath(path);
  if (!inRoots(resolved, roots)) throw new Error('Directory is outside the operator-approved roots.');
  if (!(await stat(resolved)).isDirectory()) throw new Error('Expected a directory.');
  return (await readdir(resolved)).filter(name => !name.startsWith('.')).sort();
}

/** Fill exactly `size` bytes from `offset`, or fail rather than return a short buffer. */
async function readAt(file: Awaited<ReturnType<typeof openInRoot>>, offset: number, size: number) {
  const buffer = Buffer.alloc(size);
  let filled = 0;
  while (filled < size) {
    const chunk = await file.read(buffer, filled, size - filled, offset + filled);
    if (!chunk.bytesRead) throw new Error('Artifact ended before the requested region.');
    filled += chunk.bytesRead;
  }
  return buffer;
}

export async function readArtifact(path: string, roots: string[]): Promise<Buffer> {
  const file = await openInRoot(path, roots);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.size > MAX_BYTES) throw new Error('Expected a regular file no larger than 32 MiB.');
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await file.read(bytes, length, bytes.length - length, null);
      if (!result.bytesRead) break;
      length += result.bytesRead;
    }
    if (length > MAX_BYTES) throw new Error('Artifact exceeds 32 MiB.');
    return bytes.subarray(0, length);
  } finally { await file.close(); }
}

const FAT_MAGICS = [0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca];
const THIN_MAGICS = [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe];
const LC_UUID = 0x1b, LC_BUILD_VERSION = 0x32, LC_CODE_SIGNATURE = 0x1d;
const LC_LOAD_DYLIB = 0x0c, LC_LOAD_WEAK_DYLIB = 0x8000_0018, LC_RPATH = 0x8000_001c;
const LC_SEGMENT = 0x01, LC_SEGMENT_64 = 0x19;

/** Header sizes from a 32-byte probe, before the load commands have been read. */
function machOPrelude(head: Buffer) {
  if (head.length < 28) throw new Error('Truncated Mach-O header.');
  const magic = head.readUInt32BE(0);
  if (!THIN_MAGICS.includes(magic)) throw new Error('Expected a thin Mach-O slice.');
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  return { headerBytes: wide ? 32 : 28, commandBytes: little ? head.readUInt32LE(20) : head.readUInt32BE(20) };
}

/** Shared view over a Mach-O header: endianness, width and a reader that respects both. */
export function machOHeader(bytes: Buffer) {
  if (bytes.length < 28) throw new Error('Truncated Mach-O header.');
  const magic = bytes.readUInt32BE(0);
  if (!THIN_MAGICS.includes(magic)) throw new Error('Expected a thin Mach-O slice.');
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const wide = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const read = (offset: number) => little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const headerBytes = wide ? 32 : 28;
  const commandCount = read(16);
  const commandBytes = read(20);
  if (bytes.length < headerBytes || commandBytes > bytes.length - headerBytes || commandCount > commandBytes / 8) {
    throw new Error('Invalid Mach-O load-command bounds.');
  }
  return { little, wide, read, headerBytes, commandCount, commandBytes };
}

/** Walk the load commands once. Every reader of a Mach-O goes through here. */
export function* machOCommands(bytes: Buffer) {
  const { read, headerBytes, commandCount, commandBytes } = machOHeader(bytes);
  const limit = headerBytes + commandBytes;
  let offset = headerBytes;
  for (let i = 0; i < commandCount; i++) {
    if (offset + 8 > limit) throw new Error('Truncated Mach-O load command.');
    const kind = read(offset);
    const size = read(offset + 4);
    if (size < 8 || size % 4 !== 0 || offset + size > limit) throw new Error('Invalid Mach-O load command size.');
    yield { kind, size, offset, read };
    offset += size;
  }
  if (offset !== limit) throw new Error('Mach-O load-command sizes do not match header.');
}

/** A C string inside a load command, located by the command-relative offset Mach-O stores. */
function commandString(bytes: Buffer, start: number, size: number, at: number) {
  if (at < 8 || at >= size) throw new Error('Invalid Mach-O string offset.');
  const field = bytes.subarray(start + at, start + size);
  const end = field.indexOf(0);
  return field.subarray(0, end < 0 ? field.length : end).toString('utf8');
}

function fatSlices(bytes: Buffer, fileSize: number) {
  const magic = bytes.readUInt32BE(0);
  const little = magic === 0xbebafeca || magic === 0xbfbafeca;
  const wide = magic === 0xcafebabf || magic === 0xbfbafeca;
  const read = (offset: number) => little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const readWide = (offset: number) => Number(little ? bytes.readBigUInt64LE(offset) : bytes.readBigUInt64BE(offset));
  const count = read(4);
  const entry = wide ? 32 : 20;
  if (count < 1 || count > 32 || 8 + count * entry > bytes.length) throw new Error('Invalid universal binary header.');
  return Array.from({ length: count }, (_, i) => {
    const at = 8 + i * entry;
    const offset = wide ? readWide(at + 8) : read(at + 8);
    const size = wide ? readWide(at + 16) : read(at + 12);
    if (offset < 0 || size < 28 || offset + size > fileSize) throw new Error('Universal binary slice falls outside the file.');
    return { offset, size };
  });
}

/**
 * Read only the header and load commands of every architecture in a file,
 * hashing the whole file in bounded chunks so the digest stays a digest of the
 * artifact and not of the part we parsed.
 */
export async function readMachO(path: string, roots: string[]) {
  const file = await openInRoot(path, roots);
  try {
    const info = await file.stat();
    if (!info.isFile()) throw new Error('Expected a regular file.');
    const head = Buffer.alloc(32);
    const { bytesRead } = await file.read(head, 0, head.length, 0);
    if (bytesRead < 28) throw new Error('Truncated Mach-O header.');
    const magic = head.readUInt32BE(0);
    const fat = FAT_MAGICS.includes(magic);
    if (!fat && !THIN_MAGICS.includes(magic)) throw new Error('Expected a Mach-O or universal binary.');

    let regions = [{ offset: 0, size: info.size }];
    if (fat) {
      const table = Buffer.alloc(Math.min(8 + 32 * 32, info.size));
      await file.read(table, 0, table.length, 0);
      regions = fatSlices(table, info.size);
    }

    const slices = [];
    for (const region of regions) {
      const sliceHead = Buffer.alloc(32);
      await file.read(sliceHead, 0, sliceHead.length, region.offset);
      const { headerBytes, commandBytes } = machOPrelude(sliceHead);
      const needed = headerBytes + commandBytes;
      if (needed > MAX_HEADER_BYTES || needed > region.size) throw new Error('Invalid Mach-O load-command bounds.');
      slices.push({ ...region, prefix: await readAt(file, region.offset, needed) });
    }

    const hash = createHash('sha256');
    const scratch = Buffer.alloc(HASH_CHUNK_BYTES);
    let position = 0;
    while (position < info.size) {
      const chunk = await file.read(scratch, 0, scratch.length, position);
      if (!chunk.bytesRead) break;
      hash.update(scratch.subarray(0, chunk.bytesRead));
      position += chunk.bytesRead;
    }
    return { fat, slices, sha256: hash.digest('hex'), bytes: position };
  } finally { await file.close(); }
}

/** Read one bounded region of an approved artifact, for a signature blob located by its load command. */
export async function readRegion(path: string, roots: string[], offset: number, size: number) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || size > MAX_HEADER_BYTES) {
    throw new Error('Refusing an out-of-range region read.');
  }
  const file = await openInRoot(path, roots);
  try {
    const info = await file.stat();
    if (!info.isFile() || offset + size > info.size) throw new Error('Region falls outside the file.');
    return await readAt(file, offset, size);
  } finally { await file.close(); }
}

export { inspectHar } from './har.js';

export function inspectMachO(bytes: Buffer, file?: { sha256: string; bytes: number }) {
  const { little, wide, read, commandCount } = machOHeader(bytes);
  const commands: Record<string, number> = {};
  const dylibs: string[] = [];
  const weakDylibs: string[] = [];
  const rpaths: string[] = [];
  let uuid: string | null = null;
  let build: { platform: number; minimumOs: string; sdk: string } | null = null;
  let codeSignature: { offset: number; size: number } | null = null;

  for (const { kind, size, offset, read: at } of machOCommands(bytes)) {
    const name = `0x${kind.toString(16)}`;
    commands[name] = (commands[name] ?? 0) + 1;
    if (kind === LC_LOAD_DYLIB || kind === LC_LOAD_WEAK_DYLIB) {
      (kind === LC_LOAD_DYLIB ? dylibs : weakDylibs).push(commandString(bytes, offset, size, at(offset + 8)));
    } else if (kind === LC_RPATH) {
      rpaths.push(commandString(bytes, offset, size, at(offset + 8)));
    } else if (kind === LC_UUID && size >= 24) {
      uuid = bytes.subarray(offset + 8, offset + 24).toString('hex').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, '$1-$2-$3-$4-$5');
    } else if (kind === LC_BUILD_VERSION && size >= 24) {
      build = { platform: at(offset + 8), minimumOs: version(at(offset + 12)), sdk: version(at(offset + 16)) };
    } else if (kind === LC_CODE_SIGNATURE && size >= 16) {
      codeSignature = { offset: at(offset + 8), size: at(offset + 12) };
    }
  }

  return { sha256: file?.sha256 ?? createHash('sha256').update(bytes).digest('hex'), bytes: file?.bytes ?? bytes.length,
    bits: wide ? 64 : 32, endian: little ? 'little' : 'big', architecture: architecture(read(4), read(8)),
    cpuType: read(4), cpuSubtype: read(8), fileType: read(12), flags: read(24), flagNames: machOFlagNames(read(24)),
    commandCount, commands, uuid, build, dylibs, weakDylibs, rpaths, codeSignature };
}

/** Mach-O packs a version as xxxx.yy.zz across one 32-bit word. */
function version(packed: number) {
  return `${packed >> 16}.${(packed >> 8) & 0xff}.${packed & 0xff}`;
}

const CPU_NAMES: Record<number, string> = { 7: 'i386', 0x0100_0007: 'x86_64', 12: 'arm', 0x0100_000c: 'arm64', 0x0200_000c: 'arm64_32' };
function architecture(cpuType: number, cpuSubtype: number) {
  const base = CPU_NAMES[cpuType >>> 0] ?? `cpu:0x${(cpuType >>> 0).toString(16)}`;
  if (cpuType >>> 0 !== 0x0100_000c) return base;
  const subtype = cpuSubtype & 0x00ff_ffff;
  return ({ 0: 'arm64', 1: 'arm64v8', 2: 'arm64e', 12: 'arm64e.x1' } as Record<number, string>)[subtype]
    ?? `arm64-subtype:${subtype}`;
}

const MACHO_FLAGS: [number, string][] = [[0x1, 'noUndefs'], [0x4, 'dyldLink'], [0x80, 'twoLevel'], [0x2000, 'subsectionsViaSymbols'],
  [0x8000, 'weakDefines'], [0x10000, 'bindsToWeak'], [0x20000, 'allowStackExecution'], [0x80000, 'setuidSafe'],
  [0x200000, 'pie'], [0x800000, 'hasTlvDescriptors'], [0x1000000, 'noHeapExecution'], [0x2000000, 'appExtensionSafe']];
function machOFlagNames(flags: number) {
  return MACHO_FLAGS.filter(([bit]) => flags & bit).map(([, name]) => name);
}

export async function detectHopper(candidates: string[]) {
  for (const path of candidates) {
    try {
      const info = await stat(path);
      if (!info.isFile()) continue;
      await access(path, constants.X_OK);
      return { installed: true, path, launched: false, license: 'Operator-managed; not queried or verified.' };
    } catch { /* Missing or inaccessible is not an installed executable. */ }
  }
  return { installed: false, launched: false, license: 'Use an existing operator-licensed installation; no download or trial fallback.' };
}

// A 16-byte NUL-padded name field, which is allowed to use all 16 bytes.
function fixedName(bytes: Buffer, at: number) {
  const field = bytes.subarray(at, at + 16);
  const end = field.indexOf(0);
  return field.subarray(0, end < 0 ? field.length : end).toString('utf8');
}

function wideNumber(bytes: Buffer, at: number, little: boolean) {
  const value = little ? bytes.readBigUInt64LE(at) : bytes.readBigUInt64BE(at);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Mach-O section size is out of range.');
  return Number(value);
}

// Walks the section table of every segment. Each section names its own file
// offset and size, which is what lets a reader take one bounded slice of a
// 77 MB binary instead of sweeping the whole file.
export function* machOSections(bytes: Buffer) {
  const { little } = machOHeader(bytes);
  for (const { kind, size, offset, read } of machOCommands(bytes)) {
    const wide = kind === LC_SEGMENT_64;
    if (!wide && kind !== LC_SEGMENT) continue;
    const headerBytes = wide ? 72 : 56;
    const entryBytes = wide ? 80 : 68;
    if (size < headerBytes) throw new Error('Truncated Mach-O segment command.');
    const count = read(offset + (wide ? 64 : 48));
    if (count > (size - headerBytes) / entryBytes) {
      throw new Error('Mach-O segment claims more sections than it holds.');
    }
    for (let i = 0; i < count; i++) {
      const at = offset + headerBytes + i * entryBytes;
      yield {
        section: fixedName(bytes, at),
        segment: fixedName(bytes, at + 16),
        fileOffset: read(at + (wide ? 48 : 40)),
        bytes: wide ? wideNumber(bytes, at + 40, little) : read(at + 36),
      };
    }
  }
}

/** Size of an approved artifact, for readers that have to seek from the end of one. */
export async function artifactSize(path: string, roots: string[]) {
  const file = await openInRoot(path, roots);
  try {
    const info = await file.stat();
    if (!info.isFile()) throw new Error('Expected a regular file.');
    return info.size;
  } finally { await file.close(); }
}

/** Architecture slices of a universal binary already held in memory. */
export function fatSlicesOf(bytes: Buffer) {
  return fatSlices(bytes, bytes.length);
}
