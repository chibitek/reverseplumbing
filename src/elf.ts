// Linux ELF reader for ARM, ARM64 and other targets. Headers, program headers, sections, the dynamic
// table (needed libraries, soname, search paths), dynamic imports and exports with their symbol
// versions, GNU notes and a hardening summary. Read through program headers first, so stripped
// binaries without section headers still answer; regions are bounded and the file is never executed.
import { artifactSize } from './inspect.js';
import { digestRanges, regionReader } from './pe.js';

const MAX_SEGMENTS = 256;
const MAX_SECTIONS = 4096;
const MAX_DYNAMIC = 4096;
const MAX_SYMBOLS = 1_000_000;
const MAX_STRINGS = 16 * 1024 * 1024;
const MAX_VERSIONS = 4096;

const MACHINES: Record<number, string> = { 0x3: 'x86', 0x8: 'mips', 0x14: 'ppc', 0x15: 'ppc64', 0x16: 's390x', 0x28: 'arm',
  0x3e: 'x86_64', 0xb7: 'aarch64', 0xf3: 'riscv', 0x102: 'loongarch' };
const OS_ABI: Record<number, string> = { 0: 'sysv', 3: 'linux', 6: 'solaris', 9: 'freebsd', 12: 'openbsd', 97: 'arm', 255: 'standalone' };
const SEGMENTS: Record<number, string> = { 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 6: 'PHDR', 7: 'TLS',
  0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY', 0x70000001: 'ARM_EXIDX' };
const SECTION_TYPES: Record<number, string> = { 1: 'progbits', 2: 'symtab', 3: 'strtab', 4: 'rela', 5: 'hash', 6: 'dynamic', 7: 'note',
  8: 'nobits', 9: 'rel', 11: 'dynsym', 14: 'init_array', 15: 'fini_array', 0x6ffffff6: 'gnu_hash', 0x6ffffffd: 'verdef',
  0x6ffffffe: 'verneed', 0x6fffffff: 'versym', 0x70000001: 'arm_exidx', 0x70000003: 'arm_attributes' };
const SYMBOL_TYPES = ['notype', 'object', 'func', 'section', 'file', 'common', 'tls', , , , 'ifunc'];
const BINDS = ['local', 'global', 'weak', , , , , , , , 'unique'];
const DT = { needed: 1, hash: 4, strtab: 5, symtab: 6, strsz: 10, syment: 11, soname: 14, rpath: 15, textrel: 22, bindNow: 24,
  runpath: 29, flags: 30, gnuHash: 0x6ffffef5, versym: 0x6ffffff0, flags1: 0x6ffffffb, verdef: 0x6ffffffc, verdefnum: 0x6ffffffd,
  verneed: 0x6ffffffe, verneednum: 0x6fffffff };
// GNU_PROPERTY_*_FEATURE_1_AND bits: control-flow protection the code was built with.
const FEATURES: Record<number, [number, string][]> = { 0xc0000000: [[1, 'BTI'], [2, 'PAC'], [4, 'GCS']], 0xc0000002: [[1, 'IBT'], [2, 'SHSTK']] };

const hex = (n: bigint | number) => `0x${n.toString(16)}`;

export async function inspectElf(path: string, roots: string[], limit = 200) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Refusing an out-of-range limit.');
  const size = await artifactSize(path, roots);
  const elf = await readElf(regionReader(path, roots, size), size, limit);
  return { ...(await digestRanges(path, roots, [[0, size]], ['sha256'])), bytes: size, ...elf };
}

/** The parse itself, over any bounded reader: a file on disk, or a native library inside an Android package. */
export async function readElf(fileBytes: (offset: number, length: number) => Promise<Buffer>, size: number, limit: number) {
  const ident = await fileBytes(0, Math.min(size, 64));
  if (ident.length < 52 || ident.readUInt32BE(0) !== 0x7f454c46) throw new Error('Expected an ELF file (no \\x7fELF magic).');
  const wide = ident[4] === 2, big = ident[5] === 2;
  if (![1, 2].includes(ident[4]) || ![1, 2].includes(ident[5]) || (wide && ident.length < 64)) throw new Error('Unknown ELF class or byte order.');
  const u16 = (b: Buffer, o: number) => big ? b.readUInt16BE(o) : b.readUInt16LE(o);
  const u32 = (b: Buffer, o: number) => big ? b.readUInt32BE(o) : b.readUInt32LE(o);
  const big64 = (b: Buffer, o: number) => big ? b.readBigUInt64BE(o) : b.readBigUInt64LE(o);
  /** An address-sized field as bigint (addresses are reported exactly). */
  const addr = (b: Buffer, o: number) => wide ? big64(b, o) : BigInt(u32(b, o));
  /** An address-sized offset or size; anything past 2^53 is refused by the region reader. */
  const word = (b: Buffer, o: number) => Number(addr(b, o));
  const W = wide ? 8 : 4;

  const type = u16(ident, 16), machine = u16(ident, 18), flags = u32(ident, 24 + 3 * W);
  const phoff = word(ident, 24 + W), shoff = word(ident, 24 + 2 * W), at = 28 + 3 * W;
  const phentsize = u16(ident, at + 2), phnum = u16(ident, at + 4), shentsize = u16(ident, at + 6), shnum = u16(ident, at + 8);
  const shstrndx = u16(ident, at + 10);
  if (phnum > MAX_SEGMENTS || shnum > MAX_SECTIONS || (phnum && phentsize < (wide ? 56 : 32)) || (shnum && shentsize < (wide ? 64 : 40))) {
    throw new Error('Invalid ELF header bounds.');
  }

  const phdrs = await fileBytes(phoff, phnum * phentsize);
  const segments = Array.from({ length: phnum }, (_, i) => {
    const o = i * phentsize;
    // Elf64_Phdr puts p_flags second; Elf32_Phdr puts it seventh.
    return wide
      ? { type: u32(phdrs, o), flags: u32(phdrs, o + 4), offset: word(phdrs, o + 8), vaddr: addr(phdrs, o + 16), filesz: word(phdrs, o + 32), memsz: word(phdrs, o + 40), align: word(phdrs, o + 48) }
      : { type: u32(phdrs, o), flags: u32(phdrs, o + 24), offset: word(phdrs, o + 4), vaddr: addr(phdrs, o + 8), filesz: word(phdrs, o + 16), memsz: word(phdrs, o + 20), align: word(phdrs, o + 28) };
  });
  const segment = (t: number) => segments.find(s => s.type === t);
  /** File offset of a virtual address, through the PT_LOAD segment that maps it. */
  function offsetOf(vaddr: bigint, length: number) {
    const s = segments.find(s => s.type === 1 && vaddr >= s.vaddr && vaddr + BigInt(length) <= s.vaddr + BigInt(s.filesz));
    if (!s) throw new Error('Address is not backed by file data.');
    return s.offset + Number(vaddr - s.vaddr);
  }

  // The loader never reads section headers and packers corrupt them, so a table outside the file is ignored, not fatal.
  const sectionsOutside = shnum > 0 && shoff + shnum * shentsize > size;
  const shdrs = shnum && !sectionsOutside ? await fileBytes(shoff, shnum * shentsize) : Buffer.alloc(0);
  const rawSections = Array.from({ length: sectionsOutside ? 0 : shnum }, (_, i) => {
    const o = i * shentsize;
    return { nameAt: u32(shdrs, o), type: u32(shdrs, o + 4), flags: word(shdrs, o + 8), offset: word(shdrs, o + 8 + 2 * W),
      size: word(shdrs, o + 8 + 3 * W), entsize: word(shdrs, o + 16 + 5 * W) };
  });
  const shstr = rawSections[shstrndx] && rawSections[shstrndx].size <= MAX_STRINGS && rawSections[shstrndx].offset + rawSections[shstrndx].size <= size
    ? await fileBytes(rawSections[shstrndx].offset, rawSections[shstrndx].size) : Buffer.alloc(0);
  const cstr = (b: Buffer, o: number) => o < b.length ? b.toString('utf8', o, b.indexOf(0, o) < 0 ? b.length : b.indexOf(0, o)) : '';
  const sections = rawSections.map(s => ({ ...s, name: cstr(shstr, s.nameAt) }));
  const sectionBytes = async (name: string, max: number) => {
    const s = sections.find(s => s.name === name && s.type !== 8);
    // Optional sections only; one that points outside the file is treated as absent.
    return s && s.offset + Math.min(s.size, max) <= size ? fileBytes(s.offset, Math.min(s.size, max)) : null;
  };

  const interpSeg = segment(3);
  const interpreter = interpSeg ? cstr(await fileBytes(interpSeg.offset, Math.min(interpSeg.filesz, 4096)), 0) : null;

  // Dynamic table: tag/value pairs, address-sized.
  const dynSeg = segment(2);
  const dyn = new Map<number, bigint[]>();
  if (dynSeg) {
    const bytes = await fileBytes(dynSeg.offset, Math.min(dynSeg.filesz, MAX_DYNAMIC * 2 * W));
    for (let o = 0; o + 2 * W <= bytes.length; o += 2 * W) {
      const tag = Number(addr(bytes, o));
      if (tag === 0) break;
      dyn.set(tag, [...(dyn.get(tag) ?? []), addr(bytes, o + W)]);
    }
  }
  const one = (tag: number) => dyn.get(tag)?.[0];
  const strtabAt = one(DT.strtab), strsz = Number(one(DT.strsz) ?? 0n);
  if (strsz > MAX_STRINGS) throw new Error('Refusing an oversized dynamic string table.');
  const dynstr = strtabAt !== undefined && strsz ? await fileBytes(offsetOf(strtabAt, strsz), strsz) : Buffer.alloc(0);
  const dstr = (v?: bigint) => v === undefined ? null : cstr(dynstr, Number(v));

  // Symbol versions: verneed names what each needed library must provide, verdef what this object provides.
  const versionNames = new Map<number, { name: string; library: string | null }>();
  const versionsNeeded = [];
  const verneedAt = one(DT.verneed);
  for (let i = 0, o = verneedAt === undefined ? -1 : offsetOf(verneedAt, 16); o >= 0 && i < Math.min(Number(one(DT.verneednum) ?? 0n), MAX_VERSIONS); i++) {
    const vn = await fileBytes(o, 16);
    const library = cstr(dynstr, u32(vn, 4)), versions = [];
    for (let k = 0, a = o + u32(vn, 8); k < Math.min(u16(vn, 2), MAX_VERSIONS); k++) {
      const aux = await fileBytes(a, 16);
      const name = cstr(dynstr, u32(aux, 8));
      versionNames.set(u16(aux, 6) & 0x7fff, { name, library });
      versions.push(name);
      a += u32(aux, 12);
    }
    versionsNeeded.push({ library, versions });
    o = u32(vn, 12) ? o + u32(vn, 12) : -1;
  }
  const versionsDefined = [];
  const verdefAt = one(DT.verdef);
  for (let i = 0, o = verdefAt === undefined ? -1 : offsetOf(verdefAt, 20); o >= 0 && i < Math.min(Number(one(DT.verdefnum) ?? 0n), MAX_VERSIONS); i++) {
    const vd = await fileBytes(o, 20);
    const name = cstr(dynstr, u32(await fileBytes(o + u32(vd, 12), 8), 0));
    // The BASE definition names the file itself (its soname), not a version.
    if (!(u16(vd, 2) & 1)) versionsDefined.push(name);
    versionNames.set(u16(vd, 4), { name, library: null });
    o = u32(vd, 16) ? o + u32(vd, 16) : -1;
  }

  // Dynamic symbol count: the .dynsym section when present, else DT_HASH nchain, else walk DT_GNU_HASH.
  const symtabAt = one(DT.symtab), syment = Number(one(DT.syment) ?? BigInt(wide ? 24 : 16));
  let symbolCount = 0;
  const dynsym = sections.find(s => s.type === 11);
  if (dynsym && dynsym.entsize) symbolCount = dynsym.size / dynsym.entsize;
  else if (one(DT.hash) !== undefined) symbolCount = u32(await fileBytes(offsetOf(one(DT.hash)!, 8), 8), 4);
  else if (one(DT.gnuHash) !== undefined) {
    const base = offsetOf(one(DT.gnuHash)!, 16), h = await fileBytes(base, 16);
    const nbuckets = u32(h, 0), symoffset = u32(h, 4), bloom = u32(h, 8);
    if (nbuckets > MAX_SYMBOLS) throw new Error('Invalid GNU hash table.');
    const bucketsAt = base + 16 + bloom * W, buckets = await fileBytes(bucketsAt, nbuckets * 4);
    let last = 0;
    for (let i = 0; i < nbuckets; i++) last = Math.max(last, u32(buckets, i * 4));
    if (last >= symoffset) {
      const chainAt = bucketsAt + nbuckets * 4;
      while (last < MAX_SYMBOLS && !(u32(await fileBytes(chainAt + (last - symoffset) * 4, 4), 0) & 1)) last++;
    }
    symbolCount = Math.max(last + 1, symoffset);
  }
  if (!Number.isSafeInteger(symbolCount) || symbolCount > MAX_SYMBOLS) throw new Error('Refusing an oversized symbol table.');

  const imports = { count: 0, symbols: [] as object[] }, exports = { count: 0, symbols: [] as object[] };
  // Hardening checks look at every import name, not just the ones shown.
  const importNames = new Set<string>();
  if (symtabAt !== undefined && symbolCount > 1) {
    const table = await fileBytes(offsetOf(symtabAt, symbolCount * syment), symbolCount * syment);
    const versym = one(DT.versym) !== undefined ? await fileBytes(offsetOf(one(DT.versym)!, symbolCount * 2), symbolCount * 2) : null;
    for (let i = 1; i < symbolCount; i++) {
      const o = i * syment;
      const [info, other, shndx, value, symSize] = wide
        ? [table[o + 4], table[o + 5], u16(table, o + 6), big64(table, o + 8), big64(table, o + 16)]
        : [table[o + 12], table[o + 13], u16(table, o + 14), BigInt(u32(table, o + 4)), BigInt(u32(table, o + 8))];
      const name = cstr(dynstr, u32(table, o)), bind = info >> 4;
      if (!name || bind === 0) continue;
      const v = versym ? versionNames.get(u16(versym, i * 2) & 0x7fff) : undefined;
      const base = { name, type: SYMBOL_TYPES[info & 0xf] ?? info & 0xf, bind: BINDS[bind] ?? bind, version: v?.name ?? null };
      if (shndx === 0) {
        importNames.add(name);
        if (imports.count++ < limit) imports.symbols.push({ ...base, library: v?.library ?? null });
      } else if ((other & 3) === 0 || (other & 3) === 3) {
        if (exports.count++ < limit) exports.symbols.push({ ...base, address: hex(value), size: Number(symSize) });
      }
    }
  }

  // Notes, read from PT_NOTE so they survive section stripping.
  let buildId = null, abiTag = null, branchProtection: string[] | null = null;
  for (const s of segments.filter(s => s.type === 4)) {
    const notes = await fileBytes(s.offset, Math.min(s.filesz, 64 * 1024));
    const align = s.align === 8 ? 8 : 4, pad = (n: number) => (n + align - 1) & -align;
    for (let o = 0; o + 12 <= notes.length;) {
      const namesz = u32(notes, o), descsz = u32(notes, o + 4), noteType = u32(notes, o + 8);
      const descAt = o + pad(12 + namesz);
      if (descAt + descsz > notes.length) break;
      const desc = notes.subarray(descAt, descAt + descsz);
      if (notes.toString('latin1', o + 12, o + 12 + namesz) === 'GNU\0') {
        if (noteType === 3) buildId = desc.toString('hex');
        if (noteType === 1 && descsz >= 16) abiTag = { os: ['linux', 'gnu', 'solaris', 'freebsd'][u32(desc, 0)] ?? u32(desc, 0), minKernel: `${u32(desc, 4)}.${u32(desc, 8)}.${u32(desc, 12)}` };
        for (let p = 0; noteType === 5 && p + 8 <= desc.length; p += (8 + u32(desc, p + 4) + W - 1) & -W) {
          const bits = FEATURES[u32(desc, p)];
          if (bits && u32(desc, p + 4) >= 4) branchProtection = bits.filter(([bit]) => u32(desc, p + 8) & bit).map(([, name]) => name);
        }
      }
      o = descAt + pad(descsz);
    }
  }

  const dtFlags = Number(one(DT.flags) ?? 0n), dtFlags1 = Number(one(DT.flags1) ?? 0n);
  const bindNow = dyn.has(DT.bindNow) || !!(dtFlags & 8) || !!(dtFlags1 & 1);
  const stack = segment(0x6474e551);
  const comment = await sectionBytes('.comment', 4096);
  const debugLink = await sectionBytes('.gnu_debuglink', 4096);
  const soname = dstr(one(DT.soname));
  // libc.so.6 carries an interpreter too; a soname without the PIE flag marks a library.
  const kind = type === 3 ? (dtFlags1 & 0x08000000 || (interpreter && !soname) ? 'pie-executable' : 'shared-object')
    : ({ 1: 'relocatable', 2: 'executable', 4: 'core' } as Record<number, string>)[type] ?? hex(type);
  const access = (f: number) => `${f & 4 ? 'r' : '-'}${f & 2 ? 'w' : '-'}${f & 1 ? 'x' : '-'}`;
  return {
    class: wide ? 'ELF64' : 'ELF32', endian: big ? 'big' : 'little', osAbi: OS_ABI[ident[7]] ?? ident[7], type: kind,
    machine: MACHINES[machine] ?? hex(machine),
    // 32-bit ARM keeps its EABI version and float ABI in e_flags.
    armAbi: machine === 0x28 ? { eabiVersion: flags >>> 24, floatAbi: flags & 0x400 ? 'hard' : flags & 0x200 ? 'soft' : null } : null,
    entryPoint: hex(addr(ident, 24)), interpreter, soname,
    needed: (dyn.get(DT.needed) ?? []).map(v => dstr(v)), rpath: dstr(one(DT.rpath)), runpath: dstr(one(DT.runpath)),
    buildId, abiTag, versionsNeeded, versionsDefined,
    hardening: { pie: kind === 'pie-executable', relro: segment(0x6474e552) ? (bindNow ? 'full' : 'partial') : 'none', bindNow,
      nxStack: stack ? !(stack.flags & 1) : null, stackProtector: importNames.has('__stack_chk_fail') || importNames.has('__stack_chk_guard'),
      fortified: [...importNames].some(n => n.endsWith('_chk') && n !== '__stack_chk_fail'),
      textRelocations: dyn.has(DT.textrel) || !!(dtFlags & 4), branchProtection },
    segments: segments.map(s => ({ type: SEGMENTS[s.type] ?? hex(s.type), access: access(s.flags), offset: s.offset,
      vaddr: hex(s.vaddr), fileBytes: s.filesz, memoryBytes: s.memsz })),
    sectionCount: rawSections.length, sectionHeadersOutsideFile: sectionsOutside,
    sections: sections.slice(1, limit + 1).map(s => ({ name: s.name, type: SECTION_TYPES[s.type] ?? hex(s.type),
      access: `${s.flags & 2 ? 'r' : '-'}${s.flags & 1 ? 'w' : '-'}${s.flags & 4 ? 'x' : '-'}`, offset: s.offset, bytes: s.size })),
    stripped: !sections.some(s => s.type === 2), debugInfo: sections.some(s => s.name === '.debug_info'),
    debugLink: debugLink ? cstr(debugLink, 0) : null,
    compiler: comment ? [...new Set(comment.toString('utf8').split('\0').filter(Boolean))] : [],
    imports, exports,
  };
}
