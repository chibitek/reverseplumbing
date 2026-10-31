import { machOSections, readMachO, readRegion } from './inspect.js';

// Sections that hold readable text. __text is instructions and __const is
// mostly packed binary, so neither repays being read as strings.
const TEXT_SECTIONS = ['__cstring', '__objc_classname', '__objc_methname', '__swift5_reflstr'];
const MAX_SECTION_BYTES = 8 * 1024 * 1024;
const MIN_STRING = 4;

const URL = /^(?:https?|wss?):\/\/[^\s"'<>\\]+$/;
// Deliberately narrow: an API route, not every absolute filesystem path.
const ENDPOINT = /^\/(?:api|v[0-9]+|graphql|rest|auth|oauth|rpc|ws)(?:\/[^\s"'<>\\]*)?$/;

const LIMITS = 'Reads named text sections only. A string in the binary is not proof the app uses it, and strings built at runtime are not visible here.';

function splitStrings(region: Buffer) {
  const out: string[] = [];
  let start = 0;
  for (let i = 0; i <= region.length; i++) {
    if (i < region.length && region[i] !== 0) continue;
    if (i - start >= MIN_STRING) {
      const text = region.subarray(start, i).toString('utf8');
      // Keep text, drop packed binary that happens to sit between NULs.
      if (!/[\u0000-\u0008\u000e-\u001f�]/.test(text)) out.push(text);
    }
    start = i + 1;
  }
  return out;
}

function hostOf(url: string) {
  const after = url.indexOf('://') + 3;
  const end = url.slice(after).search(/[\/:?#]/);
  return (end < 0 ? url.slice(after) : url.slice(after, after + end)).toLowerCase();
}

type Slice = { offset: number; prefix: Buffer };

/**
 * Classify the text sections of already-located architecture slices. The
 * caller supplies the read, so the same scan serves a Mach-O on disk and one
 * held in memory after being lifted out of an archive.
 */
export async function scanTextSections(slices: Slice[], read: (offset: number, size: number) => Promise<Buffer>, limit: number) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) {
    throw new Error('Refusing an out-of-range limit.');
  }
  const urls = new Set<string>(), hosts = new Set<string>(), endpoints = new Set<string>();
  const objcClasses = new Set<string>(), swiftFields = new Set<string>();
  const sections: { segment: string; section: string; bytes: number; strings: number; read: boolean }[] = [];
  let total = 0;

  for (const slice of slices) {
    for (const found of machOSections(slice.prefix)) {
      if (!TEXT_SECTIONS.includes(found.section)) continue;
      const readable = found.bytes > 0 && found.bytes <= MAX_SECTION_BYTES;
      sections.push({ ...found, strings: 0, read: readable } as never);
      const entry = sections[sections.length - 1];
      if (!readable) continue;

      const region = await read(slice.offset + found.fileOffset, found.bytes);
      const strings = splitStrings(region);
      entry.strings = strings.length;
      total += strings.length;

      for (const text of strings) {
        if (URL.test(text)) { urls.add(text); hosts.add(hostOf(text)); }
        else if (ENDPOINT.test(text)) endpoints.add(text);
        if (found.section === '__objc_classname') objcClasses.add(text);
        if (found.section === '__swift5_reflstr') swiftFields.add(text);
      }
    }
  }

  const cap = (set: Set<string>) => [...set].sort().slice(0, limit);
  const groups = { urls, hosts, endpoints, objcClasses, swiftFields };
  return {
    sections,
    hosts: cap(hosts),
    urls: cap(urls),
    endpoints: cap(endpoints),
    objcClasses: cap(objcClasses),
    swiftFields: cap(swiftFields),
    counts: { ...Object.fromEntries(Object.entries(groups).map(([k, v]) => [k, v.size])), strings: total },
    truncated: Object.entries(groups).filter(([, v]) => v.size > limit).map(([k]) => k),
    limits: LIMITS,
  };
}

export async function inspectStrings(path: string, roots: string[], limit = 200) {
  const { fat, slices, sha256, bytes } = await readMachO(path, roots);
  const scan = await scanTextSections(slices, (offset, size) => readRegion(path, roots, offset, size), limit);
  return { sha256, bytes, universal: fat, ...scan };
}
