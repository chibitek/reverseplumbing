import { join } from 'node:path';
import { readRegion } from './inspect.js';

const MAX_HEADER_BYTES = 8 * 1024 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
// Total bytes of bundled script read while hunting for hosts. An Electron
// bundle can be hundreds of megabytes; this keeps one call bounded.
const MAX_SCAN_BYTES = 32 * 1024 * 1024;

const URL = /\b(?:https?|wss?):\/\/[a-zA-Z0-9._~:\/?#\[\]@!$&'()*+,;=%-]+/g;
const SCRIPT = /\.(?:js|mjs|cjs|ts|json)$/;

type Entry = { path: string; bytes: number; offset: number | null; unpacked: boolean };

function walk(node: any, prefix: string, out: Entry[]) {
  for (const [name, value] of Object.entries<any>(node.files ?? {})) {
    const path = prefix ? `${prefix}/${name}` : name;
    if (value.files) { walk(value, path, out); continue; }
    out.push({
      path,
      bytes: value.size ?? 0,
      offset: value.unpacked ? null : Number(value.offset),
      unpacked: Boolean(value.unpacked),
    });
  }
}

export async function readAsar(asarPath: string, roots: string[]) {
  const head = await readRegion(asarPath, roots, 0, 16);
  if (head.readUInt32LE(0) !== 4) throw new Error('Not an asar archive.');
  const pickleBytes = head.readUInt32LE(4);
  const jsonBytes = head.readUInt32LE(12);
  if (jsonBytes > MAX_HEADER_BYTES || jsonBytes + 16 > pickleBytes + 8) {
    throw new Error('Refusing an out-of-range asar header.');
  }
  const json = await readRegion(asarPath, roots, 16, jsonBytes);
  const entries: Entry[] = [];
  walk(JSON.parse(json.toString('utf8')), '', entries);
  return { entries, baseOffset: 8 + pickleBytes };
}

async function readEntry(asarPath: string, roots: string[], base: number, entry: Entry) {
  if (entry.offset === null || entry.bytes > MAX_FILE_BYTES) return null;
  return await readRegion(asarPath, roots, base + entry.offset, entry.bytes);
}

export async function inspectElectronApp(appPath: string, roots: string[], limit = 200) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) {
    throw new Error('Refusing an out-of-range limit.');
  }
  const asarPath = appPath.endsWith('.asar') ? appPath : join(appPath, 'Contents/Resources/app.asar');
  const { entries, baseOffset } = await readAsar(asarPath, roots);

  const manifest = entries.find(e => e.path === 'package.json');
  const parsed = manifest ? JSON.parse((await readEntry(asarPath, roots, baseOffset, manifest))!.toString('utf8')) : {};

  const hosts = new Set<string>();
  let scanned = 0, scannedFiles = 0;
  // Largest scripts first: the bundles are where the endpoints live.
  for (const entry of entries.filter(e => SCRIPT.test(e.path)).sort((a, b) => b.bytes - a.bytes)) {
    if (scanned + entry.bytes > MAX_SCAN_BYTES) continue;
    const body = await readEntry(asarPath, roots, baseOffset, entry);
    if (!body) continue;
    scanned += entry.bytes;
    scannedFiles++;
    for (const found of body.toString('utf8').matchAll(URL)) {
      const after = found[0].indexOf('://') + 3;
      const end = found[0].slice(after).search(/[\/:?#]/);
      const host = (end < 0 ? found[0].slice(after) : found[0].slice(after, after + end)).toLowerCase();
      if (/^[a-z0-9.-]+\.[a-z]{2,}$|^localhost$|^127\./.test(host)) hosts.add(host);
    }
  }

  const bytes = entries.reduce((sum, e) => sum + e.bytes, 0);
  const top = new Map<string, number>();
  for (const e of entries) {
    const root = e.path.split('/')[0];
    top.set(root, (top.get(root) ?? 0) + e.bytes);
  }

  return {
    archive: asarPath,
    app: {
      name: parsed.name ?? null,
      version: parsed.version ?? null,
      main: parsed.main ?? null,
      dependencies: Object.keys(parsed.dependencies ?? {}).sort(),
      devDependencies: Object.keys(parsed.devDependencies ?? {}).length,
    },
    contents: {
      files: entries.length,
      bytes,
      unpacked: entries.filter(e => e.unpacked).length,
      topLevel: [...top].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([path, bytes]) => ({ path, bytes })),
      largest: [...entries].sort((a, b) => b.bytes - a.bytes).slice(0, 10).map(e => ({ path: e.path, bytes: e.bytes })),
    },
    hosts: [...hosts].sort().slice(0, limit),
    scan: { files: scannedFiles, bytes: scanned, complete: scanned < MAX_SCAN_BYTES },
    limits: 'Reads the archive as bytes. Nothing is extracted to disk and the app is not launched. A host in a bundle is not proof the app contacts it.',
  };
}
