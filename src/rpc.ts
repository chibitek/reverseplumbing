import { join } from 'node:path';
import { readRegion } from './inspect.js';
import { readAsar } from './asar.js';

// Total bytes of bundled script read while hunting for service descriptors.
const MAX_SCAN_BYTES = 48 * 1024 * 1024;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const SCRIPT = /\.(?:js|mjs|cjs)$/;

// FieldDescriptorProto.Type, the numbering a protobuf descriptor uses on the wire.
const SCALARS: Record<string, string> = {
  1: 'double', 2: 'float', 3: 'int64', 4: 'uint64', 5: 'int32', 6: 'fixed64',
  7: 'fixed32', 8: 'bool', 9: 'string', 12: 'bytes', 13: 'uint32', 14: 'enum',
  15: 'sfixed32', 16: 'sfixed64', 17: 'sint32', 18: 'sint64',
};

// A generated message class binds its own compact descriptor and the list of
// other classes its message-typed fields point at:
//   <ident>=class e extends X{ ... static $(){return["Name|1 field 9",<dep>,...]}}
const CLASS = /(\w+)\s*=\s*class\s+\w*\s*extends\s+\w+\s*\{[\s\S]{0,4000}?static\s+\$\(\)\s*\{\s*return\s*\[\s*"((?:[^"\\]|\\.)*)"((?:\s*,\s*\w+)*)\s*\]/g;
const SERVICE = /typeName\s*:\s*"([^"]+)"\s*,\s*methods\s*:\s*\{/g;
const METHOD = /(\w+)\s*:\s*\{\s*name\s*:\s*"([^"]+)"\s*,\s*I\s*:\s*(\w+)\s*,\s*O\s*:\s*(\w+)\s*,\s*kind\s*:\s*[\w.]*?\.?(\w+)\s*\}/g;

type Message = { name: string; fields: Field[] };
type Field = { number: number; name: string; type: string; repeated: boolean; optional: boolean };

// "Name|1 store_id 9|8 repo_urls 9*|9 shares #0*" -> the message and its fields.
// A '#n' type is the nth entry of that class's dependency list.
function parseDescriptor(descriptor: string, deps: string[], named: Map<string, string>): Message {
  const [name, ...rest] = descriptor.split('|');
  const fields: Field[] = [];
  for (const part of rest) {
    const match = /^(\d+)\s+(\S+)\s+(\S+)$/.exec(part.trim());
    if (!match) continue;
    const [, number, fieldName, raw] = match;
    const repeated = raw.endsWith('*');
    const optional = raw.endsWith('?');
    const code = raw.replace(/[?*]$/, '');
    let type: string;
    if (code.startsWith('#')) {
      const dep = deps[Number(code.slice(1))];
      type = (dep && named.get(dep)) ?? 'unresolved';
    } else {
      type = SCALARS[code] ?? `type${code}`;
    }
    fields.push({ number: Number(number), name: fieldName, type, repeated, optional });
  }
  return { name, fields };
}

function scanBody(body: string, messages: Map<string, Message>, services: Map<string, { method: string; kind: string; input: string; output: string }[]>) {
  // Two passes: bind every class to its message name first, so a field that
  // points at a class declared later still resolves.
  const raw = new Map<string, { descriptor: string; deps: string[] }>();
  const named = new Map<string, string>();
  for (const [, ident, descriptor, depList] of body.matchAll(CLASS)) {
    const deps = depList ? depList.split(',').map(d => d.trim()).filter(Boolean) : [];
    raw.set(ident, { descriptor, deps });
    named.set(ident, descriptor.split('|')[0]);
  }
  for (const [ident, { descriptor, deps }] of raw) {
    const message = parseDescriptor(descriptor, deps, named);
    messages.set(ident, message);
  }

  for (const match of body.matchAll(SERVICE)) {
    const service = match[1];
    // The methods object runs to its closing brace; scan a bounded window of it.
    const from = match.index! + match[0].length;
    const window = body.slice(from, from + 64 * 1024);
    const methods = [...window.matchAll(METHOD)].map(([, , method, input, output, kind]) => ({
      method, kind, input: named.get(input) ?? 'unresolved', output: named.get(output) ?? 'unresolved',
    }));
    // The same generated service shows up in several bundles. Keep one of each.
    if (!methods.length) continue;
    const merged = services.get(service) ?? [];
    const seen = new Set(merged.map(m => m.method));
    for (const call of methods) if (!seen.has(call.method)) { seen.add(call.method); merged.push(call); }
    services.set(service, merged);
  }
}

export async function inspectElectronRpc(appPath: string, roots: string[], limit = 400) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) {
    throw new Error('Refusing an out-of-range limit.');
  }
  const asarPath = appPath.endsWith('.asar') ? appPath : join(appPath, 'Contents/Resources/app.asar');
  const { entries, baseOffset } = await readAsar(asarPath, roots);

  const messages = new Map<string, Message>();
  const services = new Map<string, { method: string; kind: string; input: string; output: string }[]>();
  let scanned = 0, scannedFiles = 0;
  for (const entry of entries.filter(e => SCRIPT.test(e.path)).sort((a, b) => b.bytes - a.bytes)) {
    if (entry.offset === null || entry.bytes > MAX_FILE_BYTES) continue;
    if (scanned + entry.bytes > MAX_SCAN_BYTES) continue;
    const body = (await readRegion(asarPath, roots, baseOffset + entry.offset, entry.bytes)).toString('utf8');
    scanned += entry.bytes;
    scannedFiles++;
    if (!body.includes('methods:') && !body.includes('static $()')) continue;
    scanBody(body, messages, services);
  }

  const byName = new Map<string, Message>();
  for (const message of messages.values()) if (message.name) byName.set(message.name, message);

  // Only the messages the service surface actually reaches, followed through
  // their own message-typed fields. The rest are internal to the bundle.
  const reached = new Set<string>();
  const queue = [...services.values()].flat().flatMap(m => [m.input, m.output]);
  while (queue.length && reached.size < limit) {
    const name = queue.shift()!;
    if (reached.has(name) || !byName.has(name)) continue;
    reached.add(name);
    for (const field of byName.get(name)!.fields) if (byName.has(field.type)) queue.push(field.type);
  }

  return {
    archive: asarPath,
    services: [...services].sort().map(([service, methods]) => ({
      service,
      methods: methods.length,
      calls: methods.sort((a, b) => a.method.localeCompare(b.method)),
    })),
    schema: [...reached].sort().map(name => byName.get(name)!),
    counts: {
      services: services.size,
      methods: [...services.values()].reduce((sum, m) => sum + m.length, 0),
      messagesFound: byName.size,
      messagesReached: reached.size,
    },
    truncated: reached.size >= limit && byName.size > reached.size,
    scan: { files: scannedFiles, bytes: scanned, complete: scanned < MAX_SCAN_BYTES },
    limits: 'Reads generated descriptors out of bundled script. Names are the ones the build kept, not a source file. A declared method is not proof the app calls it, and the schema is only what the service surface reaches.',
  };
}
