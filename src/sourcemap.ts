import { dirname, isAbsolute, resolve } from 'node:path';
import { z } from 'zod';
import { readArtifact } from './inspect.js';

// One recovered original file is returned whole up to this size; larger ones are cut.
const MAX_SOURCE_CHARS = 1024 * 1024;
const LINK = /[#@][ \t]*sourceMappingURL=([^\s'"*]+)/g;
const PACKAGE = /node_modules\/((?:@[^/]+\/)?[^/]+)/;

const mapSchema = z.object({
  version: z.literal(3),
  file: z.string().optional(),
  sourceRoot: z.string().optional(),
  sources: z.array(z.string().nullable()).max(200000),
  sourcesContent: z.array(z.string().nullable()).optional(),
  names: z.array(z.string()).optional(),
  mappings: z.string(),
});
const indexSchema = z.object({
  version: z.literal(3),
  file: z.string().optional(),
  sections: z.array(z.object({ map: mapSchema })).max(10000),
});

type Linked = { origin: 'file' | 'inline'; json: string } | { origin: 'remote'; url: string } | null;

/** Find the map a script points at. Remote URLs are reported, never fetched. */
async function linkedMap(path: string, text: string, roots: string[]): Promise<Linked> {
  if (path.endsWith('.map')) return { origin: 'file', json: text };
  const url = [...text.matchAll(LINK)].at(-1)?.[1];
  if (!url) return null;
  if (url.startsWith('data:')) {
    const comma = url.indexOf(',');
    if (comma < 0) throw new Error('Malformed inline source map.');
    const meta = url.slice(5, comma), payload = url.slice(comma + 1);
    const json = meta.endsWith(';base64') ? Buffer.from(payload, 'base64').toString('utf8') : decodeURIComponent(payload);
    return { origin: 'inline', json };
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(url) || url.startsWith('//')) return { origin: 'remote', url };
  const relativePath = decodeURIComponent(url.replace(/[?#].*$/, ''));
  if (isAbsolute(relativePath)) throw new Error('Refusing an absolute source map link.');
  // The root allowlist in readArtifact still applies to wherever this resolves.
  const mapBytes = await readArtifact(resolve(dirname(path), relativePath), roots);
  return { origin: 'file', json: mapBytes.toString('utf8') };
}

/** Index maps nest whole maps in sections; flatten them into one list of sources. */
function flatten(raw: unknown) {
  const index = indexSchema.safeParse(raw);
  const maps = index.success ? index.data.sections.map(s => s.map) : [mapSchema.parse(raw)];
  const sources: { path: string; content: string | null }[] = [];
  let names = 0;
  for (const map of maps) {
    const prefix = map.sourceRoot ? map.sourceRoot.replace(/\/?$/, '/') : '';
    map.sources.forEach((source, i) => {
      if (source !== null) sources.push({ path: prefix + source, content: map.sourcesContent?.[i] ?? null });
    });
    names += map.names?.length ?? 0;
  }
  return { file: index.success ? index.data.file : maps[0].file, sections: index.success ? maps.length : null, sources, names };
}

export async function inspectSourceMap(path: string, roots: string[], limit = 200, source?: string) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 5000) throw new Error('Refusing an out-of-range limit.');
  const linked = await linkedMap(path, (await readArtifact(path, roots)).toString('utf8'), roots);
  if (!linked) return { linked: false };
  if (linked.origin === 'remote') return { linked: true, origin: 'remote', sourceMappingUrl: linked.url, fetched: false };

  // Some servers prefix maps with an XSSI guard line.
  const { file, sections, sources, names } = flatten(JSON.parse(linked.json.replace(/^\)\]\}'[^\n]*\n/, '')));
  const packages = new Map<string, number>();
  for (const { path: p } of sources) {
    const name = PACKAGE.exec(p)?.[1];
    if (name) packages.set(name, (packages.get(name) ?? 0) + 1);
  }
  const recovered = source === undefined ? undefined : sources.find(s => s.path === source || s.path.endsWith(`/${source}`));
  if (source !== undefined && !recovered) throw new Error('Source not listed in this map.');
  return {
    linked: true, origin: linked.origin, file: file ?? null, sections, names,
    sourceCount: sources.length,
    sourcesWithContent: sources.filter(s => s.content !== null).length,
    packages: [...packages].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([name, files]) => ({ name, files })),
    sources: sources.slice(0, limit).map(s => ({ path: s.path, chars: s.content?.length ?? null })),
    truncated: sources.length > limit,
    ...(recovered && {
      recovered: { path: recovered.path, content: recovered.content?.slice(0, MAX_SOURCE_CHARS) ?? null,
        truncated: (recovered.content?.length ?? 0) > MAX_SOURCE_CHARS },
    }),
  };
}
