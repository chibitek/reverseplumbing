// Offline HAR mapping | Chibitek Engineering | 2026-10-30
// Used by inspect_browser_har; run npm test for privacy and mapping checks.
import { z } from 'zod';

const headers = z.array(z.object({ name: z.string(), value: z.string() })).default([]);
const body = z.object({ text: z.string().optional(), mimeType: z.string().optional(), encoding: z.string().optional() }).optional();
const schema = z.object({ log: z.object({ entries: z.array(z.object({
  request: z.object({ method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']),
    url: z.string().optional(), headers, cookies: z.array(z.unknown()).default([]), postData: body }),
  response: z.object({ status: z.number().int().min(0).max(599), content: body }),
  pageref: z.string().optional(), time: z.number().finite().min(-1),
})).max(50000) }) });

// Fixed vocabulary, not a secret-pattern blacklist: arbitrary names may themselves be values.
const ROUTES = new Set('api rest graphql rpc v1 v2 v3 auth login logout session users user me teams organizations projects tasks tickets contacts accounts leads files folders documents search comments messages recordings videos upload download export settings events sync health'.split(' '));
const KEYS = new Set('id name title type status data items results errors error message code count total page limit offset cursor next previous hasMore createdAt updatedAt created_at updated_at user users project projects task tasks email url text content description enabled success metadata attributes relationships nodes edges token access_token refresh_token password secret authorization'.split(' '));

function endpoint(raw: string | undefined, origins: Map<string, string>) {
  try {
    const url = new URL(raw ?? '');
    if (!['http:', 'https:'].includes(url.protocol)) return { origin: 'unknown', path: 'unknown' };
    if (!origins.has(url.origin)) origins.set(url.origin, `origin-${origins.size + 1}`);
    const parts = url.pathname.split('/').filter(Boolean);
    return { origin: origins.get(url.origin)!, path: '/' + parts.slice(0, 32).map(part => ROUTES.has(part) ? part : ':id').join('/') + (parts.length > 32 ? '/:truncated' : '') };
  } catch { return { origin: 'unknown', path: 'unknown' }; }
}

function shape(value: unknown, budget: { remaining: number; truncated: boolean }, depth = 0): unknown {
  if (--budget.remaining < 0 || depth > 8) { budget.truncated = true; return 'truncated'; }
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    const variants = new Set<string>();
    for (const item of value.slice(0, 20)) {
      if (budget.remaining <= 0) { budget.truncated = true; break; }
      variants.add(JSON.stringify(shape(item, budget, depth + 1)));
    }
    if (value.length > 20) budget.truncated = true;
    return { type: 'array', items: [...variants].sort().map(item => JSON.parse(item)) };
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value);
    const properties: Record<string, unknown> = Object.create(null);
    let unnamed = 0;
    for (const [key, child] of entries.slice(0, 50)) {
      if (budget.remaining <= 0) { budget.truncated = true; break; }
      properties[KEYS.has(key) ? key : `field-${++unnamed}`] = shape(child, budget, depth + 1);
    }
    if (entries.length > 50) budget.truncated = true;
    return { type: 'object', properties };
  }
  return typeof value;
}

function jsonShape(content: z.infer<typeof body>) {
  if (!content?.text) return { state: 'absent' };
  if (content.text.length > 1024 * 1024) return { state: 'oversized' };
  if (content.encoding && content.encoding !== 'base64') return { state: 'unsupported-encoding' };
  if (!/(?:^|[+/])json(?:\s*;|$)/i.test(content.mimeType ?? '')) return { state: 'not-json' };
  try {
    const text = content.encoding === 'base64' ? Buffer.from(content.text, 'base64').toString('utf8') : content.text;
    const budget = { remaining: 200, truncated: false };
    const result = shape(JSON.parse(text), budget);
    return { state: 'parsed', shape: result, truncated: budget.truncated };
  } catch { return { state: 'invalid-json' }; }
}

function auth(request: z.infer<typeof schema>['log']['entries'][number]['request']) {
  const schemes = new Set<string>();
  for (const header of request.headers) {
    const name = header.name.toLowerCase();
    if (name === 'authorization' || name === 'proxy-authorization') {
      const kind = header.value.trim().split(/\s+/, 1)[0].toLowerCase();
      schemes.add(['bearer', 'basic', 'digest', 'negotiate'].includes(kind) ? kind : 'other-authorization');
    }
    if (name === 'cookie') schemes.add('cookie-present');
    if (['x-api-key', 'api-key', 'apikey'].includes(name)) schemes.add('api-key-header');
  }
  if (request.cookies.length) schemes.add('cookie-present');
  return schemes.size ? [...schemes].sort() : ['not-observed'];
}

export function inspectHar(bytes: Buffer) {
  // Bound direct callers too, not only readArtifact. Never expose JSON parser diagnostics.
  if (bytes.length > 32 * 1024 * 1024) throw new Error('HAR exceeds size limit.');
  let parsed;
  try { parsed = schema.safeParse(JSON.parse(bytes.toString('utf8'))); }
  catch { throw new Error('Invalid HAR JSON.'); }
  if (!parsed.success) throw new Error('Expected a HAR log with at most 50,000 valid entries.');
  const methods: Record<string, number> = {}, statuses: Record<string, number> = {};
  const origins = new Map<string, string>(), pages = new Map<string, string>();
  const endpoints = new Map<string, { id: string; origin: string; method: string; path: string; count: number; authSchemes: Set<string> }>();
  const flows = new Map<string, { page: string; calls: object[] }>();
  let durationMs = 0, unknownDurationCount = 0;
  const detailLimit = 1000;
  for (const [index, entry] of parsed.data.log.entries.entries()) {
    methods[entry.request.method] = (methods[entry.request.method] ?? 0) + 1;
    statuses[entry.response.status] = (statuses[entry.response.status] ?? 0) + 1;
    if (entry.time < 0) unknownDurationCount++; else durationMs += entry.time;
    if (index >= detailLimit) continue;
    const route = endpoint(entry.request.url, origins), schemes = auth(entry.request);
    const key = `${route.origin} ${entry.request.method} ${route.path}`;
    let record = endpoints.get(key);
    if (!record) {
      record = { id: `endpoint-${endpoints.size + 1}`, ...route, method: entry.request.method, count: 0, authSchemes: new Set() };
      endpoints.set(key, record);
    }
    record.count++;
    schemes.forEach(scheme => record.authSchemes.add(scheme));
    let page = 'unassigned';
    if (entry.pageref !== undefined) {
      if (!pages.has(entry.pageref)) pages.set(entry.pageref, `page-${pages.size + 1}`);
      page = pages.get(entry.pageref)!;
    }
    if (!flows.has(page)) flows.set(page, { page, calls: [] });
    flows.get(page)!.calls.push({ sequence: index + 1, endpoint: record.id, status: entry.response.status,
      request: jsonShape(entry.request.postData), response: jsonShape(entry.response.content) });
  }
  return { entries: parsed.data.log.entries.length, methods, statuses, durationMs, unknownDurationCount,
    endpoints: [...endpoints.values()].map(record => ({ ...record, authSchemes: [...record.authSchemes].sort() })),
    flows: [...flows.values()], detailedEntries: Math.min(detailLimit, parsed.data.log.entries.length),
    omittedEntries: Math.max(0, parsed.data.log.entries.length - detailLimit),
    privacy: 'Values, raw origins, headers, cookies, query strings, page names and non-vocabulary keys/path segments are omitted. No requests are replayed.',
    limits: 'Capture order per HAR pageref, not inferred causality or named user flows. Missing pageref is unassigned. Conservative routes may merge distinct endpoints; unknown keys are positional aliases. JSON shapes are sampled and bounded; missing bodies are not reconstructed. Cookie presence does not prove authentication. Counts cover all entries; endpoint counts and flows cover detailedEntries only.' };
}
