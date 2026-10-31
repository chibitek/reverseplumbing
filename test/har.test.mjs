// HAR privacy and mapping checks | Chibitek Engineering | 2026-10-30
// Run npm test. All canaries are synthetic test data, never real credentials.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { inspectHar } from '../dist/inspect.js';

const inspect = entries => inspectHar(Buffer.from(JSON.stringify({ log: { entries } })));
const entry = (url, payload, extra = {}) => ({
  request: { method: 'POST', url, postData: { mimeType: 'application/json', text: JSON.stringify(payload) } },
  response: { status: 200, content: { mimeType: 'application/json', text: JSON.stringify(payload) } },
  time: 3, ...extra,
});

test('HAR collapses IDs, separates origins, groups pages and maps JSON shapes', () => {
  const result = inspect([
    entry('https://example.com/api/v1/tasks/123?cursor=hidden', { id: 123, items: [{ name: 'hidden' }, null, true] }, { pageref: 'private-page' }),
    entry('https://example.com/api/v1/tasks/456', { id: 456 }, { pageref: 'private-page' }),
    entry('https://other.example.com/api/v1/tasks/123', { id: 123 }, { pageref: 'other-page' }),
  ]);
  assert.equal(result.endpoints.length, 2);
  assert.equal(result.endpoints[0].path, '/api/v1/tasks/:id');
  assert.equal(result.endpoints[0].count, 2);
  assert.deepEqual(result.flows.map(flow => flow.calls.map(call => call.sequence)), [[1, 2], [3]]);
  assert.equal(result.flows[0].calls[0].request.shape.properties.id, 'number');
  assert.equal(result.flows[0].calls[0].request.shape.properties.items.type, 'array');
});

test('canaries in every untrusted text surface never survive', () => {
  const canaries = ['value-canary-876', 'key-canary-876', 'host-canary-876', 'path-canary-876', 'query-canary-876', 'page-canary-876', 'header-canary-876', 'cookie-canary-876', 'scheme-canary-876'];
  const payload = { token: canaries[0], password: canaries[0], [canaries[1]]: [{ id: canaries[0] }], '__proto__': null };
  const e = entry(`https://user:pass@${canaries[2]}.example/api/users/${canaries[3]}?${canaries[4]}=${canaries[4]}#${canaries[0]}`, payload, { pageref: canaries[5] });
  e.request.headers = [{ name: 'Authorization', value: `Bearer ${canaries[6]}` }, { name: 'Cookie', value: canaries[7] }, { name: 'x-api-key', value: canaries[6] }, { name: canaries[6], value: canaries[6] }];
  e.request.cookies = [{ name: canaries[7], value: canaries[7] }];
  e.response.headers = [{ name: 'Set-Cookie', value: canaries[7] }];
  e.response.content.text = Buffer.from(JSON.stringify(payload)).toString('base64');
  e.response.content.encoding = 'base64';
  const unknownAuth = entry('invalid-' + canaries[3], payload);
  unknownAuth.request.headers = [{ name: 'Authorization', value: canaries[8] }];
  const result = inspect([e, unknownAuth]);
  for (const canary of canaries) assert.ok(!JSON.stringify(result).includes(canary), canary);
  assert.deepEqual(result.endpoints[0].authSchemes, ['api-key-header', 'bearer', 'cookie-present']);
  assert.deepEqual(result.endpoints[1].authSchemes, ['other-authorization']);
  assert.equal(result.flows[0].calls[0].response.state, 'parsed');
  assert.equal(result.flows[0].calls[0].response.shape.properties.token, 'string');
});

test('malformed and unsupported bodies report safe states; parser errors never echo input', () => {
  const e = entry('https://example.com/api', {});
  e.request.postData.text = '{"canary-bad-json":';
  e.response.content = { mimeType: 'text/html', text: 'canary-html' };
  const result = inspect([e]);
  assert.equal(result.flows[0].calls[0].request.state, 'invalid-json');
  assert.equal(result.flows[0].calls[0].response.state, 'not-json');
  assert.doesNotMatch(JSON.stringify(result), /canary/);
  assert.throws(() => inspectHar(Buffer.from('canary-invalid')), error => !error.message.includes('canary'));
  assert.throws(() => inspect([{ ...e, request: { method: 'canary-method' } }]), error => !error.message.includes('canary'));
});

test('bounds are explicit for deep shapes, arrays and large captures', () => {
  let payload = { id: 'hidden' };
  for (let i = 0; i < 20; i++) payload = { items: [payload] };
  const result = inspect(Array.from({ length: 1001 }, () => entry('https://example.com/api', payload)));
  assert.equal(result.entries, 1001);
  assert.equal(result.detailedEntries, 1000);
  assert.equal(result.omittedEntries, 1);
  assert.equal(result.flows[0].calls[0].response.truncated, true);
  assert.equal(inspect([entry('https://example.com', Array(21).fill(null))]).flows[0].calls[0].response.truncated, true);
});

test('HAR runs through the real stdio server without network or canary disclosure', async () => {
  const root = await mkdtemp(join(tmpdir(), 'har-proof-'));
  try {
    const path = join(root, 'session.har');
    await writeFile(path, JSON.stringify({ log: { entries: [entry('https://example.com/api/tasks/987?token=stdio-canary', { token: 'stdio-canary' })] } }));
    const output = execFileSync(process.execPath, ['scripts/prove-stdio.mjs', path], { encoding: 'utf8' });
    assert.match(output, /networkAttempts=0/);
    assert.match(output, /inspect_browser_har/);
    assert.match(output, /endpoint-1/);
    assert.doesNotMatch(output, /stdio-canary/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
