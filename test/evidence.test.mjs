// Evidence contract checks | Chibitek Engineering | 2026-10-31
// Run: npm test. Generated test scaffolding stays in temporary folders.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, realpath, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { inspectWorkflowEvidence, readVisualEvidence } from '../dist/evidence.js';
import { inspectMachO } from '../dist/inspect.js';
import { hostOf } from '../dist/strings.js';
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64');
const sha = b => createHash('sha256').update(b).digest('hex');
const date = '2026-10-31T12:00:00Z';
const asset = id => ({ id, kind: 'screenshot', path: `${id}.png`, capturedAt: date, source: 'Test-only capture', sha256: sha(png), privacyReviewed: true });
function ledger() {
  return { version: 1, target: 'Example Player', targetVersion: 'test', capturedAt: date, privacyReviewed: true,
    evidence: [asset('before'), asset('after')],
    claims: [{ id: 'visible', label: 'OBSERVED-LIVE', statement: 'Test-only screen observation', evidence: ['before'] }],
    workflows: [{ id: 'navigate', name: 'Navigate', status: 'tested', steps: [{ action: 'Open view', before: 'before', after: 'after', result: 'View visible', outcome: 'passed' }] }],
    features: [{ id: 'view', name: 'View', claims: ['visible'], workflows: ['navigate'], acceptance: 'View opens', improvement: 'Proposal: clarify state', friction: 'UNKNOWN' }] };
}

test('Apple subtype and URL authority regressions', () => {
  const b = Buffer.alloc(32); b.writeUInt32LE(0xfeedfacf); b.writeUInt32LE(0x0100000c, 4);
  for (const [subtype, expected] of [[0, 'arm64'], [0x80000002, 'arm64e'], [0x8000000c, 'arm64e.x1'], [99, 'arm64-subtype:99']]) {
    b.writeUInt32LE(subtype, 8); assert.equal(inspectMachO(b).architecture, expected);
  }
  for (const url of ['https://%@/path', 'https://%s/path', 'https://{host}/path', 'https://', 'https://%1$s/path']) assert.equal(hostOf(url), null);
  assert.equal(hostOf('https://EXAMPLE.com:443/%s'), 'example.com');
  assert.equal(hostOf('https://name@example.com/a'), 'example.com');
  assert.equal(hostOf('https://[::1]:443/a'), '[::1]');
});

test('evidence references, privacy, coverage, file integrity and roots fail closed', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-evidence-')));
  const path = join(root, 'ledger.json');
  const run = async manifest => { await writeFile(path, JSON.stringify(manifest)); return inspectWorkflowEvidence(path, [root]); };
  try {
    await writeFile(join(root, 'before.png'), png); await writeFile(join(root, 'after.png'), png);
    const report = await run(ledger());
    assert.equal(report.coverage.completeForDeclaredWorkflows, true);
    assert.equal(report.coverage.claims['OBSERVED-LIVE'], 1);
    assert.equal(report.evidence[0].details.width, 1);
    assert.equal((await readVisualEvidence(join(root, 'before.png'), [root], sha(png))).data, png.toString('base64'));
    for (const mutate of [
      m => { m.privacyReviewed = false; },
      m => { m.evidence[0].privacyReviewed = false; },
      m => { m.claims[0].evidence = ['missing']; },
      m => { m.claims[0].evidence = []; },
      m => { m.claims[0].supports = ['visible']; },
      m => { m.evidence.push(m.evidence[0]); },
      m => { m.evidence[0].sha256 = '0'.repeat(64); },
      m => { m.workflows[0].steps[0].outcome = 'blocked'; },
      m => { m.workflows[0].steps = []; },
      m => { m.workflows[0].steps[0].after = 'before'; },
      m => { m.features[0].workflows = ['missing']; },
      m => { m.features[0].claims = []; },
      m => { m.evidence[0].path = '/etc/hosts'; },
    ]) { const m = ledger(); mutate(m); await assert.rejects(run(m)); }
    const untested = ledger(); untested.workflows.push({ id: 'play', name: 'Play', status: 'untested', reason: 'Not attempted', steps: [] });
    assert.equal((await run(untested)).coverage.completeForDeclaredWorkflows, false);
    const blocked = ledger(); blocked.workflows[0].status = 'blocked'; blocked.workflows[0].reason = 'Input refused'; blocked.workflows[0].steps[0].outcome = 'blocked';
    assert.equal((await run(blocked)).coverage.workflows.blocked, 1);
    await symlink('/etc/hosts', join(root, 'escape')); const escaped = ledger(); escaped.evidence[0].path = 'escape'; await assert.rejects(run(escaped), /outside/);
    await assert.rejects(readVisualEvidence(join(root, 'before.png'), [root], '0'.repeat(64)), /changed/);
    await writeFile(join(root, 'before.png'), Buffer.from('<svg/>')); await assert.rejects(run(ledger()), /changed/);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('new MCP tools return reviewed evidence and images without networking; errors hide content', async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'rp-evidence-stdio-')));
  const transport = new StdioClientTransport({ command: process.execPath,
    args: ['--import', resolve('scripts/network-guard.mjs'), resolve('dist/server.js'), '--root', root],
    env: { PATH: '/usr/bin:/bin', HOME: root }, stderr: 'pipe' });
  let stderr = ''; transport.stderr?.on('data', b => { stderr += b; });
  const client = new Client({ name: 'evidence-test', version: '1' });
  try {
    await writeFile(join(root, 'before.png'), png); await writeFile(join(root, 'after.png'), png);
    await writeFile(join(root, 'ledger.json'), JSON.stringify(ledger()));
    await client.connect(transport);
    const report = await client.callTool({ name: 'inspect_workflow_evidence', arguments: { path: join(root, 'ledger.json') } });
    assert(!report.isError); assert.equal(JSON.parse(report.content[0].text).coverage.workflows.tested, 1);
    const visual = await client.callTool({ name: 'inspect_visual_evidence', arguments: { path: join(root, 'before.png'), privacyReviewed: true, sha256: sha(png) } });
    assert(!visual.isError); assert.equal(visual.content[1].type, 'image');
    await writeFile(join(root, 'ledger.json'), '{private-test-content');
    const error = await client.callTool({ name: 'inspect_workflow_evidence', arguments: { path: join(root, 'ledger.json') } });
    assert(error.isError); assert.doesNotMatch(JSON.stringify(error), /private-test-content/);
  } finally { await client.close(); await rm(root, { recursive: true, force: true }); }
  assert.match(stderr, /networkAttempts=0/);
});
