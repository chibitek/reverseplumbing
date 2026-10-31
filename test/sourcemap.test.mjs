// Source map checks | Chibitek Engineering | 2026-10-24
// Uses maps published inside installed dependencies and real compiler output, not invented maps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { inspectSourceMap } from '../dist/sourcemap.js';

const deps = await realpath('node_modules');

test('a script resolves its sibling map file and recovers original source', async () => {
  const script = join(deps, 'path-to-regexp/dist/index.js');
  const summary = await inspectSourceMap(script, [deps], 50, 'src/index.ts');
  assert.equal(summary.origin, 'file');
  assert.deepEqual(summary.sources.map(s => s.path), ['../src/index.ts']);
  assert.equal(summary.sourcesWithContent, 1);
  assert.match(summary.recovered.content, /export function pathToRegexp/);
  await assert.rejects(inspectSourceMap(script, [deps], 50, 'not-in-map.ts'), /not listed/);
});

test('an inline data: map from the TypeScript compiler is decoded', async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'rp-map-')));
  try {
    const input = await readFile(resolve('src/sourcemap.ts'), 'utf8');
    const { outputText } = ts.transpileModule(input, { fileName: 'sourcemap.ts',
      compilerOptions: { module: ts.ModuleKind.ESNext, inlineSourceMap: true, inlineSources: true } });
    await writeFile(join(dir, 'sourcemap.js'), outputText);
    const summary = await inspectSourceMap(join(dir, 'sourcemap.js'), [dir], 10, 'sourcemap.ts');
    assert.equal(summary.origin, 'inline');
    assert.equal(summary.recovered.content, input);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('remote links are reported, never fetched, and map links cannot leave the root', async () => {
  const dir = await realpath(await mkdtemp(join(tmpdir(), 'rp-map-')));
  try {
    await writeFile(join(dir, 'remote.js'), 'x();\n//# sourceMappingURL=https://cdn.invalid/app.js.map\n');
    assert.deepEqual(await inspectSourceMap(join(dir, 'remote.js'), [dir]),
      { linked: true, origin: 'remote', sourceMappingUrl: 'https://cdn.invalid/app.js.map', fetched: false });
    await writeFile(join(dir, 'escape.js'), `x();\n//# sourceMappingURL=${relative(dir, await realpath('/etc/hosts'))}\n`);
    await assert.rejects(inspectSourceMap(join(dir, 'escape.js'), [dir]), /outside/);
    await writeFile(join(dir, 'plain.js'), 'x();\n');
    assert.deepEqual(await inspectSourceMap(join(dir, 'plain.js'), [dir]), { linked: false });
  } finally { await rm(dir, { recursive: true, force: true }); }
});
