import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import { buildM89ShakedownReport } from './run-m89-shakedown.mjs';
import { materializeM89Shakedown, buildM89OfficialRun, verifyM89Shakedown } from './materialize-m89-shakedown.mjs';

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const digest = (value) => createHash('sha256').update(value).digest('hex');
const runSchema = load('./equal-relation-arithmetic-run.v1.schema.json');
const engineSchema = load('./equal-relation-arithmetic-engine-result.v1.schema.json');
const metricSchema = load('./equal-relation-arithmetic-metric-report.v1.schema.json');
const summarySchema = load('./equal-relation-arithmetic-cross-engine-summary.v1.schema.json');
const corpusBytes = readFileSync(new URL('../reference/m89-corpus.json', import.meta.url));
const corpus = JSON.parse(corpusBytes);
const root = mkdtempSync(join(tmpdir(), 'shieldkit-m89-materializer-'));
after(() => rmSync(root, { recursive: true, force: true }));

test('materializes exact seven artifacts, all schemas, and semantic run accounting', () => {
  const target = join(root, 'run');
  const report = buildM89ShakedownReport();
  assert.equal(report.status, 'measured-component-only-pass');
  const run = materializeM89Shakedown(report, target);
  const verified = verifyM89Shakedown(target);
  assert.deepEqual(verified.semanticErrors, []);
  assert.equal(run.trackId, 'track:canonical-schoolbook');
  assert.equal(run.trackPosition, 1);
  assert.equal(run.selection, 'none');
  assert.equal(run.artifacts.length, 7);
  assert.equal(run.corpus.digest, digest(corpusBytes));

  const ajv = new Ajv2020({ allErrors: true, strict: true });
  assert.equal(ajv.compile(runSchema)(run), true);
  for (const name of ['native', 'libauth', 'bchn', 'leanbch']) assert.equal(ajv.compile(engineSchema)(JSON.parse(readFileSync(join(target, `artifacts/${name}-result.json`)))), true);
  const metric = JSON.parse(readFileSync(join(target, 'artifacts/metric-report.json')));
  const summary = JSON.parse(readFileSync(join(target, 'artifacts/cross-engine-summary.json')));
  assert.equal(ajv.compile(metricSchema)(metric), true);
  assert.equal(ajv.compile(summarySchema)(summary), true);
  assert.equal(metric.cells.length, 4 * corpus.cases.length * 15);
  assert.equal(summary.cases.length, corpus.cases.length);
  assert.equal(summary.metricAgreements.length, corpus.cases.length * 15);
  assert.equal(metric.cells.some((cell) => cell.metricId === 'vmCost' && cell.engineId === 'engine:libauth' && cell.status === 'measured'), true);
  const stack = metric.cells.find((cell) => cell.metricId === 'stackMax' && cell.engineId === 'engine:libauth' && cell.status === 'measured');
  assert.equal(typeof stack.value, 'object');
  assert.equal(stack.value.primaryItems > 0, true);
});

test('materializer rejects corpus/report coordinate drift, missing Git, and artifact tampering', () => {
  const report = buildM89ShakedownReport();
  const coordinateDrift = structuredClone(report);
  coordinateDrift.cases.pop();
  assert.throws(() => buildM89OfficialRun(coordinateDrift, { rootDir: join(root, 'coordinate-drift') }), /coordinate bijection|report has/);

  const missingVerdict = structuredClone(report);
  delete missingVerdict.cases[0].bchn.accepted;
  assert.throws(() => buildM89OfficialRun(missingVerdict, { rootDir: join(root, 'missing-verdict') }), /no explicit per-case verdict/);

  assert.throws(() => buildM89OfficialRun(report, { rootDir: join(root, 'missing-git'), gitRepositories: { bchn: join(root, 'does-not-exist') } }), /Command failed|ENOENT|not a git repository/);

  const target = join(root, 'tamper');
  materializeM89Shakedown(report, target);
  assert.throws(() => materializeM89Shakedown(report, target), /refusing to overwrite existing run directory/);
  const artifactPath = join(target, 'artifacts/corpus.json');
  const artifact = readFileSync(artifactPath);
  writeFileSync(artifactPath, Buffer.concat([artifact, Buffer.from(' ')]));
  assert.throws(() => verifyM89Shakedown(target), /artifact corpus|corpus digest|digest mismatch/);
});
