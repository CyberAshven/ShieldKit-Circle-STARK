import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { assertArtifactLifecycle, assertObservedTerminalProjection, buildContract, deriveFixtureAgreement, deriveMetricAgreement, METRICS, validateContract, validateEvidenceShape, validateManifest } from './contract.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);

test('deterministic v3 contract binds frozen retry and fixed attempt-one boundary', () => {
  const result = validateContract();
  assert.equal(result.status, 'PASS'); assert.equal(result.obligations, 18928); assert.equal(result.metricCellsPerEngine, 70980);
  const contract = buildContract();
  assert.equal(contract.attempt.authorization, null);
  assert.equal(contract.attempt.authorizationPath, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-authorizations-v3/attempt-001.authorization.v3.json');
  assert.equal(contract.authorityBindings.retry.path.endsWith('cohort-retry-v1/attempt-001.retry-wrapper.v1.json'), true);
  assert.deepEqual(contract.metricVocabulary, METRICS);
});
test('root schema is strict and rejects execution, authority, scheduling, or count drift', () => {
  const schema = JSON.parse(fs.readFileSync(path.join(here, 'execution-contract.v3.schema.json'))); const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  for (const mutate of [x => { x.execution = {}; }, x => { x.authorityBindings.engines.pop(); }, x => { x.schedule.maxConcurrency = 2; }, x => { x.obligationAccounting.totalTerminalObligations = 1; }, x => { x.extra = true; }]) { const copy = structuredClone(buildContract()); mutate(copy); assert.equal(validate(copy), false); }
});
test('contract validator rejects re-digested authority substitutions and source binding drift', () => {
  const changed = structuredClone(buildContract()); changed.authorityBindings.retry.rawSha256 = '0'.repeat(64); changed.contentDigest.value = '0'.repeat(64);
  assert.throws(() => validateContract(changed), /differs|binding|digest/);
});
test('static package manifest has closed file and checksum coverage', () => assert.equal(validateManifest().status, 'PASS'));
test('contract-only modules cannot import process execution APIs', () => {
  for (const name of ['contract.mjs', 'lean-aggregate.mjs', 'generate.mjs']) assert.doesNotMatch(fs.readFileSync(path.join(here, name), 'utf8'), /node:child_process|spawn\(|execFile\(|execSync\(/u);
});
test('future evidence semantic join schema-checks before evidence acceptance', () => {
  assert.throws(() => validateEvidenceShape({ rawArtifacts: [], normalizedArtifacts: [], crossSummary: {} }), /schema|four raw|cardinality/);
});
test('agreement is all-four only and raw terminal status cannot be relabelled after re-digest', () => {
  const observed = engineId => ({ engineId, terminalStatus: 'observed', observedVerdict: 'accept', comparable: true });
  const engines = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'].map(observed);
  assert.equal(deriveFixtureAgreement({ preflight: false, cells: engines }), 'agree');
  const skipped = structuredClone(engines); skipped[3] = { ...skipped[3], terminalStatus: 'engine-unsupported-incomplete', observedVerdict: null, comparable: false };
  assert.equal(deriveFixtureAgreement({ preflight: false, cells: skipped }), 'not-comparable');
  const metricCells = engines.map((cell, ordinal) => ({ ...cell, status: 'measured', valueDigest: 'a'.repeat(64), comparable: true, engineId: engines[ordinal].engineId }));
  assert.equal(deriveMetricAgreement({ preflight: false, cells: metricCells, terminalStatuses: engines.map(cell => cell.terminalStatus) }), 'agree');
  metricCells[3] = { ...metricCells[3], status: 'not-applicable', valueDigest: null, comparable: false };
  assert.equal(deriveMetricAgreement({ preflight: false, cells: metricCells, terminalStatuses: ['observed', 'observed', 'observed', 'engine-unsupported-incomplete'] }), 'not-comparable');
  const raw = { verdict: 'accept', failureStage: 'accept', terminalStatus: 'process-failure' };
  assert.throws(() => assertObservedTerminalProjection(raw, { observed: { verdict: 'accept', failureStage: 'accept' }, terminalStatus: 'observed' }), /terminal/);
});
test('artifact lifecycle permits a complete Lean pair with SKIP and a secondary endpoint failure', () => {
  assert.doesNotThrow(() => assertArtifactLifecycle({ engineId: 'engine:leanbch', status: 'incomplete', lifecycle: { endpoints: [{ status: 'complete' }, { status: 'complete' }] } }));
  assert.doesNotThrow(() => assertArtifactLifecycle({ engineId: 'engine:leanbch', status: 'failed', lifecycle: { endpoints: [{ status: 'complete' }, { status: 'failed' }] } }));
  assert.throws(() => assertArtifactLifecycle({ engineId: 'engine:leanbch', status: 'complete', lifecycle: { endpoints: [{ status: 'complete' }, { status: 'failed' }] } }));
});
