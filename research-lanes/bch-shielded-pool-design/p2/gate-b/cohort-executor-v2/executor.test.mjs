import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import Ajv from 'ajv/dist/2020.js';

import { buildAuthorization, buildVerifiedRows, validateAuthorization, validateStatic } from './executor.mjs';
import { buildArtifactPairs, materializeAttempt, materializeTestAttempt } from './materializer.mjs';
import { assertNoSymlinkComponents, validateEvidencePackage, validateSerialInterruption } from './validator.mjs';
import { loadFrozenEpochArtifacts } from '../cohort-execution-v2/engine-adapters.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const read = (name) => JSON.parse(fs.readFileSync(path.join(here, name), 'utf8'));
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
const engines = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'];
const streamPath = (engineId, role, processRole = null) => `attempt-000/raw/${engineId}/${processRole ? `${processRole}-` : ''}${role}.log`;
const spans = (stream, lines, identify) => {
  const out = new Map(); let offset = 0;
  for (const [index, line] of lines.entries()) { const data = Buffer.from(line, 'utf8'); const id = identify(line); if (id) out.set(id, { path: stream, byteStart: offset, byteEnd: offset + data.length, lineStart: index + 1, lineEnd: index + 1, spanSha256: sha(data) }); offset += data.length; }
  return out;
};
const preflight = (record) => Boolean(record.preflightLimitViolation.scriptSig || record.preflightLimitViolation.redeem);

test('authorization is exact, startup-closed, source-closed, and content addressed', () => {
  const auth = read('authorization.v2.json');
  assert.doesNotThrow(() => validateAuthorization(auth));
  assert.equal(auth.executionAllowed, true);
  assert.deepEqual(auth.executorStartup.environment, { NODE_ENV: 'production' });
  assert.equal(auth.schedule.timeoutMs, 600000);
  assert.equal(auth.schedule.maxBufferBytes, 134217728);
  assert.equal(auth.runtimeDependencyTrees.reduce((n, item) => n + item.files.length, 0), 527);
  assert.ok(auth.engines.find((x) => x.engineId === 'engine:leanbch').sourceClosure.files.some((x) => x.realpath.endsWith('/LeanBCH/Crypto/Native.lean')));
  assert.throws(() => validateAuthorization({ ...auth, executionAllowed: false }), /must be equal|authorization differs/);
  assert.throws(() => validateAuthorization({ ...auth, executorStartup: { ...auth.executorStartup, environment: {} } }), /must be equal|authorization differs/);
  assert.throws(() => validateAuthorization({ ...auth, sourceBindings: auth.sourceBindings.slice(1) }), /must be equal|authorization differs/);
});

test('schemas are strict, serial lifecycle is causal, and static check is nonwriting', () => {
  for (const file of ['authorization.v2.schema.json', 'manifest.v1.schema.json']) assert.doesNotThrow(() => new Ajv({ strict: true }).compile(read(file)));
  const auth = read('authorization.v2.json'); const validator = new Ajv({ strict: true }).compile(read('authorization.v2.schema.json'));
  assert.equal(validator({ ...auth, forged: true }), false);
  for (const valid of [['complete', 'complete', 'complete', 'complete'], ['complete', 'incomplete', 'not-started', 'not-started'], ['complete', 'failed', 'not-started', 'not-started']]) assert.doesNotThrow(() => validateSerialInterruption(valid));
  assert.throws(() => validateSerialInterruption(['complete', 'incomplete', 'failed', 'not-started']), /multiple|noncausal/);
  const files = ['authorization.v2.json', 'MANIFEST.json', 'SHA256SUMS'].map((x) => [x, sha(fs.readFileSync(path.join(here, x)))]);
  assert.doesNotThrow(() => validateStatic());
  assert.deepEqual(files, files.map(([name]) => [name, sha(fs.readFileSync(path.join(here, name)))]));
});

test('path guards reject leaf and intermediate symlinks', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'cohort-executor-path-'));
  fs.mkdirSync(path.join(root, 'real')); fs.writeFileSync(path.join(root, 'real', 'payload'), 'x'); fs.symlinkSync(path.join(root, 'real'), path.join(root, 'link'));
  assert.throws(() => assertNoSymlinkComponents(root, 'link/payload'), /symlink/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('production materializer rejects arbitrary output and runner API has no injected backend seam', () => {
  const authorization = buildAuthorization(); const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'cohort-executor-output-'));
  try { assert.throws(() => materializeAttempt({ outputRoot: path.join(temp, 'attempt-000'), authorization }), /authorized output path/); } finally { fs.rmSync(temp, { recursive: true, force: true }); }
  const runnerSource = fs.readFileSync(path.join(here, 'engine-runners.mjs'), 'utf8');
  assert.match(runnerSource, /defaultRunners/); assert.equal(runnerSource.includes('reviewedBackends'), false);
  assert.match(runnerSource, /encoding: null/); assert.match(runnerSource, /hrtime\.bigint/);
});

const syntheticBatches = async () => {
  const artifacts = loadFrozenEpochArtifacts(); const rows = buildVerifiedRows(artifacts); const batches = new Map(); const streams = new Map();
  for (const engineId of engines) {
    const eligible = rows.get(engineId); const stdoutPath = streamPath(engineId, 'stdout', engineId === 'engine:leanbch' ? 'secondary' : null); let stdoutLines = []; let observations = new Map();
    if (engineId === 'engine:native' || engineId === 'engine:libauth') {
      stdoutLines = eligible.map((row) => `${JSON.stringify({ workItemId: row.workItem.workItemId, verdict: row.expected.verdict, failureStage: engineId === 'engine:native' ? row.expected.stage : row.expected.verdict === 'accept' ? 'accept' : null, metrics: null, txChecks: 'unsupported-for-component-only-script-engine-boundary', phase: engineId === 'engine:native' ? 'semantic-reference' : 'script-engine', terminalStatus: 'supported' })}\n`);
    } else if (engineId === 'engine:bchn') {
      stdoutLines = eligible.map((row) => `${JSON.stringify(row.expected.verdict === 'accept' ? { ident: row.workItem.workItemId, outcome: 'accept', error_class: 0, native_error: '', phase: 'ok', op_cost: 1, op_cost_limit: 100, hash_iters: 0, hash_iters_limit: 100, sig_checks: 0, sig_checks_limit: 100, tx_checks: 'unsupported', stack_hash: null } : { ident: row.workItem.workItemId, outcome: 'reject', error_class: 1, native_error: 'reject', phase: 'execute', op_cost: null, op_cost_limit: null, hash_iters: null, hash_iters_limit: null, sig_checks: null, sig_checks_limit: null, tx_checks: 'unsupported', stack_hash: null })}\n`);
    } else {
      stdoutLines = ['ORACLE reject\n', ...eligible.map((row) => `METRICS ${row.workItem.workItemId} ${row.expected.verdict === 'accept' ? '1' : '0'} 1 0 0 1 1 1\n`)];
    }
    const sourceSpans = spans(stdoutPath, stdoutLines, (line) => {
      if (engineId === 'engine:native' || engineId === 'engine:libauth') return JSON.parse(line).workItemId;
      if (engineId === 'engine:bchn') return JSON.parse(line).ident;
      return /^METRICS ([^\s]+)/u.exec(line)?.[1] ?? null;
    });
    for (const row of eligible) {
      const metrics = engineId === 'engine:bchn' ? row.expected.verdict === 'accept' ? { operationCost: 1, maximumOperationCost: 100, hashDigestIterations: 0, maximumHashDigestIterations: 100, signatureCheckCount: 0, maximumSignatureCheckCount: 100 } : null : engineId === 'engine:leanbch' ? { evaluatedInstructionCount: 1, signatureCheckCount: 0, hashDigestIterations: 0, arithmeticCost: 1, stackPushedBytes: 1, nativeConsensus64OperationCost: 1 } : null;
      observations.set(row.workItem.workItemId, { workItemId: row.workItem.workItemId, verdict: row.expected.verdict, failureStage: engineId === 'engine:native' ? row.expected.stage : row.expected.verdict === 'accept' ? 'accept' : null, metrics, txChecks: 'unsupported-for-component-only-script-engine-boundary', phase: engineId === 'engine:native' ? 'semantic-reference' : engineId === 'engine:bchn' ? (row.expected.verdict === 'accept' ? 'ok' : 'execute') : engineId === 'engine:leanbch' ? 'script-engine-only' : 'script-engine', terminalStatus: 'supported', sourceStream: sourceSpans.get(row.workItem.workItemId) });
    }
    const primaryStdin = Buffer.alloc(0); const primaryStdout = Buffer.from(engineId === 'engine:leanbch' ? 'ORACLE reject\nPASS 4608 / 4608\nREJECTED-VALID 0: []\nACCEPTED-INVALID 0: []\nSTD-TRUE 0 STD-FALSE 4608\nSTD-TRUE-IDS: []\nSTD-FALSE-IDS: ' + JSON.stringify(eligible.slice(0, 200).map((x) => x.workItem.workItemId)) + '\n' : engineId === 'engine:bchn' ? stdoutLines.join('') : stdoutLines.join(''), 'utf8');
    if (engineId === 'engine:bchn') {
      const { encodeBchnBatchStdin } = await import('../cohort-execution-v2/engine-adapters.mjs'); streams.set(streamPath(engineId, 'stdin'), Buffer.from(encodeBchnBatchStdin(eligible), 'utf8'));
    } else streams.set(streamPath(engineId, 'stdin'), primaryStdin);
    streams.set(streamPath(engineId, 'stdout'), primaryStdout); streams.set(streamPath(engineId, 'stderr'), Buffer.alloc(0));
    if (engineId === 'engine:leanbch') {
      const { encodeLeanVmbconfStdin, encodeLeanCostprobeStdin } = await import('../cohort-execution-v2/engine-adapters.mjs');
      streams.set(streamPath(engineId, 'stdin', 'primary'), Buffer.from(encodeLeanVmbconfStdin(eligible), 'utf8')); streams.set(streamPath(engineId, 'stdout', 'primary'), primaryStdout); streams.set(streamPath(engineId, 'stderr', 'primary'), Buffer.alloc(0)); streams.set(streamPath(engineId, 'stdin', 'secondary'), Buffer.from(encodeLeanCostprobeStdin(eligible), 'utf8')); streams.set(streamPath(engineId, 'stdout', 'secondary'), Buffer.from(stdoutLines.join(''), 'utf8')); streams.set(streamPath(engineId, 'stderr', 'secondary'), Buffer.alloc(0));
    }
    const role = engineId === 'engine:leanbch' ? { primary: { exitCode: 0, timedOut: false }, secondary: { exitCode: 0, timedOut: false } } : { primary: { exitCode: engineId === 'engine:native' || engineId === 'engine:libauth' ? null : 0, timedOut: false } };
    batches.set(engineId, { engineId, status: 'complete', observations, streams: new Map([...streams].filter(([key]) => key.includes(`/raw/${engineId}/`))), processResults: role });
  }
  return { artifacts, batches, streams };
};

test('opt-in host-only 27-file materialize, validate, rename, and adversarial cleanup', { timeout: 300000, skip: process.env.COHORT_EXECUTOR_FULL_HOST_TEST === '1' ? false : 'set COHORT_EXECUTOR_FULL_HOST_TEST=1' }, async () => {
  const authorization = buildAuthorization(); const { artifacts, batches, streams } = await syntheticBatches(); const pair = buildArtifactPairs({ authorization, artifacts, batches, streamText: streams });
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'cohort-executor-e2e-')); const output = path.join(parent, 'attempt-000');
  try {
    const result = materializeTestAttempt({ outputRoot: output, authorization, ...pair, streamText: streams });
    assert.equal(result.status, 'PASS'); assert.equal(fs.existsSync(path.join(output, 'evidence-root.v2.json')), true);
    assert.equal(fs.readdirSync(output, { recursive: true }).filter((x) => fs.statSync(path.join(output, x)).isFile()).length, 27);
    assert.doesNotThrow(() => validateEvidencePackage({ attemptRoot: output, authorization }));
    const rawPath = path.join(output, 'attempt-000/raw/engine:native/raw-engine-observation.v2.json'); fs.appendFileSync(rawPath, ' ');
    assert.throws(() => validateEvidencePackage({ attemptRoot: output, authorization }), /hash|inventory|manifest/);
  } finally { fs.rmSync(parent, { recursive: true, force: true }); }
});
