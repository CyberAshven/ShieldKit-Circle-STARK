import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import {
  FROZEN_COUNTS,
  LIMIT_FIXTURE_STATUS,
  PREFLIGHT_TERMINAL_STATUS,
  buildBchnInvocationDescriptor,
  buildLeanCostprobeInvocationDescriptor,
  buildLeanVmbconfInvocationDescriptor,
  buildNativeInvocationDescriptor,
  buildVerifiedAdapterRow,
  classifyPreflightWorkItem,
  encodeBchnBatchStdin,
  encodeLeanCostprobeStdin,
  encodeLeanVmbconfStdin,
  evaluateLibauthExactFixture,
  loadFrozenEpochArtifacts,
  parseBchnBatchStdout,
  parseLeanCostprobeStdout,
  parseLeanVmbconfAggregate,
  replayNativeDirectExtension,
  replayAllFrozenNativeCases,
  verifyFrozenFixtureAuthority,
} from './engine-adapters.mjs';

const artifacts = loadFrozenEpochArtifacts();
const firstReadyRecord = artifacts.fixtureRoster.records.find((record) => record.status !== LIMIT_FIXTURE_STATUS);
const firstLimitedRecord = artifacts.fixtureRoster.records.find((record) => record.status === LIMIT_FIXTURE_STATUS);
const workFor = (record, engineId) => artifacts.workItemRoster.workItems.find((item) => item.fixtureKey === record.fixtureKey && item.engineId === engineId);
const readyRow = (engineId) => buildVerifiedAdapterRow({ workItem: workFor(firstReadyRecord, engineId), fixtureRecord: firstReadyRecord, corpus: artifacts.corpus });

test('re-derives and byte-hash checks the exact frozen 4,732-fixture authority', () => {
  const summary = verifyFrozenFixtureAuthority({ artifacts });
  assert.deepEqual(summary, {
    fixtureCount: FROZEN_COUNTS.fixtures,
    readyFixtureCount: FROZEN_COUNTS.readyFixtures,
    preflightLimitFixtureCount: FROZEN_COUNTS.preflightLimitFixtures,
    workItemCount: FROZEN_COUNTS.workItems,
    preflightLimitWorkItemCount: FROZEN_COUNTS.preflightLimitWorkItems,
  });
});

test('replays every corpus case through all four DirectExtension configurations', () => {
  const replay = replayAllFrozenNativeCases({ corpus: artifacts.corpus });
  assert.equal(replay.replayed, 1288);
  assert.deepEqual(Object.values(replay.byConstruction), [266, 294, 350, 378]);
});

test('native parser-stage paths are finalized against the frozen expected verdict and stage', () => {
  const caseEntry = structuredClone(artifacts.corpus.constructions[0].cases[0]);
  caseEntry.stackArgsBottomToTop[0] = '00';
  caseEntry.rawOperands.D = '00';
  caseEntry.expected = { verdict: 'reject', stage: 'exact-extension-element-length-check-before-limb-decode' };
  const result = replayNativeDirectExtension({ caseEntry });
  assert.deepEqual({ verdict: result.verdict, stage: result.stage }, caseEntry.expected);
  caseEntry.expected = { verdict: 'accept', stage: 'accept' };
  assert.throws(() => replayNativeDirectExtension({ caseEntry }), /differs from frozen expected/u);
});

test('preflight-limit fixtures form explicit unsupported work records', () => {
  const row = buildVerifiedAdapterRow({ workItem: workFor(firstLimitedRecord, 'engine:bchn'), fixtureRecord: firstLimitedRecord, corpus: artifacts.corpus });
  const terminal = classifyPreflightWorkItem(row);
  assert.equal(terminal.terminalStatus, PREFLIGHT_TERMINAL_STATUS);
  assert.equal(terminal.executed, false);
  assert.equal(terminal.countedAsExecution, false);
  assert.equal(terminal.agreement, false);
  assert.throws(() => encodeBchnBatchStdin([row]), /preflight limit fixture/u);
});

test('BCHN codec and strict NDJSON parser retain the script-only boundary', () => {
  const row = readyRow('engine:bchn');
  const stdin = encodeBchnBatchStdin([row]);
  const pack = JSON.parse(stdin);
  assert.equal(pack.length, 1);
  assert.equal(pack[0][0], row.workItem.workItemId);
  assert.equal(pack[0][6], 0);
  const effect = {
    ident: row.workItem.workItemId,
    outcome: 'accept', error_class: 0, native_error: '', phase: 'ok',
    op_cost: 1, op_cost_limit: 2, hash_iters: 3, hash_iters_limit: 4,
    sig_checks: 0, sig_checks_limit: 1, tx_checks: 'unsupported', stack_hash: null,
  };
  const parsed = parseBchnBatchStdout(`${JSON.stringify(effect)}\n`, { rows: [row] });
  assert.equal(parsed.get(row.workItem.workItemId).txChecks, 'unsupported-for-component-only-script-engine-boundary');
  assert.throws(() => parseBchnBatchStdout(`${JSON.stringify({ ...effect, tx_checks: 'checked' })}\n`, { rows: [row] }), /boundary drift/u);
  const rejectedNegativeError = { ...effect, outcome: 'reject', error_class: -1, native_error: 'error', phase: 'execute', op_cost: null, op_cost_limit: null, hash_iters: null, hash_iters_limit: null, sig_checks: null };
  assert.throws(() => parseBchnBatchStdout(`${JSON.stringify(rejectedNegativeError)}\n`, { rows: [row] }), /error_class/u);
  const descriptor = buildBchnInvocationDescriptor([row], { artifacts });
  assert.deepEqual(descriptor.argv.slice(-2), ['--mode', 'standard']);
  assert.equal(descriptor.executionAllowedByFrozenEpoch, false);
  const mutated = readyRow('engine:bchn');
  mutated.fixture.bytes.transaction[0] ^= 0x01;
  assert.throws(() => encodeBchnBatchStdin([mutated]), /transaction byte binding drift/u);
});

test('Lean codecs and aggregate/per-line parsers stay fail-closed', () => {
  const row = readyRow('engine:leanbch');
  assert.match(encodeLeanVmbconfStdin([row]), new RegExp(`^${row.expected.verdict === 'accept' ? 1 : 0} `));
  assert.match(encodeLeanCostprobeStdin([row]), /^KERNEL /u);
  const id = row.workItem.workItemId;
  const aggregate = [
    'ORACLE reject', 'PASS 1 / 1', 'REJECTED-VALID 0: []', 'ACCEPTED-INVALID 0: []',
    'STD-TRUE 1 STD-FALSE 0', `STD-TRUE-IDS: ["${id}"]`, 'STD-FALSE-IDS: []',
  ].join('\n').concat('\n');
  const parsedAggregate = parseLeanVmbconfAggregate(aggregate, { rows: [row] });
  assert.equal(parsedAggregate.aggregateOnly, true);
  assert.equal(parsedAggregate.perWorkItemTerminalResults, null);
  assert.throws(() => parseLeanVmbconfAggregate(aggregate.replace('ACCEPTED-INVALID 0: []', `ACCEPTED-INVALID 1: ["${id}"]`).replace('PASS 1 / 1', 'PASS 0 / 1'), { rows: [row] }), /conflicts with frozen expected verdicts/u);
  const metrics = parseLeanCostprobeStdout(`ORACLE reject\nMETRICS ${id} 1 1 0 0 0 1 101\n`, { rows: [row] });
  assert.equal(metrics.get(id).metrics.nativeConsensus64OperationCost, 101);
  const skipped = parseLeanCostprobeStdout(`ORACLE reject\nSKIP ${id} no-metric-phase\n`, { rows: [row] });
  assert.equal(skipped.get(id).supportStatus, 'unsupported');
  assert.equal(skipped.get(id).countedAsAgreement, false);
  assert.throws(() => parseLeanCostprobeStdout(`ORACLE native\nMETRICS ${id} 1 1 0 0 0 1 101\n`, { rows: [row] }), /oracle|cardinality/u);
  assert.equal(buildLeanVmbconfInvocationDescriptor([row], { artifacts }).executionAllowedByFrozenEpoch, false);
  assert.match(buildLeanCostprobeInvocationDescriptor([row], { artifacts }).lifecycle, /separate-costprobe-process/u);
});

test('Libauth preserves finite raw VM metrics on rejected script states', () => {
  const row = readyRow('engine:libauth');
  const sourceMetrics = {
    operationCost: 17,
    stackMax: 3,
    rejectedPathCounter: 0,
    negativeAccounting: -4,
    infinite: Infinity,
    notANumber: Number.NaN,
    nonNumeric: '17',
  };
  const fakeVm = {
    evaluate: () => ({ metrics: sourceMetrics }),
    stateSuccess: () => 'script-failed',
  };
  const result = evaluateLibauthExactFixture(row.fixture, { vmFactory: () => fakeVm });
  assert.equal(result.verdict, 'reject');
  assert.equal(result.error, 'script-failed');
  // This object is carried unchanged into the raw Libauth transcript before
  // later normalized metric mapping; names and finite source values must not
  // depend on an accepted verdict.
  assert.deepEqual(result.metrics, {
    operationCost: 17,
    stackMax: 3,
    rejectedPathCounter: 0,
    negativeAccounting: -4,
  });
  assert.equal(Object.hasOwn(result.metrics, 'infinite'), false);
  assert.equal(Object.hasOwn(result.metrics, 'notANumber'), false);
  assert.equal(Object.hasOwn(result.metrics, 'nonNumeric'), false);
});

test('library is process-free and never permits the legacy fabricated Libauth helper', () => {
  const source = readFileSync(new URL('./engine-adapters.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:child_process|spawnSync|spawn\(/u);
  assert.doesNotMatch(source, /createTestAuthenticationProgramBch/u);
  const row = readyRow('engine:native');
  const descriptor = buildNativeInvocationDescriptor(row, { artifacts });
  assert.equal(descriptor.descriptorKind, 'in-process-host-reference-only-not-bch-vm');
  assert.equal(descriptor.executionAllowedByFrozenEpoch, false);
});
