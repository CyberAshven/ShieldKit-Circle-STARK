import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeBchnBatchStdin, encodeLeanCostprobeStdin, encodeLeanVmbconfStdin, encodeLibauthModuleStdin, encodeNativeModuleStdin, validateSyntheticAdapterRows } from './adapters.mjs';
import { deriveVerifiedFixtureRows } from './fixtures.mjs';

test('all 4,732 frozen fixtures re-derive from exact source-set plans without VM evaluation', () => {
  const rows = deriveVerifiedFixtureRows();
  assert.deepEqual(rows.counts, { fixtures: 4732, engines: 4, obligations: 18928, preflightFixtures: 124, executablePerEngine: 4608 });
  for (const engineId of ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']) assert.equal(rows.byEngine[engineId].length, 4732);
  const ready = engineId => rows.byEngine[engineId].filter(row => !row.preflightLimitViolation);
  assert.equal(encodeNativeModuleStdin(ready('engine:native')).length, 0);
  assert.equal(encodeLibauthModuleStdin(ready('engine:libauth')).length, 0);
  assert.equal(encodeBchnBatchStdin(ready('engine:bchn')).length, 29510638);
  assert.equal(encodeLeanVmbconfStdin(ready('engine:leanbch')).length, 29192684);
  assert.equal(encodeLeanCostprobeStdin(ready('engine:leanbch')).length, 29215724);
});
test('synthetic adapter shape cannot turn preflight fixtures into observed results', () => {
  const fixture = { fixtureKey: 'fixture:test' }; const work = { workItemId: 'work:test', terminalCellId: 'cell:test' };
  const rows = Array.from({ length: 4732 }, (_, ordinal) => ({ fixtureRecord: { ...fixture, fixtureKey: `fixture:${ordinal}` }, workItem: { ...work, workItemId: `work:${ordinal}`, terminalCellId: `cell:${ordinal}` }, preflightLimitViolation: ordinal === 0 }));
  const observations = rows.map((row, ordinal) => row.preflightLimitViolation ? { workItemId: row.workItem.workItemId, fixtureKey: row.fixtureRecord.fixtureKey, terminalCellId: row.workItem.terminalCellId, disposition: 'preflight-limit-unsupported', verdict: null, metrics: null } : { workItemId: row.workItem.workItemId, fixtureKey: row.fixtureRecord.fixtureKey, terminalCellId: row.workItem.terminalCellId, disposition: 'observed-script-engine-only', metrics: ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'].map(metricId => ({ metricId })), ordinal });
  assert.equal(validateSyntheticAdapterRows('engine:native', rows, observations), true);
  observations[0].disposition = 'observed-script-engine-only'; assert.throws(() => validateSyntheticAdapterRows('engine:native', rows, observations), /preflight/);
});
