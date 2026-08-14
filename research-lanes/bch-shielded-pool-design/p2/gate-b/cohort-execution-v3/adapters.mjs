import { ENGINE_ORDER, METRICS } from './contract.mjs';
import { parseLeanCostprobeRows, parseLeanVmbconfAggregate } from './lean-aggregate.mjs';

const assert = (condition, message) => { if (!condition) throw new Error(`cohort-execution-v3 adapter surface: ${message}`); };
const exactKeys = (value, keys, label) => assert(value !== null && typeof value === 'object' && !Array.isArray(value) && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()), `${label} exact key set`);
const strictUtf8 = (bytes, label) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) { throw new Error(`cohort-execution-v3 adapter surface: ${label} is not strict UTF-8: ${error.message}`); } };
const safeNonnegative = (value, label) => assert(Number.isSafeInteger(value) && value >= 0, `${label} nonnegative safe integer`);
const BCHN_FIELDS = Object.freeze(['ident', 'outcome', 'error_class', 'native_error', 'phase', 'op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks', 'sig_checks_limit', 'tx_checks', 'stack_hash']);
const BCHN_PHASES = new Set(['ok', 'execute', 'tx_decode', 'utxo_decode', 'malformed_vector', 'exception']);
const bytesToHex = value => Buffer.from(value).toString('hex');

/** Validate synthetic/non-executing adapter output identities; never evaluates a BCH VM. */
export function validateSyntheticAdapterRows(engineId, rows, observations) {
  assert(ENGINE_ORDER.includes(engineId) && Array.isArray(rows) && Array.isArray(observations) && rows.length === 4732 && observations.length === 4732, 'engine/row cardinality');
  for (let ordinal = 0; ordinal < rows.length; ordinal += 1) {
    const row = rows[ordinal]; const observation = observations[ordinal];
    assert(observation.workItemId === row.workItem.workItemId && observation.fixtureKey === row.fixtureRecord.fixtureKey && observation.terminalCellId === row.workItem.terminalCellId, `synthetic identity ${engineId}/${ordinal}`);
    if (row.preflightLimitViolation) assert(observation.disposition === 'preflight-limit-unsupported' && observation.verdict === null && observation.metrics === null, `preflight adapter boundary ${engineId}/${ordinal}`);
    else assert(['observed-script-engine-only', 'engine-unsupported-incomplete'].includes(observation.disposition), `eligible adapter disposition ${engineId}/${ordinal}`);
    if (observation.disposition === 'observed-script-engine-only') assert(Array.isArray(observation.metrics) && observation.metrics.length === METRICS.length && observation.metrics.every((metric, index) => metric.metricId === METRICS[index]), `synthetic metrics ${engineId}/${ordinal}`);
  }
  return true;
}

/**
 * Parse the canonical LF-only NDJSON transcript used by the two in-process
 * adapters. This is a parser only; it cannot evaluate a BCH program.
 */
export function parseCanonicalNdjsonTranscript(bytes, { rows, engineId } = {}) {
  assert((engineId === 'engine:native' || engineId === 'engine:libauth') && Array.isArray(rows), 'canonical transcript engine/rows');
  const text = strictUtf8(bytes, `${engineId} stdout`);
  assert(text.endsWith('\n') && !text.includes('\r'), `${engineId} LF transcript`);
  const lines = text.slice(0, -1).split('\n');
  assert(lines.length === rows.length, `${engineId} transcript cardinality`);
  const parsed = new Map();
  for (let ordinal = 0; ordinal < lines.length; ordinal += 1) {
    let row;
    try { row = JSON.parse(lines[ordinal]); } catch (error) { throw new Error(`cohort-execution-v3 adapter surface: ${engineId} transcript JSON ${ordinal}: ${error.message}`); }
    exactKeys(row, ['workItemId', 'verdict', 'failureStage', 'metrics', 'txChecks', 'phase', 'terminalStatus'], `${engineId} transcript row ${ordinal}`);
    const expected = rows[ordinal];
    const expectedWorkItemId = expected.workItemId ?? expected.workItem?.workItemId;
    assert(typeof expectedWorkItemId === 'string' && row.workItemId === expectedWorkItemId && !parsed.has(row.workItemId), `${engineId} transcript row identity ${ordinal}`);
    assert(row.verdict === 'accept' || row.verdict === 'reject', `${engineId} transcript verdict ${ordinal}`);
    assert((row.failureStage === null || typeof row.failureStage === 'string') && row.txChecks === 'unsupported' && typeof row.phase === 'string' && typeof row.terminalStatus === 'string', `${engineId} transcript boundary ${ordinal}`);
    assert(row.metrics === null || (typeof row.metrics === 'object' && !Array.isArray(row.metrics)), `${engineId} transcript metrics ${ordinal}`);
    parsed.set(row.workItemId, Object.freeze(row));
  }
  return parsed;
}

/** Strict BCHN Effects NDJSON parser; script-only tx checks stay unsupported. */
export function parseBchnEffectsTranscript(bytes, { rows } = {}) {
  assert(Array.isArray(rows), 'BCHN rows');
  const text = strictUtf8(bytes, 'BCHN stdout');
  assert(text.endsWith('\n') && !text.includes('\r'), 'BCHN LF NDJSON');
  const lines = text.slice(0, -1).split('\n');
  assert(lines.length === rows.length && lines.every(line => line.length > 0), 'BCHN cardinality/blank line');
  const parsed = new Map();
  for (let ordinal = 0; ordinal < lines.length; ordinal += 1) {
    let effect;
    try { effect = JSON.parse(lines[ordinal]); } catch (error) { throw new Error(`cohort-execution-v3 adapter surface: BCHN JSON ${ordinal}: ${error.message}`); }
    exactKeys(effect, BCHN_FIELDS, `BCHN effect ${ordinal}`);
    const expected = rows[ordinal];
    const expectedWorkItemId = expected.workItemId ?? expected.workItem?.workItemId;
    assert(typeof expectedWorkItemId === 'string' && effect.ident === expectedWorkItemId && !parsed.has(effect.ident), `BCHN identity ${ordinal}`);
    assert(effect.outcome === 'accept' || effect.outcome === 'reject', `BCHN outcome ${ordinal}`);
    safeNonnegative(effect.error_class, `BCHN error class ${ordinal}`);
    assert(typeof effect.native_error === 'string' && BCHN_PHASES.has(effect.phase) && effect.tx_checks === 'unsupported' && effect.stack_hash === null, `BCHN component boundary ${ordinal}`);
    for (const field of ['op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks', 'sig_checks_limit']) assert(effect[field] === null || (Number.isSafeInteger(effect[field]) && effect[field] >= 0), `BCHN ${field} ${ordinal}`);
    if (effect.outcome === 'accept') {
      assert(effect.error_class === 0 && effect.phase === 'ok' && effect.native_error === '', `BCHN accepted identity ${ordinal}`);
      for (const field of ['op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks', 'sig_checks_limit']) assert(effect[field] !== null, `BCHN accepted ${field} ${ordinal}`);
    } else {
      assert(effect.error_class !== 0 && effect.phase !== 'ok', `BCHN rejected identity ${ordinal}`);
      for (const field of ['op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks']) assert(effect[field] === null, `BCHN rejected ${field} ${ordinal}`);
    }
    parsed.set(effect.ident, Object.freeze({
      workItemId: effect.ident,
      verdict: effect.outcome,
      failureStage: effect.outcome === 'accept' ? 'accept' : null,
      metrics: effect.outcome === 'accept' ? Object.freeze({ operationCost: effect.op_cost, maximumOperationCost: effect.op_cost_limit, hashDigestIterations: effect.hash_iters, maximumHashDigestIterations: effect.hash_iters_limit, signatureCheckCount: effect.sig_checks, maximumSignatureCheckCount: effect.sig_checks_limit }) : null,
      /* Normalized evidence uses the frozen terminal vocabulary. The BCHN
       * Effects phase remains captured separately; it is not a different
       * terminal-status namespace. */
      txChecks: 'unsupported', phase: effect.phase, terminalStatus: 'observed',
    }));
  }
  return parsed;
}

/* These serializers are copied as a closed v3 definition from the frozen v2
 * adapter contract. They are pure byte encoders, not runners. A module
 * endpoint has no stdin transport: its exact captured stdin is empty. */
function exactReadyRows(rows, engineId) {
  assert(Array.isArray(rows) && rows.length === 4608, `${engineId} ready row cardinality`);
  const seen = new Set();
  for (const row of rows) {
    assert(row?.workItem?.engineId === engineId && row.fixture && row.expected && row.preflightLimitViolation === false, `${engineId} fixture row authority`);
    assert(typeof row.workItem.workItemId === 'string' && !seen.has(row.workItem.workItemId), `${engineId} duplicate work item`); seen.add(row.workItem.workItemId);
    assert(row.fixture.bytes?.transaction instanceof Uint8Array && row.fixture.bytes?.sourceOutputs instanceof Uint8Array, `${engineId} fixture byte authority`);
  }
  return rows;
}
export function encodeNativeModuleStdin(rows) { exactReadyRows(rows, 'engine:native'); return Buffer.alloc(0); }
export function encodeLibauthModuleStdin(rows) { exactReadyRows(rows, 'engine:libauth'); return Buffer.alloc(0); }
export function encodeBchnBatchStdin(rows) {
  exactReadyRows(rows, 'engine:bchn');
  const packed = rows.map(row => [row.workItem.workItemId, 'cohort-freeze-v2 exact synthetic P2SH32 component fixture', '', '', bytesToHex(row.fixture.bytes.transaction), bytesToHex(row.fixture.bytes.sourceOutputs), 0]);
  return Buffer.from(`${JSON.stringify(packed)}\n`, 'utf8');
}
const leanLine = (row, expected) => `${expected} ${row.workItem.workItemId} ${bytesToHex(row.fixture.bytes.transaction)} ${bytesToHex(row.fixture.bytes.sourceOutputs)} 0`;
export function encodeLeanVmbconfStdin(rows) { exactReadyRows(rows, 'engine:leanbch'); return Buffer.from(`${rows.map(row => leanLine(row, row.expected.verdict === 'accept' ? '1' : '0')).join('\n')}\n`, 'utf8'); }
export function encodeLeanCostprobeStdin(rows) { exactReadyRows(rows, 'engine:leanbch'); return Buffer.from(`${rows.map(row => leanLine(row, 'KERNEL')).join('\n')}\n`, 'utf8'); }
export const parseLeanAggregateCorroboration = parseLeanVmbconfAggregate;
export const parseLeanCostprobeAuthority = parseLeanCostprobeRows;
export const ADAPTER_BOUNDARY = Object.freeze({ componentAndScriptEngineOnly: true, bchnTxChecks: 'unsupported', syntheticOnly: true, executionClaim: null });
