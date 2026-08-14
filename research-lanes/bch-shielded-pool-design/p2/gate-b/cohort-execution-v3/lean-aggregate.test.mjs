import assert from 'node:assert/strict';
import test from 'node:test';
import { parseLeanCostprobeRows, parseLeanVmbconfAggregate, parseUnquotedLeanList } from './lean-aggregate.mjs';

const rows = [{ workItemId: 'case-A', expected: { verdict: 'accept' } }, { workItemId: 'case-B', expected: { verdict: 'reject' } }, { workItemId: 'case-C', expected: { verdict: 'accept' } }];
const aggregate = (lists = {}) => `ORACLE reject\nPASS 3 / 3\nREJECTED-VALID 0: ${lists.rejected ?? '[]'}\nACCEPTED-INVALID 0: ${lists.accepted ?? '[]'}\nSTD-TRUE 2 STD-FALSE 1\nSTD-TRUE-IDS: ${lists.truth ?? '[case-A, case-C]'}\nSTD-FALSE-IDS: ${lists.falsehood ?? '[case-B]'}\n`;

test('unquoted Lean lists accept empty single and canonical multiple values', () => {
  assert.deepEqual(parseUnquotedLeanList('[]'), []);
  assert.deepEqual(parseUnquotedLeanList('[case-A]'), ['case-A']);
  assert.deepEqual(parseUnquotedLeanList('[case-A, case-B, case-C]'), ['case-A', 'case-B', 'case-C']);
});
test('unquoted Lean lists reject spacing, quoted, and malformed variants', () => {
  for (const source of ['[ case-A]', '[case-A ]', '[case-A,case-B]', '[case-A,  case-B]', '["case-A"]', '[case-A,, case-B]', 'case-A']) assert.throws(() => parseUnquotedLeanList(source));
});
test('Lean aggregate accepts exact unquoted List.toString output', () => {
  const result = parseLeanVmbconfAggregate(aggregate(), { rows });
  assert.equal(result.total, 3); assert.deepEqual(result.standardTrueIds, ['case-A', 'case-C']);
});
test('Lean aggregate rejects duplicate unknown quoted and truncated lists', () => {
  assert.throws(() => parseLeanVmbconfAggregate(aggregate({ truth: '[case-A, case-A]' }), { rows }), /duplicate/);
  assert.throws(() => parseLeanVmbconfAggregate(aggregate({ truth: '[case-A, missing]' }), { rows }), /unknown/);
  assert.throws(() => parseLeanVmbconfAggregate(aggregate({ truth: '[case-C, case-A]' }), { rows }), /row-order/);
  assert.throws(() => parseLeanVmbconfAggregate(aggregate({ truth: '["case-A", case-C]' }), { rows }), /quoted|token/);
  const bad = aggregate().replace('STD-TRUE 2 STD-FALSE 1', 'STD-TRUE 3 STD-FALSE 0');
  assert.throws(() => parseLeanVmbconfAggregate(bad, { rows }), /truncation|count/);
});
test('CostProbe admits metrics and exact explicit unsupported SKIP only', () => {
  const good = 'ORACLE reject\nMETRICS case-A 1 1 2 3 4 5 6\nMETRICS case-B 0 1 2 3 4 5 6\nMETRICS case-C 1 1 2 3 4 5 6\n';
  const parsed = parseLeanCostprobeRows(good, { rows }); assert.equal(parsed.get('case-B').verifyInput, false);
  const skipped = parseLeanCostprobeRows(good.replace('METRICS case-B 0 1 2 3 4 5 6', 'SKIP case-B decode'), { rows });
  assert.deepEqual(skipped.get('case-B'), { workItemId: 'case-B', status: 'engine-unsupported-incomplete', verifyInput: null, verdict: null, metrics: null, reason: 'decode', executed: false, countedAsExecution: false, countedAsAgreement: false, agreementEligible: false });
  assert.throws(() => parseLeanCostprobeRows(good.replace('METRICS case-B 0 1 2 3 4 5 6', 'SKIP case-B arbitrary'), { rows }), /grammar/);
  assert.throws(() => parseLeanCostprobeRows(good.replace('case-C', 'missing'), { rows }), /unknown|omitted/);
  assert.throws(() => parseLeanCostprobeRows(good.replace('METRICS case-C', 'METRICS case-A'), { rows }), /duplicate/);
  assert.throws(() => parseLeanCostprobeRows(good.replace('METRICS case-A 1 1 2 3 4 5 6\nMETRICS case-B 0 1 2 3 4 5 6', 'METRICS case-B 0 1 2 3 4 5 6\nMETRICS case-A 1 1 2 3 4 5 6'), { rows }), /row-order/);
  const laundered = skipped.get('case-B'); assert.equal(laundered.verdict, null); assert.equal(laundered.metrics, null); assert.equal(laundered.agreementEligible, false);
});
