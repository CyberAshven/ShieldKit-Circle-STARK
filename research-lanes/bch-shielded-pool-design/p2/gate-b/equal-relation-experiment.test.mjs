import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const schema = load('./equal-relation-experiment.schema.json');
const contract = load('./equal-relation-experiment.v1.json');
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);

const expectedRelations = [
  ['relation:e-mac', 'E-MAC', 'D=A*B+C', 'eq(D,add(mul(A,B),C))'],
  ['relation:e-square-mac', 'E-SQUARE-MAC', 'D=A^2+C', 'eq(D,add(square(A),C))'],
  ['relation:e-inverse-check', 'E-INVERSE-CHECK', 'A!=0 && A*H=1', 'and(ne(A,0),eq(mul(A,H),1))']
];
const expectedMetrics = [
  'verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram',
  'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes',
  'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'
];
const clone = (value) => structuredClone(value);

test('Gate-B contract validates as strict JSON and remains non-evidence', () => {
  assert.equal(validateSchema(contract), true, JSON.stringify(validateSchema.errors));
  assert.equal(contract.status, 'contract-only-unmeasured');
  assert.equal(contract.frontier.selectedTupleCount, 0);
  assert.equal(contract.selection.frozenCandidateTupleCount, 0);
  assert.equal(contract.selection.candidateSpecificExecution, 'blocked-pending-frozen-descriptor-and-certificates');
  assert.ok(contract.selection.candidateRoster.length > 0);
  assert.ok(contract.selection.candidateRoster.every((slot) => slot.executionAllowed === false && slot.frozenCandidateTupleRef === null));
  assert.ok(contract.selection.candidateRoster.some((slot) => slot.fieldSpecRef === 'field-spec:m17-d8'));
  assert.ok(contract.artifactSlots.every((slot) => slot.status === 'empty-contract-slot' && slot.digest === null));
  assert.ok(contract.engines.every((engine) => engine.status === 'not-run'));
});

test('relation identities, seed, shared case plan, and shared mutation plan are exact', () => {
  assert.equal(contract.relationSuite.seedHex, '0123456789abcdef');
  assert.equal(contract.corpusSemantics.seedHex, '0123456789abcdef');
  assert.deepEqual(contract.relationSuite.relations.map((r) => [r.relationId, r.label, r.expression, r.normalizedExpression]), expectedRelations);
  assert.ok(contract.relationSuite.relations.every((r) => r.casePlanRef === 'cases:gate-b-shared-v1' && r.mutationPlanRef === 'mutations:gate-b-shared-v1'));
  assert.equal(contract.corpusSemantics.caseSemantics.length >= 5, true);
  assert.equal(contract.corpusSemantics.mutationSemantics.length >= 8, true);
  assert.equal(contract.corpusSemantics.crossEngineIdentityRule.includes('same category'), true);
});

test('engine roster fixes standard Libauth, real unmodified BCHN, and LeanBCH policy', () => {
  assert.deepEqual(contract.engines.map((engine) => engine.engineId), ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
  const libauth = contract.engines.find((engine) => engine.engineId === 'engine:libauth');
  assert.equal(libauth.mode, 'standard');
  assert.equal(libauth.executionPolicy, 'standard-library-pinned');
  const bchn = contract.engines.find((engine) => engine.engineId === 'engine:bchn');
  assert.equal(bchn.engineKind, 'real-unmodified-bchn');
  assert.equal(bchn.executionPolicy, 'unmodified-build-only');
  const leanbch = contract.engines.find((engine) => engine.engineId === 'engine:leanbch');
  assert.equal(leanbch.mode, 'supported-or-explicit-unsupported');
  assert.equal(leanbch.supportPolicy, 'required-or-explicit-unsupported');
});

test('metric vector contains the locked byte, opcode, arithmetic, VM, stack, limit, and headroom fields', () => {
  assert.deepEqual(contract.metricVector.ordering, expectedMetrics);
  assert.deepEqual(contract.metricVector.metrics.map((metric) => metric.metricId), expectedMetrics);
  for (const metricId of ['lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom']) {
    assert.equal(contract.metricVector.metrics.find((metric) => metric.metricId === metricId).requiredForComparison, true);
  }
  assert.match(contract.metricVector.headroomRule, /limit minus the measured value/);
});

test('candidate execution stays blocked until exact algebra, dual replay, and typed descriptor gates pass', () => {
  assert.deepEqual(contract.preExecutionGates.map((gate) => gate.kind), ['exact-polynomial-or-tower', 'dual-certificate-replay', 'typed-descriptor']);
  assert.ok(contract.preExecutionGates.every((gate) => gate.status === 'blocked' && gate.requiredBeforeCandidateExecution === true));
  const replayGate = contract.preExecutionGates.find((gate) => gate.kind === 'dual-certificate-replay');
  assert.deepEqual(replayGate.replays.map((replay) => replay.independenceRole), ['repository-checker', 'independent-cas-or-equivalently-reviewed-checker']);
  assert.ok(replayGate.replays.every((replay) => replay.status === 'required-unrun'));
});

test('strict schema rejects evidence-looking or gate-bypassing mutations', () => {
  const evidence = clone(contract);
  evidence.status = 'measured';
  assert.equal(validateSchema(evidence), false);

  const selected = clone(contract);
  selected.selection.selectedTupleCount = 1;
  assert.equal(validateSchema(selected), false);

  const run = clone(contract);
  run.engines[0].status = 'measured';
  assert.equal(validateSchema(run), false);

  const oneReplay = clone(contract);
  oneReplay.preExecutionGates[1].replays.pop();
  assert.equal(validateSchema(oneReplay), false);

  const metricDrop = clone(contract);
  metricDrop.metricVector.ordering.pop();
  assert.equal(validateSchema(metricDrop), false);
});
