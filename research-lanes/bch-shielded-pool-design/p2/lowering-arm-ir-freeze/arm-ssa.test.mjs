import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { DirectExtension } from '../reference/direct-extension.mjs';
import {
  CANONICAL_REDUCE_SEMANTICS,
  SCALAR_NODE_OPS,
  canonicalJson,
  evaluateArmSsa,
  generateArmSsa,
  recomputeNodeRange,
  sha256,
  validateArmSsaProgram
} from './arm-ssa.mjs';

const loadJson = (url) => JSON.parse(readFileSync(url, 'utf8'));
const schedule = loadJson(new URL('../schedule-freeze/schedule-freeze.v1.json', import.meta.url));
const lowering = loadJson(new URL('../lowering-freeze/lowering-freeze.v1.json', import.meta.url));
const arms = generateArmSsa();
const constructionById = new Map(schedule.fieldConstructions.map((entry) => [entry.constructionId, entry]));
const scheduleArmById = new Map(schedule.arms.map((entry) => [entry.armId, entry]));
const loweringArmById = new Map(lowering.arms.map((entry) => [entry.armId, entry]));
const cloned = (value) => structuredClone(value);
const mod = (value, p) => ((value % p) + p) % p;

const contextFor = (construction) => new DirectExtension({
  modulus: BigInt(construction.p),
  degree: construction.degree,
  limbBytes: construction.codec.baseLimbBytes,
  definingPolynomial: construction.definingPolynomialAscending.map(BigInt)
});
const inputsFor = (a, b = null) => Object.fromEntries([
  ...a.map((value, index) => [`a.c${index}`, value]),
  ...(b === null ? [] : b.map((value, index) => [`b.c${index}`, value]))
]);
const deterministic = (p, degree, seed) => Array.from({ length: degree }, (_, index) => mod(
  (BigInt(seed + 7) * BigInt(index + 11)) ** 3n + BigInt((seed * 97) + (index * 193) + 5), p
));
const vectors = (p, degree) => {
  const zero = Array(degree).fill(0n);
  const one = [1n, ...Array(degree - 1).fill(0n)];
  const max = Array.from({ length: degree }, (_, index) => p - 1n - BigInt(index));
  return [
    [zero, zero],
    [one, one],
    [max, deterministic(p, degree, 3)],
    [deterministic(p, degree, 17), deterministic(p, degree, 29)],
    [deterministic(p, degree, 41), deterministic(p, degree, 53)]
  ];
};

test('generator is deterministic and preserves the exact fourteen-arm upstream order and digests', () => {
  assert.equal(arms.length, 14);
  assert.deepEqual(generateArmSsa(), arms);
  assert.deepEqual(arms.map((entry) => entry.armId), schedule.arms.map((entry) => entry.armId));
  for (const [index, arm] of arms.entries()) {
    const source = schedule.arms[index];
    const binding = loweringArmById.get(arm.armId);
    assert.equal(arm.orderIndex, index);
    assert.equal(arm.formulaId, source.formula.formulaId);
    assert.equal(arm.armDigest, binding.armDigest);
    assert.equal(arm.formulaDigest, binding.formulaDigest);
  }
  assert.deepEqual(arms.map((entry) => [entry.programs.multiply.variableBaseCounts.actual, entry.programs.square.variableBaseCounts.actual]), [
    [4, 3], [9, 6], [25, 15], [36, 21], [3, 2], [6, 6], [5, 5],
    [15, 15], [9, 9], [21, 21], [11, 11], [18, 12], [15, 10], [15, 10]
  ]);
  assert.equal(arms.reduce((sum, arm) => sum + arm.programs.multiply.variableBaseCounts.actual, 0), 192);
  assert.equal(arms.reduce((sum, arm) => sum + arm.programs.square.variableBaseCounts.actual, 0), 146);
});

test('programs expose only typed direct formals, exact coefficient vectors, and stable content digests', () => {
  for (const arm of arms) for (const program of Object.values(arm.programs)) {
    const names = program.kind === 'multiply' ? ['a', 'b'] : ['a'];
    assert.deepEqual(program.inputs.map((entry) => entry.id), names.flatMap((name) => Array.from({ length: arm.degree }, (_, index) => `${name}.c${index}`)));
    assert.ok(program.inputs.every((entry) => entry.type === 'FpCanonical' && entry.representation === 'direct-power-basis-coefficient'));
    assert.deepEqual(program.outputs.map((entry) => entry.coefficientIndex), Array.from({ length: arm.degree }, (_, index) => index));
    const digestable = cloned(program);
    delete digestable.programDigest;
    assert.equal(program.programDigest, sha256(canonicalJson(digestable)));
  }
});

test('the independent SSA evaluator matches DirectExtension on edge and nontrivial vectors for every arm multiply and square', () => {
  for (const arm of arms) {
    const construction = constructionById.get(arm.constructionId);
    const p = BigInt(construction.p);
    const reference = contextFor(construction);
    for (const [left, right] of vectors(p, arm.degree)) {
      assert.deepEqual(evaluateArmSsa(arm.programs.multiply, inputsFor(left, right)), reference.mul(left, right), `${arm.armId} multiply`);
      assert.deepEqual(evaluateArmSsa(arm.programs.square, inputsFor(left)), reference.square(left), `${arm.armId} square`);
    }
  }
});

test('all graphs are flat, topological, immediately reduced, range-complete, and dead-node-free', () => {
  for (const arm of arms) for (const program of Object.values(arm.programs)) {
    assert.deepEqual(validateArmSsaProgram(program), [], `${arm.armId} ${program.kind}`);
    const known = new Set(program.inputs.map((entry) => entry.id));
    const ranges = new Map(program.inputs.map((entry) => [entry.id, entry.range.map(BigInt)]));
    for (const [index, node] of program.nodes.entries()) {
      assert.ok(SCALAR_NODE_OPS.includes(node.op));
      assert.ok(node.args.every((ref) => known.has(ref)), `${node.id} topological references`);
      assert.equal(known.has(node.id), false);
      const range = recomputeNodeRange(node, ranges, program.modulus);
      assert.deepEqual(node.range, range.map(String));
      ranges.set(node.id, range);
      known.add(node.id);
      if (node.op === 'reduce') {
        assert.equal(node.args[0], program.nodes[index - 1].id);
        assert.equal(node.semantics, CANONICAL_REDUCE_SEMANTICS);
      } else {
        assert.equal(program.nodes[index + 1].op, 'reduce');
        assert.equal(program.nodes[index + 1].args[0], node.id);
      }
    }
    assert.equal(program.rangeLedger.length, program.nodes.length);
    assert.ok(program.rangeLedger.every((row) => row.type && row.inputRanges && row.outputRange && row.normalizationState && row.modulus === program.modulus && row.reason));
  }
});

test('variable-base occurrence metadata is exact and excludes every constant scale', () => {
  for (const arm of arms) for (const program of Object.values(arm.programs)) {
    const arithmetic = program.nodes.filter((node) => node.op === 'mul' || node.op === 'square');
    assert.deepEqual(program.variableBaseOccurrences.map((entry) => entry.nodeId), arithmetic.map((node) => node.id));
    assert.equal(program.variableBaseOccurrences.length, program.variableBaseCounts.declared);
    assert.ok(program.variableBaseOccurrences.every((entry) => entry.classification === 'variable-base-Fp-arithmetic' && entry.constantsAndScalesExcluded));
    assert.equal(program.variableBaseOccurrences.some((entry) => entry.op === 'scale'), false);
  }
});

test('a fabricated count-correct scalar-fold graph fails coefficient equality', () => {
  const arm = arms.find((entry) => entry.armId.includes('m31-d6-canonical'));
  const construction = constructionById.get(arm.constructionId);
  const reference = contextFor(construction);
  const left = deterministic(BigInt(construction.p), arm.degree, 71);
  const right = deterministic(BigInt(construction.p), arm.degree, 83);
  const fabricated = cloned(arm.programs.multiply);
  const folded = fabricated.outputs[0].ref;
  fabricated.outputs = fabricated.outputs.map((output) => ({ ...output, ref: folded }));
  assert.equal(fabricated.variableBaseCounts.actual, 36, 'fabrication retains the exact count');
  assert.notDeepEqual(evaluateArmSsa(fabricated, inputsFor(left, right)), reference.mul(left, right));
  assert.ok(validateArmSsaProgram(fabricated).some((error) => error.includes('dead node') || error.includes('digest')));
});

test('Toom matrix cells have exhaustive row-major omit, alias, or unique-scale dispositions', () => {
  for (const arm of arms.filter((entry) => entry.formulaFamily === 'toom5' || entry.formulaFamily === 'toom6')) {
    const source = scheduleArmById.get(arm.armId);
    const [evaluation, interpolation] = source.formula.matrices;
    for (const program of Object.values(arm.programs)) {
      const applications = program.kind === 'multiply' ? [
        [evaluation, 'left'], [evaluation, 'right'], [interpolation, 'inverse-interpolation']
      ] : [[evaluation, 'value'], [interpolation, 'inverse-interpolation']];
      let cursor = 0;
      const scaleIds = new Set();
      for (const [matrix, application] of applications) for (let row = 0; row < matrix.rows; row += 1) for (let column = 0; column < matrix.columns; column += 1) {
        const occurrence = program.matrixOccurrences[cursor++];
        const scalar = BigInt(matrix.entries[row][column]);
        assert.deepEqual([occurrence.matrixId, occurrence.application, occurrence.row, occurrence.column], [matrix.matrixId, application, row, column]);
        assert.equal(occurrence.disposition, scalar === 0n ? 'omit-zero' : scalar === 1n ? 'alias-unit' : 'scale-unique');
        if (occurrence.disposition === 'scale-unique') {
          assert.equal(scaleIds.has(occurrence.scaleNodeId), false);
          scaleIds.add(occurrence.scaleNodeId);
        }
      }
      assert.equal(cursor, program.matrixOccurrences.length);
      const mutation = cloned(program);
      mutation.matrixOccurrences.find((entry) => entry.disposition === 'scale-unique').disposition = 'alias-unit';
      assert.ok(validateArmSsaProgram(mutation).some((error) => error.includes('matrix')));
    }
  }
});

test('every scale binds signed source provenance to its canonical modulus residue', () => {
  let sawNegativeSource = false;
  for (const arm of arms) for (const program of Object.values(arm.programs)) for (const node of program.nodes.filter((entry) => entry.op === 'scale')) {
    assert.equal(node.scalarProvenance, 'signed-source-canonicalized-mod-p');
    assert.equal(node.scalar, node.scalarCanonical);
    assert.equal(BigInt(node.scalarCanonical), mod(BigInt(node.scalarSource), BigInt(program.modulus)));
    sawNegativeSource ||= BigInt(node.scalarSource) < 0n;
  }
  assert.equal(sawNegativeSource, true, 'direct x^5 reduction must preserve -2 signed provenance');
  const mutation = cloned(arms[2].programs.multiply);
  const scale = mutation.nodes.find((node) => node.op === 'scale' && BigInt(node.scalarSource) < 0n);
  scale.scalarCanonical = '2';
  assert.ok(validateArmSsaProgram(mutation).some((error) => error.includes('scalar provenance')));
});

test('formula dispositions cover each source step and forbid a second generic reduction on reduced optimized results', () => {
  for (const arm of arms) for (const program of Object.values(arm.programs)) {
    const source = scheduleArmById.get(arm.armId);
    const coverage = program.formulaOccurrences.filter((entry) => entry.label.startsWith('upstream-dag-step:'));
    assert.equal(coverage.length, source.formula.dagSteps.length);
    assert.deepEqual(coverage.map((entry) => entry.source), source.formula.dagSteps);
    const genericExpected = ['canonical-schoolbook', 'pairwise', 'toom3', 'toom5', 'toom6'].includes(arm.formulaFamily);
    assert.equal(program.nodes.some((node) => node.context.includes('direct-quotient-reduction')), genericExpected);
    assert.equal(program.directReductionDisposition.startsWith('not-emitted'), !genericExpected);
  }
  const tower3Square = arms.at(-1).programs.square;
  const nonEmitted = tower3Square.formulaOccurrences.filter((entry) => entry.label === 'inner-Fp3Square prose declaration');
  assert.equal(nonEmitted.length, 1);
  assert.equal(nonEmitted[0].disposition, 'recorded-non-emitted');
  assert.equal(tower3Square.formulaOccurrences.find((entry) => entry.label === 'upstream-dag-step:0').disposition.includes('expanded-emitted'), false);
});

test('tower maps are direct-wire aliases in exact map and inverse-map order', () => {
  for (const arm of arms.filter((entry) => entry.formulaFamily.startsWith('tower'))) for (const program of Object.values(arm.programs)) {
    assert.deepEqual(validateArmSsaProgram(program), []);
    const direct = program.mapOccurrences.filter((entry) => entry.direction === 'direct-to-tower');
    assert.ok(direct.every((entry) => /^(a|b)\.c[0-5]$/u.test(entry.from) && entry.disposition === 'alias-wire'));
    assert.ok(direct.every((entry) => !program.nodes.some((node) => node.id === entry.from)), 'tower map sources are direct formal wires');
    const inverse = program.mapOccurrences.filter((entry) => entry.direction === 'tower-to-direct');
    assert.deepEqual(inverse.map((entry) => entry.to), Array.from({ length: 6 }, (_, index) => `output.c${index}`));
    assert.deepEqual(inverse.map((entry) => entry.from), program.outputs.map((entry) => entry.ref));
    const mutation = cloned(program);
    mutation.mapOccurrences[0].from = 'a.c5';
    assert.ok(validateArmSsaProgram(mutation).some((error) => error.includes('map wiring')));
  }
});

test('pairwise square is a literal b=a multiply graph with no square substitution or CSE', () => {
  for (const arm of arms.filter((entry) => entry.formulaFamily === 'pairwise')) {
    const program = arm.programs.square;
    assert.ok(program.variableBaseOccurrences.every((entry) => entry.op === 'mul'));
    assert.equal(program.nodes.some((node) => node.op === 'square'), false);
    const diagonals = program.variableBaseOccurrences.filter((entry) => entry.context.some((label) => label.startsWith('pairwise:diagonal:')));
    assert.equal(diagonals.length, arm.degree);
    assert.ok(diagonals.every((entry) => entry.operands[0] === entry.operands[1]));
    const pairs = program.variableBaseOccurrences.filter((entry) => entry.context.some((label) => label.startsWith('pairwise:pair:')));
    assert.ok(pairs.every((entry) => entry.operands[0] !== entry.operands[1]), 'separate left/right evaluations prove no CSE');
  }
});

test('direct Toom square product positions are explicit squares and canonical schoolbook square retains pair products', () => {
  for (const arm of arms.filter((entry) => ['toom3', 'toom5', 'toom6'].includes(entry.formulaFamily))) {
    assert.ok(arm.programs.square.variableBaseOccurrences.every((entry) => entry.op === 'square'));
  }
  for (const arm of arms.filter((entry) => entry.formulaFamily === 'canonical-schoolbook')) {
    const occurrences = arm.programs.square.variableBaseOccurrences;
    assert.equal(occurrences.filter((entry) => entry.op === 'square').length, arm.degree);
    assert.equal(occurrences.filter((entry) => entry.op === 'mul').length, (arm.degree * (arm.degree - 1)) / 2);
  }
});

test('tower substitutions and targeted malformed-graph mutations fail closed', () => {
  const six = arms.find((entry) => entry.formulaFamily === 'tower2x3-six-product').programs.square;
  assert.equal(six.variableBaseOccurrences.length, 12);
  assert.ok(six.variableBaseOccurrences.every((entry) => entry.op === 'mul'));
  assert.deepEqual(validateArmSsaProgram(six), [], 'equal-input substitution creates no dead rhs evaluations');

  const outer = arms.find((entry) => entry.formulaFamily === 'tower2x3-toom3').programs.square;
  assert.equal(outer.variableBaseOccurrences.length, 10);
  assert.ok(outer.variableBaseOccurrences.every((entry) => entry.op === 'mul'));

  const tower3 = arms.find((entry) => entry.formulaFamily === 'tower3x2-karatsuba-toom3').programs.square;
  assert.equal(tower3.variableBaseOccurrences.length, 10);
  assert.ok(tower3.variableBaseOccurrences.every((entry) => entry.op === 'mul'));
  const innerLabels = new Set(tower3.variableBaseOccurrences.map((entry) => entry.context.find((label) => label.startsWith('general-inner-Fp3-Toom3:'))));
  assert.deepEqual([...innerLabels], ['general-inner-Fp3-Toom3:P0-general', 'general-inner-Fp3-Toom3:P1-general']);
  assert.equal(tower3.nodes.some((node) => node.op === 'square'), false);

  const opaque = cloned(tower3);
  opaque.nodes[0].op = 'Fp3Mul';
  assert.ok(validateArmSsaProgram(opaque).some((error) => error.includes('opaque')));
  assert.throws(() => evaluateArmSsa(opaque, inputsFor(Array(6).fill(1n))), /opaque|unsupported/u);

  const missingReduce = cloned(arms[0].programs.multiply);
  missingReduce.nodes.splice(1, 1);
  assert.ok(validateArmSsaProgram(missingReduce).some((error) => error.includes('reduce') || error.includes('later')));
  assert.throws(() => evaluateArmSsa(arms[0].programs.multiply, { 'a.c0': 1n }), /missing input/u);
});

