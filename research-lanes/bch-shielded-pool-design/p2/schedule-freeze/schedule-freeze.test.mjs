import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  FIELD_CONSTANTS,
  RELATION_MAPPING,
  canonicalJson,
  contentDigestFor,
  evaluateCountExpression,
  generateScheduleFreeze,
  inverse,
  makeToomMatrices,
  compareOptimizedOrderEntries,
  optimizedOrderFrame,
  optimizedOrderKey,
  resolveFutureRunOrder,
  validateOptimizedOrderFrame,
  validateScheduleFreezeSemantics,
  verifyFiniteToomMatrices
} from './schedule-freeze.mjs';

const loadJson = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const artifact = loadJson('./schedule-freeze.v1.json');
const schema = loadJson('./schedule-freeze.v1.schema.json');
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const cloned = (value) => structuredClone(value);
const mod = (value, p) => {
  const residue = value % p;
  return residue < 0n ? residue + p : residue;
};
const add = (left, right, p) => mod(left + right, p);
const sub = (left, right, p) => mod(left - right, p);
const mul = (left, right, p) => mod(left * right, p);
const scalar = (left, factor, p) => mul(left, factor, p);

const constructionById = new Map(artifact.fieldConstructions.map((entry) => [entry.constructionId, entry]));
const pointPlans = {
  5: FIELD_CONSTANTS.toom5Points,
  6: FIELD_CONSTANTS.toom6Points
};

const signedPolynomial = (construction) => construction.definingPolynomialAscending.map((entry) => {
  const p = BigInt(construction.p);
  const value = BigInt(entry);
  return value > p / 2n ? value - p : value;
});
const directReduce = (convolution, construction) => {
  const p = BigInt(construction.p);
  const d = construction.degree;
  const f = signedPolynomial(construction);
  const coeffs = convolution.map((entry) => mod(entry, p));
  for (let exponent = coeffs.length - 1; exponent >= d; exponent -= 1) {
    const high = coeffs[exponent];
    if (high !== 0n) {
      for (let index = 0; index < d; index += 1) coeffs[exponent - d + index] = mod(coeffs[exponent - d + index] - high * f[index], p);
    }
  }
  return coeffs.slice(0, d);
};
const directMultiply = (left, right, construction) => {
  const p = BigInt(construction.p);
  const convolution = Array((2 * construction.degree) - 1).fill(0n);
  for (let i = 0; i < construction.degree; i += 1) for (let j = 0; j < construction.degree; j += 1) convolution[i + j] = add(convolution[i + j], mul(left[i], right[j], p), p);
  return directReduce(convolution, construction);
};
const pairwiseMultiply = (left, right, construction) => {
  const p = BigInt(construction.p);
  const d = construction.degree;
  const convolution = Array((2 * d) - 1).fill(0n);
  const diagonal = Array.from({ length: d }, (_, index) => mul(left[index], right[index], p));
  for (let index = 0; index < d; index += 1) convolution[2 * index] = add(convolution[2 * index], diagonal[index], p);
  for (let i = 0; i < d; i += 1) for (let j = i + 1; j < d; j += 1) {
    const pair = mul(add(left[i], left[j], p), add(right[i], right[j], p), p);
    const cross = sub(sub(pair, diagonal[i], p), diagonal[j], p);
    convolution[i + j] = add(convolution[i + j], cross, p);
  }
  return directReduce(convolution, construction);
};
const evaluate = (coefficients, point, p) => coefficients.reduceRight((total, coefficient) => add(mul(total, point, p), coefficient, p), 0n);
const multiplyMatrixVector = (rows, vector, p) => rows.map((row) => row.reduce((total, entry, index) => add(total, mul(entry, vector[index], p), p), 0n));
const toomHighMultiply = (left, right, construction, arm) => {
  const p = BigInt(construction.p);
  const d = construction.degree;
  const finite = pointPlans[d].slice(0, -1).map(BigInt);
  const [evaluation, inverseInterpolation] = arm.formula.matrices;
  const evalRows = evaluation.entries.map((row) => row.map(BigInt));
  const inverseRows = inverseInterpolation.entries.map((row) => row.map(BigInt));
  const pValues = finite.map((point, index) => mul(multiplyMatrixVector([evalRows[index]], left, p)[0], multiplyMatrixVector([evalRows[index]], right, p)[0], p));
  const top = mul(left[d - 1], right[d - 1], p);
  const adjusted = pValues.map((value, index) => sub(value, mul(top, pow(finite[index], BigInt((2 * d) - 2), p), p), p));
  const low = multiplyMatrixVector(inverseRows, adjusted, p);
  return directReduce([...low, top], construction);
};
const pow = (base, exponent, p) => {
  let x = mod(base, p);
  let e = BigInt(exponent);
  let out = 1n;
  while (e > 0n) {
    if ((e & 1n) === 1n) out = mul(out, x, p);
    x = mul(x, x, p);
    e >>= 1n;
  }
  return out;
};
const toom3Convolution = (left, right, p) => {
  const p0 = mul(left[0], right[0], p);
  const p1 = mul(add(add(left[0], left[1], p), left[2], p), add(add(right[0], right[1], p), right[2], p), p);
  const pm = mul(add(sub(left[0], left[1], p), left[2], p), add(sub(right[0], right[1], p), right[2], p), p);
  const p2 = mul(add(add(left[0], scalar(left[1], 2n, p), p), scalar(left[2], 4n, p), p), add(add(right[0], scalar(right[1], 2n, p), p), scalar(right[2], 4n, p), p), p);
  const pinf = mul(left[2], right[2], p);
  const inv2 = inverse(2n, p);
  const inv3 = inverse(3n, p);
  const s = scalar(add(p1, pm, p), inv2, p);
  const d = scalar(sub(p1, pm, p), inv2, p);
  const c2 = sub(sub(s, p0, p), pinf, p);
  const q = scalar(sub(sub(sub(p2, p0, p), scalar(c2, 4n, p), p), scalar(pinf, 16n, p), p), inv2, p);
  const c3 = scalar(sub(q, d, p), inv3, p);
  const c1 = sub(d, c3, p);
  return [p0, c1, c2, c3, pinf];
};
const toom3Direct = (left, right, construction) => directReduce(toom3Convolution(left, right, BigInt(construction.p)), construction);

const fp2 = (a0, a1) => [a0, a1];
const fp2Add = (left, right, p) => fp2(add(left[0], right[0], p), add(left[1], right[1], p));
const fp2Sub = (left, right, p) => fp2(sub(left[0], right[0], p), sub(left[1], right[1], p));
const fp2Scale = (left, value, p) => fp2(scalar(left[0], value, p), scalar(left[1], value, p));
const fp2Mul = (left, right, p) => {
  const m0 = mul(left[0], right[0], p);
  const m1 = mul(left[1], right[1], p);
  const m2 = mul(add(left[0], left[1], p), add(right[0], right[1], p), p);
  return fp2(add(m0, scalar(m1, 5n, p), p), sub(sub(m2, m0, p), m1, p));
};
const fp2Square2 = (left, p) => {
  const s0 = mul(add(left[0], left[1], p), add(left[0], scalar(left[1], 5n, p), p), p);
  const s1 = mul(left[0], left[1], p);
  return fp2(sub(s0, scalar(s1, 6n, p), p), scalar(s1, 2n, p));
};
const fp2MulXi = (left, p) => fp2(scalar(left[1], 5n, p), left[0]);
const fp2Equal = (left, right) => left[0] === right[0] && left[1] === right[1];
const tower2Map = (value) => [fp2(value[0], value[3]), fp2(value[1], value[4]), fp2(value[2], value[5])];
const tower2Unmap = (value) => [value[0][0], value[1][0], value[2][0], value[0][1], value[1][1], value[2][1]];
const tower2Six = (left, right, p, square = false) => {
  const a = tower2Map(left);
  const b = tower2Map(right);
  const product = (x, y) => square && fp2Equal(x, y) ? fp2Square2(x, p) : fp2Mul(x, y, p);
  const t0 = product(a[0], b[0]);
  const t1 = product(a[1], b[1]);
  const t2 = product(a[2], b[2]);
  const d2 = fp2Sub(fp2Sub(product(fp2Add(a[1], a[2], p), fp2Add(b[1], b[2], p)), t1, p), t2, p);
  const d4 = fp2Sub(fp2Sub(product(fp2Add(a[0], a[1], p), fp2Add(b[0], b[1], p)), t0, p), t1, p);
  const d6 = fp2Sub(fp2Sub(product(fp2Add(a[0], a[2], p), fp2Add(b[0], b[2], p)), t0, p), t2, p);
  return tower2Unmap([fp2Add(t0, fp2MulXi(d2, p), p), fp2Add(d4, fp2MulXi(t2, p), p), fp2Add(d6, t1, p)]);
};
const toom3Ring = (left, right, operations, square = false) => {
  const product = (x, y) => square ? operations.square(x) : operations.mul(x, y);
  const p0 = product(left[0], right[0]);
  const p1 = product(operations.add(operations.add(left[0], left[1]), left[2]), operations.add(operations.add(right[0], right[1]), right[2]));
  const pm = product(operations.add(operations.sub(left[0], left[1]), left[2]), operations.add(operations.sub(right[0], right[1]), right[2]));
  const p2 = product(operations.add(operations.add(left[0], operations.scale(left[1], 2n)), operations.scale(left[2], 4n)), operations.add(operations.add(right[0], operations.scale(right[1], 2n)), operations.scale(right[2], 4n)));
  const pinf = product(left[2], right[2]);
  const s = operations.scale(operations.add(p1, pm), operations.inv2);
  const d = operations.scale(operations.sub(p1, pm), operations.inv2);
  const c2 = operations.sub(operations.sub(s, p0), pinf);
  const q = operations.scale(operations.sub(operations.sub(operations.sub(p2, p0), operations.scale(c2, 4n)), operations.scale(pinf, 16n)), operations.inv2);
  const c3 = operations.scale(operations.sub(q, d), operations.inv3);
  return [p0, operations.sub(d, c3), c2, c3, pinf];
};
const tower2Toom = (left, right, p, square = false) => {
  const a = tower2Map(left);
  const b = tower2Map(right);
  const operations = {
    add: (x, y) => fp2Add(x, y, p), sub: (x, y) => fp2Sub(x, y, p), scale: (x, s) => fp2Scale(x, s, p),
    mul: (x, y) => fp2Mul(x, y, p), square: (x) => fp2Square2(x, p), inv2: inverse(2n, p), inv3: inverse(3n, p)
  };
  const c = toom3Ring(a, b, operations, square);
  return tower2Unmap([fp2Add(c[0], fp2MulXi(c[3], p), p), fp2Add(c[1], fp2MulXi(c[4], p), p), c[2]]);
};

const fp3Add = (left, right, p) => left.map((value, index) => add(value, right[index], p));
const fp3Sub = (left, right, p) => left.map((value, index) => sub(value, right[index], p));
const fp3Scale = (left, value, p) => left.map((entry) => scalar(entry, value, p));
const fp3MulV = (left, p) => [scalar(left[2], 5n, p), left[0], left[1]];
const fp3Mul = (left, right, p) => {
  const c = toom3Convolution(left, right, p);
  return [add(c[0], scalar(c[3], 5n, p), p), add(c[1], scalar(c[4], 5n, p), p), c[2]];
};
const tower3Map = (value) => [[value[0], value[2], value[4]], [value[1], value[3], value[5]]];
const tower3Unmap = (value) => [value[0][0], value[1][0], value[0][1], value[1][1], value[0][2], value[1][2]];
const tower3Mul = (left, right, p) => {
  const [a0, a1] = tower3Map(left);
  const [b0, b1] = tower3Map(right);
  const m0 = fp3Mul(a0, b0, p);
  const m1 = fp3Mul(a1, b1, p);
  const m2 = fp3Mul(fp3Add(a0, a1, p), fp3Add(b0, b1, p), p);
  return tower3Unmap([fp3Add(m0, fp3MulV(m1, p), p), fp3Sub(fp3Sub(m2, m0, p), m1, p)]);
};
const tower3Square = (value, p) => {
  const [a, b] = tower3Map(value);
  const p0 = fp3Mul(a, b, p);
  const p1 = fp3Mul(fp3Add(a, b, p), fp3Add(a, fp3MulV(b, p), p), p);
  return tower3Unmap([fp3Sub(p1, fp3Add(fp3MulV(p0, p), p0, p), p), fp3Scale(p0, 2n, p)]);
};

const m89Karatsuba = (left, right, p) => {
  const m0 = mul(left[0], right[0], p);
  const m1 = mul(left[1], right[1], p);
  const m2 = mul(add(left[0], left[1], p), add(right[0], right[1], p), p);
  return [sub(m0, m1, p), sub(sub(m2, m0, p), m1, p)];
};
const m89Square = (value, p) => {
  const s0 = mul(add(value[0], value[1], p), sub(value[0], value[1], p), p);
  const s1 = mul(value[0], value[1], p);
  return [s0, scalar(s1, 2n, p)];
};

const runArmMultiply = (arm, left, right) => {
  const construction = constructionById.get(arm.constructionId);
  const p = BigInt(construction.p);
  if (arm.algorithmId.includes('canonical-schoolbook')) return directMultiply(left, right, construction);
  if (arm.algorithmId.includes('pairwise')) return pairwiseMultiply(left, right, construction);
  if (arm.algorithmId === 'algorithm:m89-d2-karatsuba-special-square-v1') return m89Karatsuba(left, right, p);
  if (arm.algorithmId === 'algorithm:m61-d3-toom3-v1') return toom3Direct(left, right, construction);
  if (arm.algorithmId.includes('toom5') || arm.algorithmId.includes('direct-toom6')) return toomHighMultiply(left, right, construction, arm);
  if (arm.algorithmId.includes('tower2x3-six-product')) return tower2Six(left, right, p);
  if (arm.algorithmId.includes('tower2x3-outer-toom3')) return tower2Toom(left, right, p);
  if (arm.algorithmId.includes('tower3x2')) return tower3Mul(left, right, p);
  throw new Error(`unhandled arm ${arm.algorithmId}`);
};
const runArmSquare = (arm, value) => {
  const construction = constructionById.get(arm.constructionId);
  const p = BigInt(construction.p);
  if (arm.algorithmId === 'algorithm:m89-d2-karatsuba-special-square-v1') return m89Square(value, p);
  if (arm.algorithmId.includes('tower2x3-six-product')) return tower2Six(value, value, p, true);
  if (arm.algorithmId.includes('tower2x3-outer-toom3')) return tower2Toom(value, value, p, true);
  if (arm.algorithmId.includes('tower3x2')) return tower3Square(value, p);
  return runArmMultiply(arm, value, value);
};
const deterministicVector = (p, degree, index, offset) => Array.from({ length: degree }, (_, coefficient) => mod(BigInt((index + 3) * (coefficient + 5) * (offset + 7)) ** 3n + BigInt(index * 13 + coefficient * 17 + offset), p));

test('strict schema, exact fourteen-arm roster, digest manifest, and deterministic regeneration hold', () => {
  assert.equal(validateSchema(artifact), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(artifact, generateScheduleFreeze());
  assert.equal(artifact.contentDigest.value, contentDigestFor(artifact));
  assert.deepEqual(validateScheduleFreezeSemantics(artifact), []);
  assert.equal(artifact.arms.length, 14);
  assert.equal(artifact.arms.filter((arm) => arm.trackId === 'track:canonical-schoolbook').length, 4);
  assert.equal(artifact.arms.filter((arm) => arm.trackId === 'track:optimized').length, 10);
  assert.deepEqual(artifact.relationMapping, RELATION_MAPPING);
  const sums = readFileSync(new URL('./SHA256SUMS', import.meta.url), 'utf8').trim().split('\n');
  assert.equal(sums.length, 6);
  for (const row of sums) {
    const [digest, name] = row.split(/  /u);
    const bytes = readFileSync(new URL(`./${name}`, import.meta.url));
    assert.equal(digest, createHash('sha256').update(bytes).digest('hex'), `digest mismatch for ${name}`);
  }
  assert.equal(readFileSync(new URL('./schedule-freeze.v1.json', import.meta.url)).equals(Buffer.from(canonicalJson(artifact))), true);
});

test('Toom-5 and Toom-6 matrices are exact BigInt finite evaluation/inverse interpolation matrices', () => {
  for (const arm of artifact.arms.filter((entry) => entry.formula.family === 'toom5' || entry.formula.family === 'toom6')) {
    const construction = constructionById.get(arm.constructionId);
    const p = BigInt(construction.p);
    const points = arm.formula.family === 'toom5' ? FIELD_CONSTANTS.toom5Points : FIELD_CONSTANTS.toom6Points;
    const [evaluation, inverseInterpolation] = arm.formula.matrices;
    assert.equal(verifyFiniteToomMatrices(p, construction.degree, points, evaluation.entries, inverseInterpolation.entries), true, arm.armId);
    const regenerated = makeToomMatrices(p, construction.degree, points);
    assert.deepEqual(evaluation.entries, regenerated.evaluation.map((row) => row.map(String)));
    assert.deepEqual(inverseInterpolation.entries, regenerated.inverseInterpolation.map((row) => row.map(String)));
  }
});

test('all formula arms agree with the direct quotient on deterministic vectors and tower maps round-trip', () => {
  for (const arm of artifact.arms) {
    const construction = constructionById.get(arm.constructionId);
    const p = BigInt(construction.p);
    for (let index = 0; index < 12; index += 1) {
      const left = deterministicVector(p, construction.degree, index, 1);
      const right = deterministicVector(p, construction.degree, index, 11);
      assert.deepEqual(runArmMultiply(arm, left, right), directMultiply(left, right, construction), `${arm.armId} multiply vector ${index}`);
      assert.deepEqual(runArmSquare(arm, left), directMultiply(left, left, construction), `${arm.armId} square vector ${index}`);
    }
  }
  const m31d6 = artifact.fieldConstructions.find((entry) => entry.fieldSpecRef === 'field-spec:m31-d6');
  const p = BigInt(m31d6.p);
  for (let index = 0; index < 12; index += 1) {
    const value = deterministicVector(p, 6, index, 23);
    assert.deepEqual(tower2Unmap(tower2Map(value)), value);
    assert.deepEqual(tower3Unmap(tower3Map(value)), value);
  }
});

test('declared variable-base counts are recomputed from the machine-readable formula count derivations', () => {
  for (const arm of artifact.arms) {
    const construction = constructionById.get(arm.constructionId);
    assert.equal(evaluateCountExpression(arm.formula.countDerivation.multiply, construction.degree), arm.declaredVariableBaseCounts.multiply, `${arm.armId} multiply count`);
    assert.equal(evaluateCountExpression(arm.formula.countDerivation.square, construction.degree), arm.declaredVariableBaseCounts.square, `${arm.armId} square count`);
  }
});

test('future run order has an exact raw-byte frame, canonical construction order, and stable optimized sorting', () => {
  const descriptorDigests = Object.fromEntries(artifact.fieldConstructions.map((construction, index) => [
    construction.constructionId,
    `${(index + 1).toString(16).padStart(2, '0')}${'ab'.repeat(31)}`
  ]));
  const schedule = resolveFutureRunOrder(artifact, descriptorDigests);
  assert.deepEqual(schedule.canonical.map((item) => item.constructionId), artifact.fieldConstructions.map((item) => item.constructionId));
  const reference = artifact.arms.filter((item) => item.trackId === 'track:optimized').map((arm) => {
    const digest = descriptorDigests[arm.constructionId];
    const frame = Buffer.concat([Buffer.from(digest, 'ascii'), Buffer.from([0x00]), Buffer.from(arm.armId, 'utf8')]);
    return { arm, armId: arm.armId, key: createHash('sha256').update(frame).digest() };
  }).sort((left, right) => {
    const byKey = Buffer.compare(left.key, right.key);
    return byKey !== 0 ? byKey : Buffer.compare(Buffer.from(left.armId, 'utf8'), Buffer.from(right.armId, 'utf8'));
  });
  assert.deepEqual(schedule.optimized.map(({ arm, keyHex }) => ({ armId: arm.armId, keyHex })), reference.map(({ arm, key }) => ({ armId: arm.armId, keyHex: key.toString('hex') })));

  const armId = artifact.arms.find((item) => item.trackId === 'track:optimized').armId;
  const digest = descriptorDigests[artifact.arms.find((item) => item.armId === armId).constructionId];
  const frame = optimizedOrderFrame(digest, armId);
  assert.equal(frame.subarray(0, 64).toString('ascii'), digest);
  assert.equal(frame[64], 0x00);
  assert.equal(frame.subarray(65).toString('utf8'), armId);
  assert.equal(validateOptimizedOrderFrame(frame, digest, armId), true);
  assert.equal(validateOptimizedOrderFrame(Buffer.concat([Buffer.from(digest, 'ascii'), Buffer.from(armId, 'utf8')]), digest, armId), false, 'missing raw delimiter must fail');
  assert.equal(validateOptimizedOrderFrame(Buffer.concat([Buffer.from(digest, 'ascii'), Buffer.from('00', 'ascii'), Buffer.from(armId, 'utf8')]), digest, armId), false, 'ASCII 00 is not the delimiter byte');
  assert.equal(validateOptimizedOrderFrame(Buffer.concat([Buffer.from(digest, 'hex'), Buffer.from([0]), Buffer.from(armId, 'utf8')]), digest, armId), false, 'raw digest bytes are not lowercase hex ASCII bytes');
  assert.throws(() => optimizedOrderFrame(digest.toUpperCase(), armId), /lowercase/u);
  assert.equal(optimizedOrderKey(digest, armId).length, 32);
  assert.ok(compareOptimizedOrderEntries({ key: Buffer.alloc(32), armId: 'arm:z' }, { key: Buffer.alloc(32), armId: 'arm:zz' }) < 0, 'equal keys must use UTF-8 armId bytes as a stable tie-break');

  const unstableTie = cloned(artifact);
  unstableTie.fairness.phaseOrder.optimizedSort.tieBreak = 'none';
  assert.equal(validateSchema(unstableTie), false, 'schema must reject removal of the tie policy');
  assert.notDeepEqual(validateScheduleFreezeSemantics(unstableTie), []);
});

test('optimized conclusion gate and r18 rationale pin are fail-closed and read-only', (t) => {
  const gateDrift = cloned(artifact);
  gateDrift.fairness.optimizedConclusionGate.onIncompleteOrFailure = 'permit-partial-optimized-conclusion';
  assert.equal(validateSchema(gateDrift), false);
  assert.notDeepEqual(validateScheduleFreezeSemantics(gateDrift), []);

  const source = artifact.provenance.r18Source;
  const sourcePath = resolve(source.repository, source.file);
  if (!existsSync(sourcePath)) {
    t.skip('optional rationale checkout is absent; deterministic generation does not depend on it');
    return;
  }
  assert.equal(execFileSync('git', ['-C', source.repository, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(), source.gitCommit);
  assert.equal(execFileSync('git', ['-C', source.repository, 'status', '--porcelain', '--', source.file], { encoding: 'utf8' }), '');
  assert.equal(createHash('sha256').update(readFileSync(sourcePath)).digest('hex'), source.sha256);
});

test('counts, exact formulas, parser boundary, no-OP_DIV, and no-promotion boundaries fail closed under mutation', () => {
  const mutations = [
    (value) => { value.arms[4].declaredVariableBaseCounts.square = 3; },
    (value) => { value.arms[11].formula.countDerivation.square.args[1].value = 3; },
    (value) => { value.arms[10].formula.matrices[0].entries[1][1] = '9'; },
    (value) => { value.arms[13].formula.dagSteps[2] = 'square=P0-only'; },
    (value) => { value.arms[12].formula.divisionPolicy = 'OP_DIV allowed'; },
    (value) => { value.arms[11].formula.maps[0].formula = 'alternate codec mapping'; },
    (value) => { value.arms.pop(); },
    (value) => { value.fairness.optimizedConclusionGate.silentDrop = 'allowed'; },
    (value) => { value.fairness.phaseOrder.canonicalPhase = 'optimized-first'; },
    (value) => { value.qualification.selection = 'selected'; },
    (value) => { value.status = 'promotion-ready'; },
    (value) => { value.fieldConstructions[1].p = Number(value.fieldConstructions[1].p); },
    (value) => { value.arms[9].formula.matrices = [{ ...value.arms[10].formula.matrices[0], entries: [[Number(value.fieldConstructions[2].p)]] }]; }
  ];
  for (const mutate of mutations) {
    const candidate = cloned(artifact);
    mutate(candidate);
    assert.notDeepEqual(validateScheduleFreezeSemantics(candidate), []);
  }
  const unsafe = cloned(artifact);
  unsafe.fieldConstructions[0].p = Number(unsafe.fieldConstructions[0].p);
  assert.equal(validateSchema(unsafe), false, 'schema must reject unsafe numeric field values');
  const opDiv = cloned(artifact);
  opDiv.arms[0].formula.divisionPolicy = 'OP_DIV';
  assert.equal(validateSchema(opDiv), false, 'schema must reject OP_DIV policy');
  const unknown = cloned(artifact);
  unknown.unexpected = true;
  assert.equal(validateSchema(unknown), false, 'schema must reject unknown top-level fields');
});

test('requested specialized square formulas are independently checked', () => {
  const m89 = constructionById.get('algebra-construction:m89-d2-x2-plus-1-v1');
  const m31d6 = constructionById.get('algebra-construction:m31-d6-x6-minus-5-v1');
  const p89 = BigInt(m89.p);
  const p31 = BigInt(m31d6.p);
  for (let index = 0; index < 32; index += 1) {
    const a = deterministicVector(p89, 2, index, 91);
    assert.deepEqual(m89Square(a, p89), directMultiply(a, a, m89));
    const x = deterministicVector(p31, 6, index, 97);
    assert.deepEqual(tower3Square(x, p31), directMultiply(x, x, m31d6));
    const y = fp2(deterministicVector(p31, 2, index, 101)[0], deterministicVector(p31, 2, index, 103)[1]);
    assert.deepEqual(fp2Square2(y, p31), fp2Mul(y, y, p31));
  }
});

test('M31d6 tower3x2 square DAG fixes exactly two general inner Fp3 Toom-3 nodes', () => {
  const arm = artifact.arms.find((item) => item.algorithmId === 'algorithm:m31-d6-tower3x2-quadratic-toom3-v1');
  assert.ok(arm, 'tower3x2 arm must be present');
  assert.equal(arm.formula.dagSteps[2], 'square:P0=B0*B1;P1=(B0+B1)*(B0+v*B1);R0=P1-(v+1)*P0;R1=2*P0');
  assert.equal(arm.formula.dagSteps[3], 'multiply-substitution:exactly-three-general-inner-Fp3Mul-Toom3-nodes; square-substitution:exactly-two-general-inner-Fp3Mul-Toom3-nodes-for-P0-and-P1;no-data-dependent-or-equal-input-Fp3Square-substitution');
  assert.ok(arm.proofObligations.includes('square-path-uses-exactly-two-general-inner-Fp3Mul-Toom3-nodes-no-data-dependent-substitution'));
  assert.equal(arm.declaredVariableBaseCounts.square, 10);
});
