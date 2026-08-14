import { createHash } from 'node:crypto';

export const SCHEMA_ID = 'shieldkit-labs/p2/schedule-freeze/v1';
export const ARTIFACT_ID = 'schedule-freeze:gate-b-direct-arithmetic-formula-envelope-v1';
export const STATUS = 'formula-envelope-only-unimplemented-premeasurement';
export const RELATION_MAPPING = Object.freeze({
  eMac: 'relation:e-mac=mul-once-then-add-C-and-compare-D',
  eSquareMac: 'relation:e-square-mac=square-once-then-add-C-and-compare-D',
  eInverseCheck: 'relation:e-inverse-check=reject-zero-A-then-verify-mul-A-H-equals-one-only-no-inverse-calculation',
  malformed: 'all-malformed-cases-reject-at-parser-before-selected-arm'
});

const M31 = (1n << 31n) - 1n;
const M61 = (1n << 61n) - 1n;
const M89 = (1n << 89n) - 1n;
const ZERO = 0n;
const ONE = 1n;

export const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const contentDigestFor = (value) => {
  const copy = structuredClone(value);
  delete copy.contentDigest;
  return sha256(canonicalize(copy));
};
export const canonicalJson = (value) => `${JSON.stringify(value, null, 2)}\n`;

const LOWERCASE_SHA256_HEX = /^[0-9a-f]{64}$/u;
const utf8Bytes = (value) => Buffer.from(value, 'utf8');
const descriptorDigestFor = (bindings, constructionId) => bindings instanceof Map ? bindings.get(constructionId) : bindings?.[constructionId];
export const optimizedOrderFrame = (descriptorContentDigestHex, armId) => {
  if (typeof descriptorContentDigestHex !== 'string' || !LOWERCASE_SHA256_HEX.test(descriptorContentDigestHex)) throw new TypeError('descriptor content digest must be exactly lowercase 64-character SHA-256 hex');
  if (typeof armId !== 'string' || armId.length === 0) throw new TypeError('armId must be a nonempty UTF-8 string');
  return Buffer.concat([Buffer.from(descriptorContentDigestHex, 'ascii'), Buffer.from([0x00]), utf8Bytes(armId)]);
};
export const validateOptimizedOrderFrame = (frame, descriptorContentDigestHex, armId) => Buffer.isBuffer(frame) && frame.equals(optimizedOrderFrame(descriptorContentDigestHex, armId));
export const optimizedOrderKey = (descriptorContentDigestHex, armId) => createHash('sha256').update(optimizedOrderFrame(descriptorContentDigestHex, armId)).digest();
export const compareOptimizedOrderEntries = (left, right) => {
  const keyOrder = Buffer.compare(Buffer.from(left.key), Buffer.from(right.key));
  return keyOrder !== 0 ? keyOrder : Buffer.compare(utf8Bytes(left.armId), utf8Bytes(right.armId));
};
export const resolveFutureRunOrder = (artifact, descriptorContentDigestByConstruction) => {
  const canonical = [];
  for (const construction of artifact.fieldConstructions) {
    const matches = artifact.arms.filter((item) => item.trackId === 'track:canonical-schoolbook' && item.constructionId === construction.constructionId);
    if (matches.length !== 1) throw new Error(`expected exactly one canonical arm for ${construction.constructionId}`);
    canonical.push(matches[0]);
  }
  const optimized = artifact.arms
    .filter((item) => item.trackId === 'track:optimized')
    .map((item) => {
      const digest = descriptorDigestFor(descriptorContentDigestByConstruction, item.constructionId);
      return { arm: item, armId: item.armId, descriptorContentDigestHex: digest, key: optimizedOrderKey(digest, item.armId) };
    })
    .sort(compareOptimizedOrderEntries)
    .map(({ arm, key }) => ({ arm, keyHex: key.toString('hex') }));
  return { canonical, optimized };
};

const mod = (value, p) => {
  const residue = value % p;
  return residue < ZERO ? residue + p : residue;
};
const pow = (base, exponent, p) => {
  let x = mod(base, p);
  let e = BigInt(exponent);
  let out = ONE;
  while (e > ZERO) {
    if ((e & ONE) === ONE) out = mod(out * x, p);
    x = mod(x * x, p);
    e >>= ONE;
  }
  return out;
};
export const inverse = (value, p) => {
  let oldR = mod(value, p);
  let r = p;
  let oldT = ONE;
  let t = ZERO;
  while (r !== ZERO) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldT, t] = [t, oldT - q * t];
  }
  if (oldR !== ONE) throw new RangeError('non-invertible field element');
  return mod(oldT, p);
};
const fieldDecimal = (value, p) => mod(value, p).toString();
const deepEqual = (left, right) => canonicalize(left) === canonicalize(right);

const highMask = (unusedHighBits) => ((0xff << (8 - unusedHighBits)) & 0xff).toString(16).padStart(2, '0');
const elementHex = (degree, limbBytes, one = false) => {
  const bytes = new Uint8Array(degree * limbBytes);
  if (one) bytes[0] = 1;
  return Buffer.from(bytes).toString('hex');
};
const directCodec = (tag, q, degree) => {
  const limbBytes = Math.ceil(q / 8);
  const unusedHighBits = limbBytes * 8 - q;
  return {
    codecId: `codec:direct-power-basis-${tag}-fixed-le-v1`,
    basis: 'direct-power-basis',
    coefficientOrder: 'c0-to-cd-minus-1',
    baseLimbEncoding: 'fixed-width-unsigned-little-endian',
    baseLimbBytes: limbBytes,
    elementBytes: limbBytes * degree,
    modulusBitLength: q,
    unusedHighBits,
    unusedHighBitMaskHex: highMask(unusedHighBits),
    highBitPolicy: 'reject-before-numeric-decode',
    coefficientRange: 'reject-unless-0<=coefficient<p',
    fullConsumption: true,
    zeroHex: elementHex(degree, limbBytes),
    oneHex: elementHex(degree, limbBytes, true),
    towerCoordinates: 'internal-only-never-wire-or-codec'
  };
};

const CONSTRUCTIONS = Object.freeze([
  Object.freeze({
    tag: 'm89-d2', constructionId: 'algebra-construction:m89-d2-x2-plus-1-v1', fieldSpecRef: 'field-spec:m89-d2',
    p: M89, q: 89, degree: 2, polynomial: [1n, 0n, 1n], quotient: 'x^2=-1', codec: directCodec('m89-d2', 89, 2),
    reduction: '(C0-C2,C1)'
  }),
  Object.freeze({
    tag: 'm61-d3', constructionId: 'algebra-construction:m61-d3-x3-minus-5-v1', fieldSpecRef: 'field-spec:m61-d3',
    p: M61, q: 61, degree: 3, polynomial: [-5n, 0n, 0n, 1n], quotient: 'x^3=5', codec: directCodec('m61-d3', 61, 3),
    reduction: '(C0+5C3,C1+5C4,C2)'
  }),
  Object.freeze({
    tag: 'm31-d5', constructionId: 'algebra-construction:m31-d5-x5-plus-2x-minus-1-v1', fieldSpecRef: 'field-spec:m31-d5',
    p: M31, q: 31, degree: 5, polynomial: [-1n, 2n, 0n, 0n, 0n, 1n], quotient: 'x^5=1-2x', codec: directCodec('m31-d5', 31, 5),
    reduction: '(C0+C5,C1-2C5+C6,C2-2C6+C7,C3-2C7+C8,C4-2C8)'
  }),
  Object.freeze({
    tag: 'm31-d6', constructionId: 'algebra-construction:m31-d6-x6-minus-5-v1', fieldSpecRef: 'field-spec:m31-d6',
    p: M31, q: 31, degree: 6, polynomial: [-5n, 0n, 0n, 0n, 0n, 0n, 1n], quotient: 'x^6=5', codec: directCodec('m31-d6', 31, 6),
    reduction: '(C0+5C6,C1+5C7,C2+5C8,C3+5C9,C4+5C10,C5)'
  })
]);

const constructionArtifact = (construction) => ({
  constructionId: construction.constructionId,
  fieldSpecRef: construction.fieldSpecRef,
  futureDescriptorRef: null,
  p: construction.p.toString(),
  q: construction.q,
  degree: construction.degree,
  definingPolynomialAscending: construction.polynomial.map((value) => fieldDecimal(value, construction.p)),
  quotientRelation: construction.quotient,
  codec: construction.codec,
  descriptorResolution: 'future-exact-descriptor-and-certificate-required-before-execution'
});

const constant = (label, value, role) => ({ label, value: value.toString(), role });
const reduction = (formula) => ({ stage: 'after-extension-product-before-relation-add-or-equality', formula });
const countConstant = (value) => ({ op: 'constant', value });
const countDegree = () => ({ op: 'degree' });
const countPairs = () => ({ op: 'pair-count' });
const countAdd = (...args) => ({ op: 'add', args });
const countMultiply = (...args) => ({ op: 'multiply', args });
export const evaluateCountExpression = (expression, degree) => {
  if (expression.op === 'constant') return expression.value;
  if (expression.op === 'degree') return degree;
  if (expression.op === 'pair-count') return (degree * (degree - 1)) / 2;
  const values = expression.args.map((item) => evaluateCountExpression(item, degree));
  return expression.op === 'add' ? values.reduce((sum, value) => sum + value, 0) : values.reduce((product, value) => product * value, 1);
};
const formula = ({ formulaId, family, dagSteps, constants = [], matrices = [], maps = [], countDerivation, reductionFormula }) => ({
  formulaId,
  family,
  dagSteps,
  constants,
  matrices,
  maps,
  countDerivation,
  reduction: reduction(reductionFormula),
  divisionPolicy: 'fixed-canonical-inverse-scalar-multiplication-only;OP_DIV-forbidden',
  dagIntegrity: 'every-declared-node-reaches-an-output;no-optional-cse-or-dead-node'
});
const baseCounts = (multiply, square) => ({
  multiply,
  square,
  interpretation: 'variable-variable-base-Fp-multiplications-only-not-opcode-byte-stack-cost-or-rank-lower-bound'
});
const proofObligations = (extra = []) => [
  'symbolic-DAG-equals-direct-polynomial-quotient-relation',
  'direct-power-basis-codec-round-trip-is-unchanged',
  'parser-and-canonicality-reject-before-selected-arm',
  'all-declared-DAG-nodes-reach-the-declared-output',
  'no-OP_DIV-and-all-fixed-inverses-are-canonical-field-scalars',
  ...extra
];

const arm = (construction, trackId, algorithmId, shape, counts, obligations = []) => ({
  armId: `arm:${trackId === 'track:canonical-schoolbook' ? 'canonical' : 'optimized'}:${construction.tag}-${algorithmId}-v1`,
  constructionId: construction.constructionId,
  fieldSpecRef: construction.fieldSpecRef,
  codecId: construction.codec.codecId,
  trackId,
  algorithmId: `algorithm:${construction.tag}-${algorithmId}-v1`,
  formula: shape,
  declaredVariableBaseCounts: baseCounts(...counts),
  relationMapping: RELATION_MAPPING,
  parserBeforeArithmetic: true,
  executionStatus: 'closed-unimplemented-premeasurement',
  proofObligations: proofObligations(obligations)
});

const canonicalSchoolbook = (construction) => formula({
  formulaId: `formula:${construction.tag}-canonical-schoolbook-v1`,
  family: 'canonical-schoolbook',
  dagSteps: [
    `Ck=sum(i+j=k,a_i*b_j) for k=0..${2 * construction.degree - 2}`,
    `square-Ck=sum(i<=j;i+j=k,(i==j?a_i*a_i:2*a_i*a_j))`,
    `reduce-direct-product=${construction.reduction}`
  ],
  constants: construction.tag === 'm31-d5' ? [constant('minus-two', -2n, 'direct-reduction')] : construction.tag === 'm89-d2' ? [constant('minus-one', -1n, 'direct-reduction')] : [constant('five', 5n, 'direct-reduction')],
  countDerivation: { multiply: countMultiply(countDegree(), countDegree()), square: countAdd(countDegree(), countPairs()) },
  reductionFormula: construction.reduction
});

const pairwise = (construction) => formula({
  formulaId: `formula:${construction.tag}-pairwise-d${construction.degree}-v1`,
  family: 'pairwise',
  dagSteps: [
    `diagonal[i]=a_i*b_i for i=0..${construction.degree - 1}`,
    `pair[i,j]=(a_i+a_j)*(b_i+b_j) for 0<=i<j<${construction.degree}`,
    'cross[i,j]=pair[i,j]-diagonal[i]-diagonal[j]',
    'Ck=sum(diagonal[i] where 2i=k)+sum(cross[i,j] where i+j=k)',
    `square-reuses-the-same-DAG-with-b=a;pair-count=C(${construction.degree},2)`,
    `reduce-direct-product=${construction.reduction}`
  ],
  constants: construction.tag === 'm31-d5' ? [constant('minus-two', -2n, 'direct-reduction')] : [constant('five', 5n, 'direct-reduction')],
  countDerivation: { multiply: countAdd(countDegree(), countPairs()), square: countAdd(countDegree(), countPairs()) },
  reductionFormula: construction.reduction
});

const matrix = (matrixId, entries, orientation) => ({
  matrixId,
  rows: entries.length,
  columns: entries[0].length,
  entryEncoding: 'canonical-residue-decimal-mod-p',
  entries: entries.map((row) => row.map((value) => value.toString())),
  orientation
});

const invertMatrix = (input, p) => {
  const size = input.length;
  const work = input.map((row, rowIndex) => [
    ...row.map((value) => mod(value, p)),
    ...Array.from({ length: size }, (_, columnIndex) => rowIndex === columnIndex ? ONE : ZERO)
  ]);
  for (let pivot = 0; pivot < size; pivot += 1) {
    let pivotRow = pivot;
    while (pivotRow < size && work[pivotRow][pivot] === ZERO) pivotRow += 1;
    if (pivotRow === size) throw new Error('singular interpolation matrix');
    [work[pivot], work[pivotRow]] = [work[pivotRow], work[pivot]];
    const scale = inverse(work[pivot][pivot], p);
    work[pivot] = work[pivot].map((value) => mod(value * scale, p));
    for (let row = 0; row < size; row += 1) {
      if (row === pivot) continue;
      const scaleOut = work[row][pivot];
      if (scaleOut === ZERO) continue;
      work[row] = work[row].map((value, index) => mod(value - scaleOut * work[pivot][index], p));
    }
  }
  return work.map((row) => row.slice(size));
};
const pointValue = (point) => BigInt(point);
const finiteEvaluationMatrix = (points, inputDegree, p) => points.map((point) => Array.from({ length: inputDegree }, (_, index) => pow(pointValue(point), index, p)));
const finiteInterpolationInverse = (points, outputWithoutTopLength, p) => invertMatrix(
  points.map((point) => Array.from({ length: outputWithoutTopLength }, (_, index) => pow(pointValue(point), index, p))), p
);
export const makeToomMatrices = (p, inputDegree, orderedPoints) => {
  const finitePoints = orderedPoints.filter((point) => point !== 'infinity');
  if (finitePoints.length !== (2 * inputDegree) - 2 || orderedPoints.at(-1) !== 'infinity') throw new Error('invalid finite-plus-infinity Toom point plan');
  return {
    finitePoints,
    evaluation: finiteEvaluationMatrix(finitePoints, inputDegree, p),
    inverseInterpolation: finiteInterpolationInverse(finitePoints, (2 * inputDegree) - 2, p)
  };
};

const TOOM3_STEPS = Object.freeze([
  'P0=A(0)*B(0)',
  'P1=A(1)*B(1)',
  'Pm=A(-1)*B(-1)',
  'P2=A(2)*B(2)',
  'Pinf=a2*b2',
  'c0=P0;c4=Pinf;s=(P1+Pm)*inv2;d=(P1-Pm)*inv2;c2=s-c0-c4',
  'q=(P2-c0-4c2-16c4)*inv2;c3=(q-d)*inv3;c1=d-c3'
]);
const toom3 = (construction) => formula({
  formulaId: `formula:${construction.tag}-toom3-v1`,
  family: 'toom3',
  dagSteps: [...TOOM3_STEPS, `reduce-direct-product=${construction.reduction}`],
  constants: [
    constant('two', 2n, 'evaluation-and-square'), constant('three', 3n, 'interpolation-denominator'),
    constant('four', 4n, 'interpolation'), constant('sixteen', 16n, 'interpolation'),
    constant('inv2', inverse(2n, construction.p), 'canonical-fixed-inverse'),
    constant('inv3', inverse(3n, construction.p), 'canonical-fixed-inverse'),
    constant('five', 5n, 'direct-reduction')
  ],
  countDerivation: { multiply: countConstant(5), square: countConstant(5) },
  reductionFormula: construction.reduction
});
const toomHighDegree = (construction, family, orderedPoints) => {
  const plan = makeToomMatrices(construction.p, construction.degree, orderedPoints);
  return formula({
    formulaId: `formula:${construction.tag}-${family}-v1`,
    family,
    dagSteps: [
      `ordered-points=${JSON.stringify(orderedPoints)}`,
      'for-each-finite-point-s:EA[s]=sum(i,s^i*a_i);EB[s]=sum(i,s^i*b_i);P[s]=EA[s]*EB[s]',
      `Pinf=a_${construction.degree - 1}*b_${construction.degree - 1}=C_${(2 * construction.degree) - 2}`,
      `for-each-finite-s:Q[s]=P[s]-s^${(2 * construction.degree) - 2}*Pinf`,
      `C_0..C_${(2 * construction.degree) - 3}=inverse-interpolation-matrix*Q`,
      `reduce-direct-product=${construction.reduction}`
    ],
    constants: [constant('top-coefficient', 1n, 'known-infinity-product-term')],
    matrices: [
      matrix(`matrix:${construction.tag}-${family}-finite-evaluation-v1`, plan.evaluation, 'rows=finite-points-in-listed-order;columns=input-coefficients-c0-through-c(d-1)'),
      matrix(`matrix:${construction.tag}-${family}-inverse-interpolation-v1`, plan.inverseInterpolation, 'rows=output-coefficients-c0-through-c(2d-3);columns=finite-points-in-listed-order-after-top-term-subtraction')
    ],
    countDerivation: { multiply: countConstant((2 * construction.degree) - 1), square: countConstant((2 * construction.degree) - 1) },
    reductionFormula: construction.reduction
  });
};

const m89Karatsuba = (construction) => formula({
  formulaId: 'formula:m89-d2-karatsuba-special-square-v1',
  family: 'karatsuba-quadratic',
  dagSteps: [
    'mul:m0=a0*b0;m1=a1*b1;m2=(a0+a1)*(b0+b1);r0=m0-m1;r1=m2-m0-m1',
    'square:s0=(a0+a1)*(a0-a1);s1=a0*a1;r0=s0;r1=2*s1',
    'reduce-direct-product=(C0-C2,C1)'
  ],
  constants: [constant('minus-one', -1n, 'direct-reduction'), constant('two', 2n, 'special-square')],
  countDerivation: { multiply: countConstant(3), square: countConstant(2) },
  reductionFormula: construction.reduction
});

const tower2x3Maps = Object.freeze([
  { mapId: 'map:m31-d6-direct-to-tower2x3-v1', direction: 'direct-to-tower', formula: 'Phi2x3(c0..c5)=(c0+c3*u,c1+c4*u,c2+c5*u);u=x^3;u^2=5;x^3=u', codecBoundary: 'internal-only-direct-power-basis-wire-unchanged' },
  { mapId: 'map:m31-d6-tower2x3-to-direct-v1', direction: 'tower-to-direct', formula: 'Phi2x3Inverse(A0,A1,A2)=(A0.c0,A1.c0,A2.c0,A0.c1,A1.c1,A2.c1)', codecBoundary: 'internal-only-direct-power-basis-wire-unchanged' }
]);
const tower3x2Maps = Object.freeze([
  { mapId: 'map:m31-d6-direct-to-tower3x2-v1', direction: 'direct-to-tower', formula: 'Phi3x2(c0..c5)=(c0+c2*v+c4*v^2,c1+c3*v+c5*v^2);v=x^2;v^3=5;x^2=v', codecBoundary: 'internal-only-direct-power-basis-wire-unchanged' },
  { mapId: 'map:m31-d6-tower3x2-to-direct-v1', direction: 'tower-to-direct', formula: 'Phi3x2Inverse(B0,B1)=(B0.c0,B1.c0,B0.c1,B1.c1,B0.c2,B1.c2)', codecBoundary: 'internal-only-direct-power-basis-wire-unchanged' }
]);
const fp2Steps = Object.freeze([
  'Fp2Mul(a+bu,c+du):m0=a*c;m1=b*d;m2=(a+b)*(c+d);out=(m0+5m1)+(m2-m0-m1)u',
  'Fp2Square2(a+bu):s0=(a+b)*(a+5b);s1=a*b;out=(s0-6s1)+(2s1)u',
  'mulXi(a+bu)=5b+au'
]);
const tower2x3SixProduct = (construction) => formula({
  formulaId: 'formula:m31-d6-tower2x3-six-product-r18-v1',
  family: 'tower2x3-six-product',
  dagSteps: [
    ...fp2Steps,
    't0=A0*B0;t1=A1*B1;t2=A2*B2',
    'd2=(A1+A2)*(B1+B2)-t1-t2;R0=t0+mulXi(d2)',
    'd4=(A0+A1)*(B0+B1)-t0-t1;R1=d4+mulXi(t2)',
    'd6=(A0+A2)*(B0+B2)-t0-t2;R2=d6+t1',
    'square-substitution:replace-each-of-the-six-Fp2Mul-nodes-with-Fp2Square2-on-its-equal-input',
    'unmap-Phi2x3Inverse-after-the-six-product-cubic-result'
  ],
  constants: [constant('five', 5n, 'u-square-and-mulXi'), constant('six', 6n, 'Fp2Square2'), constant('two', 2n, 'Fp2Square2')],
  maps: tower2x3Maps,
  countDerivation: { multiply: countMultiply(countConstant(6), countConstant(3)), square: countMultiply(countConstant(6), countConstant(2)) },
  reductionFormula: construction.reduction
});
const tower2x3Toom3 = (construction) => formula({
  formulaId: 'formula:m31-d6-tower2x3-outer-toom3-v1',
  family: 'tower2x3-toom3',
  dagSteps: [
    ...fp2Steps,
    'outer-Fp2-coefficients=(A0,A1,A2);apply-the-exact-Toom3-DAG-over-Fp2',
    'multiply-substitution:each-of-five-outer-products-is-Fp2Mul',
    'square-substitution:each-of-five-outer-products-is-Fp2Square2',
    'outer-reduction:x^3=u;R0=C0+mulXi(C3);R1=C1+mulXi(C4);R2=C2',
    'unmap-Phi2x3Inverse'
  ],
  constants: [
    constant('five', 5n, 'u-square-and-mulXi'), constant('six', 6n, 'Fp2Square2'), constant('two', 2n, 'Fp2Square2-and-Toom3'),
    constant('inv2', inverse(2n, construction.p), 'canonical-fixed-inverse-on-each-Fp2-component'), constant('inv3', inverse(3n, construction.p), 'canonical-fixed-inverse-on-each-Fp2-component')
  ],
  maps: tower2x3Maps,
  countDerivation: { multiply: countMultiply(countConstant(5), countConstant(3)), square: countMultiply(countConstant(5), countConstant(2)) },
  reductionFormula: construction.reduction
});
const tower3x2 = (construction) => formula({
  formulaId: 'formula:m31-d6-tower3x2-quadratic-toom3-v1',
  family: 'tower3x2-karatsuba-toom3',
  dagSteps: [
    'inner-Fp3Mul=exact-Toom3-DAG-over-Fp-with-v^3=5;inner-Fp3Square=exact-Toom3-DAG-with-equal-inputs',
    'mul:M0=B0*C0;M1=B1*C1;M2=(B0+B1)*(C0+C1);R0=M0+v*M1;R1=M2-M0-M1',
    'square:P0=B0*B1;P1=(B0+B1)*(B0+v*B1);R0=P1-(v+1)*P0;R1=2*P0',
    'multiply-substitution:exactly-three-general-inner-Fp3Mul-Toom3-nodes; square-substitution:exactly-two-general-inner-Fp3Mul-Toom3-nodes-for-P0-and-P1;no-data-dependent-or-equal-input-Fp3Square-substitution',
    'unmap-Phi3x2Inverse'
  ],
  constants: [
    constant('five', 5n, 'v-cubic-reduction-and-outer-v-multiply'), constant('one', 1n, 'outer-square-v-plus-one'), constant('two', 2n, 'outer-square'),
    constant('inv2', inverse(2n, construction.p), 'canonical-fixed-inverse-in-inner-Toom3'), constant('inv3', inverse(3n, construction.p), 'canonical-fixed-inverse-in-inner-Toom3')
  ],
  maps: tower3x2Maps,
  countDerivation: { multiply: countMultiply(countConstant(3), countConstant(5)), square: countMultiply(countConstant(2), countConstant(5)) },
  reductionFormula: construction.reduction
});

const toom5Points = ['0', '1', '-1', '2', '-2', '3', '-3', '4', 'infinity'];
const toom6Points = ['0', '1', '-1', '2', '-2', '3', '-3', '4', '-4', '5', 'infinity'];
const OPTIMIZED_CONCLUSION_GATE = Object.freeze({
  scope: 'per-construction-per-epoch',
  requiredArmSet: 'all-precommitted-optimized-arms-for-that-construction',
  onIncompleteOrFailure: 'block-all-optimized-conclusions-for-that-construction-in-that-epoch',
  silentDrop: 'forbidden',
  terminalFailureScope: 'exact-constructionId-codecId-algorithmId-trackId-only',
  wholeFamilyResult: 'forbidden-without-representation-independent-bound-or-precommitted-envelope-exhaustion'
});
const PHASE_ORDER = Object.freeze({
  canonicalPhase: 'first',
  canonicalArmOrder: 'fieldConstructions-array-order;exactly-one-canonical-arm-per-construction',
  optimizedKey: {
    algorithm: 'sha256',
    descriptorDigestEncoding: 'lowercase-64-char-hex-ascii',
    descriptorDigestBinding: 'exact-future-descriptor-content-digest-for-arm-construction',
    delimiterHex: '00',
    armIdEncoding: 'utf-8',
    frame: 'descriptor-content-digest-lowercase-hex-ascii-bytes||raw-0x00-byte||utf8-armId'
  },
  optimizedSort: {
    primary: 'unsigned-lexicographic-32-byte-sha256-key-ascending',
    tieBreak: 'utf8-armId-byte-lexicographic-ascending'
  },
  resolution: 'descriptor-digests-unresolved-until-future-exact-descriptors'
});

export const generateScheduleFreeze = () => {
  const [m89, m61d3, m31d5, m31d6] = CONSTRUCTIONS;
  const arms = [
    arm(m89, 'track:canonical-schoolbook', 'canonical-schoolbook', canonicalSchoolbook(m89), [4, 3]),
    arm(m61d3, 'track:canonical-schoolbook', 'canonical-schoolbook', canonicalSchoolbook(m61d3), [9, 6]),
    arm(m31d5, 'track:canonical-schoolbook', 'canonical-schoolbook', canonicalSchoolbook(m31d5), [25, 15]),
    arm(m31d6, 'track:canonical-schoolbook', 'canonical-schoolbook', canonicalSchoolbook(m31d6), [36, 21]),
    arm(m89, 'track:optimized', 'karatsuba-special-square', m89Karatsuba(m89), [3, 2]),
    arm(m61d3, 'track:optimized', 'pairwise-d3', pairwise(m61d3), [6, 6]),
    arm(m61d3, 'track:optimized', 'toom3', toom3(m61d3), [5, 5]),
    arm(m31d5, 'track:optimized', 'pairwise-d5', pairwise(m31d5), [15, 15]),
    arm(m31d5, 'track:optimized', 'toom5', toomHighDegree(m31d5, 'toom5', toom5Points), [9, 9]),
    arm(m31d6, 'track:optimized', 'pairwise-d6', pairwise(m31d6), [21, 21]),
    arm(m31d6, 'track:optimized', 'direct-toom6', toomHighDegree(m31d6, 'toom6', toom6Points), [11, 11]),
    arm(m31d6, 'track:optimized', 'tower2x3-six-product-r18', tower2x3SixProduct(m31d6), [18, 12], ['r18-source-is-rationale-only-and-adaptation-remains-unimplemented']),
    arm(m31d6, 'track:optimized', 'tower2x3-outer-toom3', tower2x3Toom3(m31d6), [15, 10]),
    arm(m31d6, 'track:optimized', 'tower3x2-quadratic-toom3', tower3x2(m31d6), [15, 10], ['square-path-uses-exactly-two-general-inner-Fp3Mul-Toom3-nodes-no-data-dependent-substitution'])
  ];
  const artifact = {
    schema: SCHEMA_ID,
    artifactId: ARTIFACT_ID,
    status: STATUS,
    evidenceClassification: 'not-evidence',
    qualification: {
      componentScope: 'gate-b-formula-envelope-only', selection: 'none', tupleRef: null,
      fieldRanking: 'none', proofSystemRanking: 'none', protocolRanking: 'none', protocolRoles: [],
      circleDomain: null, deepStrategy: null, soundnessEventDag: null
    },
    fieldConstructions: CONSTRUCTIONS.map(constructionArtifact),
    arms,
    relationMapping: RELATION_MAPPING,
    fairness: {
      armCount: 14,
      futureEpochBindings: ['descriptor-content-digest', 'canonical-corpus-digest', 'relation-contract-digest', 'engine-roster', 'execution-profile-digest', 'toolchain-epoch-id'],
      terminalAccounting: 'every-precommitted-arm-must-have-explicit-terminal-accounting',
      silentDropPolicy: 'forbidden',
      failureScope: 'failure-eliminates-only-exact-constructionId-codecId-algorithmId-trackId;never-whole-p-d-family-without-representation-independent-bound-or-precommitted-envelope-exhaustion',
      optimizedConclusionGate: OPTIMIZED_CONCLUSION_GATE,
      crossEnginePolicy: 'agreement-only-within-arm-case-metric',
      crossArmPolicy: 'only-after-complete-shared-epoch',
      rerunPolicy: 'preserve-all-reruns-never-replace',
      phaseOrder: PHASE_ORDER
    },
    provenance: {
      r18Source: {
        repository: '/home/toorik/Projects/ZK-Proofs/Groth16-Formal',
        gitCommit: 'df06767f75479e7ae123571d60f6cafc284282a4',
        file: 'Groth16/Field/Fp6.lean',
        sha256: 'a1ff6f8081521bd03cfa8419a726fb8792c0b540819bbed54f58928cb4404953',
        lines: '39-69',
        role: 'rationale-only-for-arm:optimized:m31-d6-tower2x3-six-product-r18'
      },
      adaptationStatus: 'source-adaptation-unimplemented-not-evidence-not-selection',
      legacyFilesModified: false
    },
    contentDigest: { algorithm: 'sha256-jcs-omit-contentDigest', value: null }
  };
  artifact.contentDigest.value = contentDigestFor(artifact);
  return artifact;
};

const expectedArmCounts = new Map([
  ['algorithm:m89-d2-canonical-schoolbook-v1', [4, 3]],
  ['algorithm:m61-d3-canonical-schoolbook-v1', [9, 6]],
  ['algorithm:m31-d5-canonical-schoolbook-v1', [25, 15]],
  ['algorithm:m31-d6-canonical-schoolbook-v1', [36, 21]],
  ['algorithm:m89-d2-karatsuba-special-square-v1', [3, 2]],
  ['algorithm:m61-d3-pairwise-d3-v1', [6, 6]],
  ['algorithm:m61-d3-toom3-v1', [5, 5]],
  ['algorithm:m31-d5-pairwise-d5-v1', [15, 15]],
  ['algorithm:m31-d5-toom5-v1', [9, 9]],
  ['algorithm:m31-d6-pairwise-d6-v1', [21, 21]],
  ['algorithm:m31-d6-direct-toom6-v1', [11, 11]],
  ['algorithm:m31-d6-tower2x3-six-product-r18-v1', [18, 12]],
  ['algorithm:m31-d6-tower2x3-outer-toom3-v1', [15, 10]],
  ['algorithm:m31-d6-tower3x2-quadratic-toom3-v1', [15, 10]]
]);

const checkMatrixShapeAndValues = (entry, p, errors) => {
  const { rows, columns, entries } = entry;
  if (entries.length !== rows || entries.some((row) => row.length !== columns)) errors.push(`${entry.matrixId}: matrix shape mismatch`);
  for (const value of entries.flat()) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/u.test(value)) errors.push(`${entry.matrixId}: matrix entry is not canonical decimal`);
    else if (BigInt(value) >= p) errors.push(`${entry.matrixId}: matrix entry is outside Fp`);
  }
};
export const validateScheduleFreezeSemantics = (artifact, { expected = generateScheduleFreeze() } = {}) => {
  const errors = [];
  if (!artifact || typeof artifact !== 'object') return ['artifact is not an object'];
  if (artifact?.contentDigest?.value !== contentDigestFor(artifact)) errors.push('content digest mismatch');
  if (!deepEqual(artifact, expected)) errors.push('artifact differs from deterministic precommitted regeneration');
  if (artifact.arms?.length !== 14) errors.push('roster must contain exactly fourteen arms');
  const ids = artifact.arms?.map((item) => item.armId) ?? [];
  if (new Set(ids).size !== 14) errors.push('duplicate or missing arm identity');
  const optimized = artifact.arms?.filter((item) => item.trackId === 'track:optimized') ?? [];
  const canonical = artifact.arms?.filter((item) => item.trackId === 'track:canonical-schoolbook') ?? [];
  if (optimized.length !== 10 || canonical.length !== 4) errors.push('track roster must be four canonical plus ten optimized');
  const constructionById = new Map((artifact.fieldConstructions ?? []).map((item) => [item.constructionId, item]));
  if (constructionById.size !== 4) errors.push('exactly four direct constructions required');
  for (const construction of artifact.fieldConstructions ?? []) {
    const p = BigInt(construction.p);
    if (p !== (ONE << BigInt(construction.q)) - ONE) errors.push(`${construction.constructionId}: p is not 2^q-1`);
    if (construction.codec.elementBytes !== construction.codec.baseLimbBytes * construction.degree) errors.push(`${construction.constructionId}: codec element width mismatch`);
    if (construction.codec.oneHex.length !== construction.codec.elementBytes * 2 || construction.codec.zeroHex.length !== construction.codec.elementBytes * 2) errors.push(`${construction.constructionId}: codec zero/one width mismatch`);
    if (construction.codec.zeroHex !== '00'.repeat(construction.codec.elementBytes) || construction.codec.oneHex !== `01${'00'.repeat(construction.codec.elementBytes - 1)}`) errors.push(`${construction.constructionId}: codec zero/one mismatch`);
  }
  for (const item of artifact.arms ?? []) {
    const construction = constructionById.get(item.constructionId);
    if (!construction) { errors.push(`${item.armId}: unresolved construction`); continue; }
    const expectedCounts = expectedArmCounts.get(item.algorithmId);
    if (!expectedCounts || item.declaredVariableBaseCounts.multiply !== expectedCounts[0] || item.declaredVariableBaseCounts.square !== expectedCounts[1]) errors.push(`${item.armId}: declared base count mismatch`);
    try {
      const computedMultiply = evaluateCountExpression(item.formula.countDerivation.multiply, construction.degree);
      const computedSquare = evaluateCountExpression(item.formula.countDerivation.square, construction.degree);
      if (computedMultiply !== item.declaredVariableBaseCounts.multiply || computedSquare !== item.declaredVariableBaseCounts.square) errors.push(`${item.armId}: count derivation does not produce declared counts`);
    } catch {
      errors.push(`${item.armId}: malformed count derivation`);
    }
    if (!deepEqual(item.relationMapping, RELATION_MAPPING)) errors.push(`${item.armId}: relation mapping drift`);
    if (item.parserBeforeArithmetic !== true || item.executionStatus !== 'closed-unimplemented-premeasurement') errors.push(`${item.armId}: execution boundary drift`);
    if (item.formula.divisionPolicy !== 'fixed-canonical-inverse-scalar-multiplication-only;OP_DIV-forbidden') errors.push(`${item.armId}: OP_DIV policy drift`);
    if (item.formula.dagIntegrity !== 'every-declared-node-reaches-an-output;no-optional-cse-or-dead-node') errors.push(`${item.armId}: DAG integrity drift`);
    for (const entry of item.formula.matrices) checkMatrixShapeAndValues(entry, BigInt(construction.p), errors);
  }
  if (artifact.qualification?.selection !== 'none' || artifact.qualification?.tupleRef !== null || artifact.qualification?.fieldRanking !== 'none' || artifact.qualification?.proofSystemRanking !== 'none' || artifact.qualification?.protocolRanking !== 'none') errors.push('qualification or ranking boundary drift');
  if (artifact.fairness?.armCount !== 14 || artifact.fairness?.silentDropPolicy !== 'forbidden') errors.push('fairness roster/drop policy drift');
  if (!deepEqual(artifact.fairness?.optimizedConclusionGate, OPTIMIZED_CONCLUSION_GATE)) errors.push('optimized conclusion gate drift');
  if (!deepEqual(artifact.fairness?.phaseOrder, PHASE_ORDER)) errors.push('future phase/order algorithm drift');
  const canonicalOrder = (artifact.fieldConstructions ?? []).map((construction) => {
    const matches = canonical.filter((item) => item.constructionId === construction.constructionId);
    return matches.length === 1 ? matches[0].armId : null;
  });
  const listedCanonicalOrder = canonical.map((item) => item.armId);
  if (canonicalOrder.some((item) => item === null) || !deepEqual(canonicalOrder, listedCanonicalOrder)) errors.push('canonical arm order is not fieldConstructions array order with exactly one arm each');
  return errors;
};

export const verifyFiniteToomMatrices = (p, inputDegree, orderedPoints, evaluation, inverseInterpolation) => {
  const plan = makeToomMatrices(p, inputDegree, orderedPoints);
  if (!deepEqual(evaluation, plan.evaluation.map((row) => row.map((value) => value.toString()))) && !deepEqual(evaluation, plan.evaluation)) return false;
  const expectedInverse = plan.inverseInterpolation;
  const actualInverse = inverseInterpolation.map((row) => row.map((value) => BigInt(value)));
  if (actualInverse.length !== expectedInverse.length || actualInverse.some((row) => row.length !== expectedInverse.length)) return false;
  const finitePoints = plan.finitePoints;
  for (let row = 0; row < finitePoints.length; row += 1) {
    for (let column = 0; column < finitePoints.length; column += 1) {
      let total = ZERO;
      for (let index = 0; index < finitePoints.length; index += 1) total = mod(total + pow(pointValue(finitePoints[row]), index, p) * actualInverse[index][column], p);
      if (total !== (row === column ? ONE : ZERO)) return false;
    }
  }
  return true;
};

export const FIELD_CONSTANTS = Object.freeze({ M31, M61, M89, CONSTRUCTIONS, toom5Points, toom6Points });
