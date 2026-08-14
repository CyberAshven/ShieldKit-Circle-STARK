import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const moduleDir = dirname(fileURLToPath(import.meta.url));
export const laneDir = resolve(moduleDir, '../..');
export const gateBContractDigest = 'cd0e657214a108cd6d5dbf753b5739250f640fc13e03de21ec1be26bbf14c10a';
export const gateBSchemaDigest = 'd2d8905fb61ddccb9991ca76d9689de2d60d035e2564c451f5fe0b7244b5c9e5';
export const matrixDigest = '203d2cabb6c12340ce117f1f07018a0c08072a6be87fd1eb0c76952faa9e3185';
export const executionProfileDigest = 'd1ec071c1630d38dc719d5a040f36cc94fa02ac7d7f832769d09788595c80e3f';
export const REQUIRED_RELATIONS = ['add', 'subtract', 'negate', 'multiply', 'square', 'equality', 'inverse-hint'];
export const GATE_B_RELATIONS = ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'];
export const GATE_B_CATEGORIES = ['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed'];
export const GATE_B_ENGINES = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'];
export const GATE_B_TRACKS = ['track:canonical-schoolbook', 'track:optimized'];
export const GATE_B_METRICS = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];
export const GATE_B_MUTATIONS = ['wrong-length', 'truncation', 'trailing-bytes', 'out-of-range', 'sign-alias', 'swapped-limb', 'wrong-relation-output', 'zero-inverse-hint'];
const ALL_GATE_B_RELATIONS = [...GATE_B_RELATIONS];
export const GATE_B_MUTATION_PLANS = [
  { family: 'wrong-length', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'A', transform: 'replace-the-entire-A-element-with-its-prefix-of-exactly-j-complete-base-limbs;resulting-length=j*baseLimbByteLength', expectedFailure: 'reject-at-exact-extension-element-length-check-before-limb-decode' },
  { family: 'truncation', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'A', transform: 'remove-the-byte-at-zero-based-offset-((j+1)*baseLimbByteLength-1)-from-A;resulting-length=extensionByteLength-1', expectedFailure: 'reject-at-exact-extension-element-length-check-before-limb-decode' },
  { family: 'trailing-bytes', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'A', transform: 'insert-one-00-byte-at-zero-based-offset-((j+1)*baseLimbByteLength)-in-A;resulting-length=extensionByteLength+1', expectedFailure: 'reject-at-exact-extension-element-length-check-before-limb-decode' },
  { family: 'out-of-range', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'A', transform: 'replace-A-coefficient-j-with-the-exact-fixed-width-unsigned-little-endian-encoding-of-p', expectedFailure: 'reject-at-coefficient-range-check-before-arithmetic' },
  { family: 'sign-alias', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'A', transform: 'replace-A-coefficient-j-with-(baseLimbByteLength-1)-zero-bytes-followed-by-80', expectedFailure: 'reject-at-unused-high-bit-check-before-numeric-decode' },
  { family: 'swapped-limb', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'A', transform: 'swap-A-coefficients-j-and-((j+1)-mod-degree)-while-retaining-the-original-derived-D-or-H;the-independent-base-must-make-the-swap-nonidentity-and-the-relation-false', expectedFailure: 'canonical-parser-pass-then-reject-at-relation-check' },
  { family: 'wrong-relation-output', relations: ALL_GATE_B_RELATIONS, instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'D-for-e-mac-and-e-square-mac-or-H-for-e-inverse-check', transform: 'replace-target-coefficient-j-with-(coefficient+1)-mod-p-while-retaining-all-input-operands', expectedFailure: 'canonical-parser-pass-then-reject-at-relation-check' },
  { family: 'zero-inverse-hint', relations: ['relation:e-inverse-check'], instances: 'one-per-coefficient-index-j-in-ascending-order', targetOperand: 'H', transform: 'replace-H-coefficient-j-with-zero;the-independent-valid-base-must-have-H-coefficient-j-nonzero', expectedFailure: 'canonical-parser-pass-then-reject-at-inverse-relation-check' }
];
export const GATE_B_ARTIFACT_KINDS = ['corpus', 'native-result', 'libauth-result', 'bchn-result', 'leanbch-result', 'metric-report', 'cross-engine-summary'];

const M89 = {
  fieldSpecRef: 'field-spec:m89-d2',
  constructionId: 'algebra-construction:m89-d2-x2-plus-1-v1',
  semanticProfile: 'algebra-profile:m89-d2-x2-plus-1-v1',
  descriptorId: 'algebra-component:m89-d2-x2-plus-1-v1',
  p: '618970019642690137449562111',
  q: 89,
  degree: 2,
  limbBytes: 12,
  elementBytes: 24,
  polynomial: ['1', '0', '1'],
  fixtureId: 'fixture:m89-x2-plus-1-rabin-v1',
  fixtureDigest: 'f7d802d5f763cc4afc301ed0d35f141fd80ffa4a64ad7e6151588ad8c370ea7a'
};

const pm1 = { op: 'p-minus-1' };
const two = { op: 'constant', value: '2' };
const twicePm1 = { op: 'multiply', args: [two, pm1] };
const pm1Squared = { op: 'multiply', args: [pm1, pm1] };
const twicePm1Squared = { op: 'multiply', args: [two, pm1, pm1] };

export const M89_RELATIONS = [
  { operation: 'add', formulaId: 'relation-formula:m89-d2-add-v1', equations: ['r0=modp(a0+b0)', 'r1=modp(a1+b1)'] },
  { operation: 'subtract', formulaId: 'relation-formula:m89-d2-subtract-v1', equations: ['r0=modp(a0-b0)', 'r1=modp(a1-b1)'] },
  { operation: 'negate', formulaId: 'relation-formula:m89-d2-negate-v1', equations: ['r0=modp(-a0)', 'r1=modp(-a1)'] },
  { operation: 'multiply', formulaId: 'relation-formula:m89-d2-multiply-v1', equations: ['r0=modp(a0*b0-a1*b1)', 'r1=modp(a0*b1+a1*b0)'] },
  { operation: 'square', formulaId: 'relation-formula:m89-d2-square-v1', equations: ['r0=modp(a0*a0-a1*a1)', 'r1=modp(2*a0*a1)'] },
  { operation: 'equality', formulaId: 'relation-formula:m89-d2-equality-v1', equations: ['accept=canonical(A)&&canonical(B)&&(a0==b0)&&(a1==b1)'] },
  { operation: 'inverse-hint', formulaId: 'relation-formula:m89-d2-inverse-hint-v1', equations: ['accept=canonical(A)&&canonical(H)&&(A!=0)&&modp(a0*h0-a1*h1)==1&&modp(a0*h1+a1*h0)==0'] }
];

const stage = (stageId, formula) => ({ stageId, formula });
export const M89_BOUND_STAGES = [
  { operation: 'add', stages: [stage('stage:add-unreduced-sum', twicePm1), stage('stage:add-reduced', pm1)] },
  { operation: 'subtract', stages: [stage('stage:subtract-signed-difference', pm1), stage('stage:subtract-reduced', pm1)] },
  { operation: 'negate', stages: [stage('stage:negate-canonical', pm1)] },
  { operation: 'multiply', stages: [stage('stage:multiply-base-product', pm1Squared), stage('stage:multiply-real-difference', pm1Squared), stage('stage:multiply-imaginary-sum', twicePm1Squared), stage('stage:multiply-reduced-coefficient', pm1)] },
  { operation: 'square', stages: [stage('stage:square-base-product', pm1Squared), stage('stage:square-real-difference', pm1Squared), stage('stage:square-doubled-cross-product', twicePm1Squared), stage('stage:square-reduced-coefficient', pm1)] },
  { operation: 'equality', stages: [stage('stage:equality-coefficient', pm1)] },
  { operation: 'inverse-hint', stages: [stage('stage:inverse-base-product', pm1Squared), stage('stage:inverse-real-difference', pm1Squared), stage('stage:inverse-imaginary-sum', twicePm1Squared), stage('stage:inverse-reduced-coefficient', pm1)] }
];

const countCategories = (malformedMutations) => [
  { categoryId: 'category:valid', caseFormula: { op: 'constant', value: 16 } },
  { categoryId: 'category:boundary', caseFormula: { op: 'add', args: [{ op: 'multiply', args: [{ op: 'constant', value: 2 }, { op: 'degree' }] }, { op: 'constant', value: 6 }] } },
  { categoryId: 'category:random', caseFormula: { op: 'constant', value: 32 } },
  { categoryId: 'category:metamorphic', caseFormula: { op: 'constant', value: 16 } },
  { categoryId: 'category:malformed', caseFormula: { op: 'multiply', args: [{ op: 'constant', value: malformedMutations }, { op: 'degree' }] } }
];
export const EXPECTED_COUNT_FORMULAS = [
  { relationId: 'relation:e-mac', operandCount: 4, categories: countCategories(7) },
  { relationId: 'relation:e-square-mac', operandCount: 3, categories: countCategories(7) },
  { relationId: 'relation:e-inverse-check', operandCount: 2, categories: countCategories(8) }
];

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};
export const contentDigestFor = (value) => {
  const clone = structuredClone(value);
  delete clone.contentDigest;
  return sha256(canonicalize(clone));
};

const exactArray = (actual, expected) => Array.isArray(actual) && actual.length === expected.length && actual.every((item, index) => item === expected[index]);
const exactSet = (actual, expected) => Array.isArray(actual) && actual.length === expected.length && new Set(actual).size === actual.length && expected.every((item) => actual.includes(item));
const pushIf = (errors, condition, message) => { if (!condition) errors.push(message); };
const uniqueBy = (items, key) => Array.isArray(items) && new Set(items.map((item) => item?.[key])).size === items.length;

const resolvedRegularFile = (relativePath, rootDir) => {
  if (typeof relativePath !== 'string' || relativePath.length === 0) return null;
  const root = realpathSync(rootDir);
  const candidate = resolve(root, relativePath);
  if (candidate !== root && !candidate.startsWith(`${root}${sep}`)) return null;
  if (!existsSync(candidate)) return null;
  const real = realpathSync(candidate);
  if (real !== root && !real.startsWith(`${root}${sep}`)) return null;
  if (!statSync(real).isFile()) return null;
  return real;
};

export const fileDigest = (relativePath, rootDir = laneDir) => {
  try {
    const path = resolvedRegularFile(relativePath, rootDir);
    return path === null ? null : sha256(readFileSync(path));
  } catch {
    return null;
  }
};

const loadJsonFile = (relativePath, rootDir) => {
  const path = resolvedRegularFile(relativePath, rootDir);
  if (path === null) return null;
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return null; }
};

const verifyFilePin = (errors, path, digest, label, rootDir) => {
  const actual = fileDigest(path, rootDir);
  pushIf(errors, actual !== null, `${label} file is missing or unsafe`);
  pushIf(errors, actual === digest, `${label} digest mismatch`);
};

const formulaValue = (formula, p, degree) => {
  if (formula.op === 'p-minus-1') return p - 1n;
  if (formula.op === 'degree') return BigInt(degree);
  if (formula.op === 'constant') return BigInt(formula.value);
  const values = formula.args.map((item) => formulaValue(item, p, degree));
  return formula.op === 'add' ? values.reduce((a, b) => a + b, 0n) : values.reduce((a, b) => a * b, 1n);
};

export const signedMagnitudeBytes = (value) => {
  const magnitude = value < 0n ? -value : value;
  if (magnitude === 0n) return 0;
  return Math.ceil((magnitude.toString(2).length + 1) / 8);
};

const validateM89SemanticProfile = (descriptor, errors) => {
  const binding = descriptor.registryBinding;
  const algebra = descriptor.algebra;
  pushIf(errors, descriptor.descriptorId === M89.descriptorId, 'M89 descriptor identity mismatch');
  pushIf(errors, binding.fieldSpecRef === M89.fieldSpecRef && binding.constructionId === M89.constructionId, 'M89 construction binding mismatch');
  pushIf(errors, binding.q === M89.q && binding.p === M89.p && binding.extensionDegree === M89.degree && binding.baseLimbBytes === M89.limbBytes && binding.rawElementBytes === M89.elementBytes, 'M89 dimensions mismatch');
  pushIf(errors, algebra.kind === 'direct-polynomial' && algebra.semanticProfile === M89.semanticProfile && algebra.generatorSymbol === 'u', 'M89 semantic profile mismatch');
  pushIf(errors, canonicalize(algebra.definingPolynomial) === canonicalize(M89.polynomial), 'M89 polynomial is not X^2+1');
  pushIf(errors, canonicalize(descriptor.relations) === canonicalize(M89_RELATIONS), 'M89 exact relation formulas drift');
  const actualStages = descriptor.intermediateBounds.operations.map((operation) => ({ operation: operation.operation, stages: operation.stages.map(({ stageId, formula }) => ({ stageId, formula })) }));
  pushIf(errors, canonicalize(actualStages) === canonicalize(M89_BOUND_STAGES), 'M89 intermediate stage inventory or formulas drift');
};

const validateCertificate = (certificate, expectedKind, descriptor, errors, rootDir, verifyPins) => {
  pushIf(errors, certificate?.certificateKind === expectedKind, `${expectedKind} certificate kind mismatch`);
  pushIf(errors, certificate?.certificateFixtureId === M89.fixtureId, `${expectedKind} fixture identity mismatch`);
  pushIf(errors, certificate?.certificateArtifactDigest === M89.fixtureDigest, `${expectedKind} fixture digest mismatch`);
  const checkers = certificate?.checkers ?? [];
  pushIf(errors, checkers.length === 2 && exactSet(checkers.map((item) => item.checkerRole), ['repository-checker', 'independent-external-cas']), `${expectedKind} checker roles are not an independent pair`);
  pushIf(errors, uniqueBy(checkers, 'checkerIdentity'), `${expectedKind} checker identities are not distinct`);
  pushIf(errors, uniqueBy(checkers, 'sourceManifestDigest'), `${expectedKind} checker source manifests are not distinct`);
  pushIf(errors, uniqueBy(checkers, 'commandDigest'), `${expectedKind} checker commands are not distinct`);
  pushIf(errors, uniqueBy(checkers, 'outputDigest'), `${expectedKind} checker outputs are not distinct`);
  for (const checker of checkers) {
    pushIf(errors, checker.canonicalCertificateDigest === certificate.certificateArtifactDigest, `${expectedKind} checker is not bound to the canonical certificate bytes`);
    if (verifyPins) {
      verifyFilePin(errors, checker.sourceManifestPath, checker.sourceManifestDigest, `${expectedKind}/${checker.checkerRole} source manifest`, rootDir);
      verifyFilePin(errors, checker.commandPath, checker.commandDigest, `${expectedKind}/${checker.checkerRole} command`, rootDir);
      verifyFilePin(errors, checker.outputPath, checker.outputDigest, `${expectedKind}/${checker.checkerRole} output`, rootDir);
      const output = checker.checkerRole === 'independent-external-cas' ? loadJsonFile(checker.outputPath, rootDir) : null;
      if (checker.checkerRole === 'independent-external-cas') {
        pushIf(errors, output?.fixtureId === M89.fixtureId && output?.modulus === M89.p, `${expectedKind} external CAS fixture binding mismatch`);
        pushIf(errors, canonicalize(output?.fixturePolynomialCoefficientsAscending) === canonicalize([1, 0, 1]), `${expectedKind} external CAS polynomial binding mismatch`);
        pushIf(errors, output?.labels?.includes('root-reviewed-component-pass') && output?.labels?.includes('not-selection'), `${expectedKind} external CAS review boundary mismatch`);
        pushIf(errors, output?.checks?.sympyLucasLehmerPrimeProof?.value === true && output?.checks?.sympyDirectIrreducibility === true && output?.checks?.sympyFactorization?.singleIrreducibleFactor === true && output?.checks?.legendreSymbolMinusOne?.irreducibleQuadraticCriterion === true, `${expectedKind} external CAS verdict is incomplete`);
      } else {
        const path = resolvedRegularFile(checker.outputPath, rootDir);
        const text = path === null ? '' : readFileSync(path, 'utf8');
        pushIf(errors, text === `PASS ${M89.fixtureId} rabin-irreducibility-fixture\n`, `${expectedKind} repository replay output mismatch`);
      }
    }
  }
  if (verifyPins) verifyFilePin(errors, certificate.certificateArtifactPath, certificate.certificateArtifactDigest, `${expectedKind} certificate artifact`, rootDir);
};

export const validateDescriptor = (descriptor, { rootDir = laneDir, verifyPins = true } = {}) => {
  const errors = [];
  pushIf(errors, descriptor?.contentDigest?.value === contentDigestFor(descriptor), 'descriptor content digest mismatch');
  pushIf(errors, descriptor?.qualification?.selection === 'none' && descriptor?.qualification?.tupleRef === null, 'descriptor must remain selection:none with tupleRef:null');
  const boundary = descriptor?.protocolBoundary;
  pushIf(errors, boundary?.protocolRoles?.length === 0 && boundary?.circleDomain === null && boundary?.deepStrategy === null && boundary?.embeddings?.length === 0 && boundary?.challengeSamplers?.length === 0 && boundary?.soundnessEventDag === null && boundary?.hashBindings?.length === 0, 'descriptor contains prohibited protocol binding');

  const binding = descriptor?.registryBinding;
  if (binding) {
    pushIf(errors, binding.matrixDigest === matrixDigest, 'descriptor matrix digest is not the current frozen v2 digest');
    const p = (1n << BigInt(binding.q)) - 1n;
    pushIf(errors, binding.p === p.toString(), 'descriptor p is not 2^q-1');
    pushIf(errors, binding.baseLimbBytes === Math.ceil(binding.q / 8), 'descriptor base limb width mismatch');
    pushIf(errors, binding.rawElementBytes === binding.baseLimbBytes * binding.extensionDegree, 'descriptor raw element width mismatch');
    if (verifyPins) {
      verifyFilePin(errors, binding.matrixPath, binding.matrixDigest, 'descriptor candidate matrix', rootDir);
      const matrix = loadJsonFile(binding.matrixPath, rootDir);
      const field = matrix?.fieldSpecs?.find((item) => item.fieldSpecId === binding.fieldSpecRef);
      pushIf(errors, field !== undefined, 'descriptor field specification is unresolved');
      if (field) {
        pushIf(errors, field.kind === 'mersenne-family' && field.freezingStatus === 'family-unfrozen' && field.disposition === 'first-arithmetic-shortlist', 'descriptor field is not an unselected arithmetic-shortlist family');
        pushIf(errors, field.mersenneExponent === binding.q && field.extensionDegree === binding.extensionDegree && field.baseLimbBytes === binding.baseLimbBytes && field.rawElementBytes === binding.rawElementBytes, 'descriptor dimensions differ from prequalification registry');
      }
    }
  }

  const algebra = descriptor?.algebra;
  if (binding && algebra?.kind === 'direct-polynomial') {
    const p = BigInt(binding.p);
    const coeffs = algebra.definingPolynomial ?? [];
    pushIf(errors, coeffs.length === binding.extensionDegree + 1, 'direct polynomial degree mismatch');
    pushIf(errors, coeffs.at(-1) === '1', 'direct polynomial is not monic');
    try { pushIf(errors, coeffs.every((coefficient) => BigInt(coefficient) >= 0n && BigInt(coefficient) < p), 'direct polynomial coefficient is out of range'); } catch { errors.push('direct polynomial coefficient is not canonical'); }
  }
  if (binding && algebra?.kind === 'tower') {
    const totalDegree = (algebra.steps ?? []).reduce((product, item) => product * item.degree, 1);
    pushIf(errors, totalDegree === binding.extensionDegree, 'tower degree product mismatch');
    pushIf(errors, algebra.flattenedBasis?.length === binding.extensionDegree, 'tower flattened basis dimension mismatch');
    for (const item of algebra.steps ?? []) pushIf(errors, item.definingPolynomial.length === item.degree + 1 && item.definingPolynomial.at(-1) === '1', `tower step ${item.stepId} is not monic at declared degree`);
  }

  const codec = descriptor?.canonicalCodec;
  if (binding && codec) {
    const usedHighBits = binding.q - 8 * (binding.baseLimbBytes - 1);
    const unusedHighBits = 8 - usedHighBits;
    const highMask = ((0xff << usedHighBits) & 0xff).toString(16).padStart(2, '0');
    pushIf(errors, codec.baseLimbByteLength === binding.baseLimbBytes, 'codec base limb byte length mismatch');
    pushIf(errors, codec.modulusBitLength === binding.q, 'codec modulus bit length mismatch');
    pushIf(errors, codec.unusedHighBits === unusedHighBits && codec.unusedHighBitMaskHex === highMask, 'codec unused-high-bit rule mismatch');
    pushIf(errors, codec.extensionByteLength === binding.rawElementBytes, 'codec extension byte length mismatch');
    pushIf(errors, codec.zeroHex === '00'.repeat(binding.rawElementBytes), 'codec zero is not canonical fixed width');
    pushIf(errors, codec.oneHex === `01${'00'.repeat(binding.rawElementBytes - 1)}`, 'codec one is not canonical little-endian fixed width');
  }

  pushIf(errors, exactSet((descriptor?.relations ?? []).map((item) => item.operation), REQUIRED_RELATIONS), 'descriptor relation set is incomplete or duplicated');
  pushIf(errors, exactSet((descriptor?.intermediateBounds?.operations ?? []).map((item) => item.operation), REQUIRED_RELATIONS), 'descriptor bound operation set is incomplete or duplicated');
  let maxStageBytes = 0;
  if (binding) for (const operation of descriptor?.intermediateBounds?.operations ?? []) {
    pushIf(errors, uniqueBy(operation.stages, 'stageId'), `duplicate bound stage in ${operation.operation}`);
    for (const bound of operation.stages ?? []) {
      try {
        const value = formulaValue(bound.formula, BigInt(binding.p), binding.extensionDegree);
        const bytes = signedMagnitudeBytes(value);
        pushIf(errors, BigInt(bound.maxAbs) === value, `bound formula mismatch at ${operation.operation}/${bound.stageId}`);
        pushIf(errors, bound.maxSignedMagnitudeBytes === bytes, `signed-magnitude width mismatch at ${operation.operation}/${bound.stageId}`);
        pushIf(errors, bound.stackElementLimitBytes === 10000 && bound.headroomBytes === 10000 - bytes, `stack-element headroom mismatch at ${operation.operation}/${bound.stageId}`);
        maxStageBytes = Math.max(maxStageBytes, bytes);
      } catch { errors.push(`invalid bound formula at ${operation.operation}/${bound.stageId}`); }
    }
  }
  pushIf(errors, descriptor?.intermediateBounds?.maxEncodedElementBytes === binding?.rawElementBytes, 'encoded element byte bound mismatch');
  pushIf(errors, descriptor?.intermediateBounds?.maxArithmeticIntermediateBytes === maxStageBytes, 'maximum arithmetic intermediate byte bound mismatch');

  if (descriptor?.status === 'frozen-gate-b0-arithmetic-admitted') {
    if (algebra?.semanticProfile === M89.semanticProfile) validateM89SemanticProfile(descriptor, errors);
    else errors.push('admitted descriptor has no reviewed construction-specific semantic profile');
  }

  const baseCertificate = descriptor?.certificateBundle?.basePrime;
  const extensionCertificate = descriptor?.certificateBundle?.extension;
  validateCertificate(baseCertificate, 'mersenne-primality', descriptor, errors, rootDir, verifyPins);
  validateCertificate(extensionCertificate, algebra?.kind === 'tower' ? 'tower-step-irreducibility' : 'direct-rabin-irreducibility', descriptor, errors, rootDir, verifyPins);
  if (verifyPins && binding && algebra?.kind === 'direct-polynomial') {
    const fixture = loadJsonFile(extensionCertificate?.certificateArtifactPath, rootDir);
    pushIf(errors, fixture?.fixtureId === extensionCertificate?.certificateFixtureId, 'certificate fixture ID does not match descriptor');
    pushIf(errors, fixture?.certificate?.modulus === binding.p && Number(fixture?.certificate?.degree) === binding.extensionDegree, 'certificate modulus or degree does not match descriptor');
    pushIf(errors, canonicalize(fixture?.certificate?.polynomial) === canonicalize(algebra.definingPolynomial), 'certificate polynomial does not match descriptor algebra');
    pushIf(errors, fixture?.certificate?.conclusion === 'irreducible' && fixture?.certificate?.mersennePrimeCheck?.classification === 'prime', 'certificate conclusion is not prime and irreducible');
  }

  pushIf(errors, uniqueBy(descriptor?.sourcePins, 'sourceId') && uniqueBy(descriptor?.sourcePins, 'path'), 'descriptor source pins contain duplicate identities or paths');
  for (const pin of descriptor?.sourcePins ?? []) if (verifyPins) verifyFilePin(errors, pin.path, pin.sha256, `source pin ${pin.sourceId}`, rootDir);

  const profile = descriptor?.executionProfileBinding;
  pushIf(errors, profile?.sha256 === executionProfileDigest && profile?.sourceCommit === '864c53ee34924cca6c6b6d96607ff2cedcdccf02', 'execution profile pin drift');
  if (verifyPins && profile) {
    verifyFilePin(errors, profile.path, profile.sha256, 'execution profile', rootDir);
    const profileJson = loadJsonFile(profile.path, rootDir);
    const constraints = new Map((profileJson?.constraints ?? []).map((item) => [item.id, item.value]));
    pushIf(errors, profileJson?.id === profile.profileRef && profileJson?.source?.commit === profile.sourceCommit, 'execution profile identity or source commit mismatch');
    pushIf(errors, constraints.get('bch:max-stack-element-size') === profile.maxStackElementBytes && constraints.get('bch:max-stack-size') === profile.maxStackItems && constraints.get('bch:max-script-size') === profile.maxScriptBytes && constraints.get('bch:max-standard-transaction-size') === profile.maxStandardTransactionBytes, 'execution profile limits mismatch');
  }

  const gate = descriptor?.gateBContractBinding;
  pushIf(errors, gate?.contractDigest === gateBContractDigest && gate?.schemaDigest === gateBSchemaDigest, 'descriptor does not pin unchanged Gate-B v1 artifacts');
  if (verifyPins && gate) {
    verifyFilePin(errors, gate.contractPath, gate.contractDigest, 'Gate-B v1 contract', rootDir);
    verifyFilePin(errors, gate.schemaPath, gate.schemaDigest, 'Gate-B v1 schema', rootDir);
  }

  const campaignBinding = descriptor?.arithmeticCampaignBinding;
  if (verifyPins && campaignBinding) {
    verifyFilePin(errors, campaignBinding.campaignPath, campaignBinding.fileDigest, 'Gate-B0 arithmetic campaign', rootDir);
    const campaign = loadJsonFile(campaignBinding.campaignPath, rootDir);
    pushIf(errors, campaign?.campaignId === campaignBinding.campaignId && campaign?.contentDigest?.value === campaignBinding.contentDigest && contentDigestFor(campaign) === campaignBinding.contentDigest, 'arithmetic campaign content binding mismatch');
  }
  return errors;
};

const countExpression = (expression, degree, operands) => {
  if (expression.op === 'constant') return BigInt(expression.value);
  if (expression.op === 'degree') return BigInt(degree);
  if (expression.op === 'operands') return BigInt(operands);
  const values = expression.args.map((item) => countExpression(item, degree, operands));
  return expression.op === 'add' ? values.reduce((a, b) => a + b, 0n) : values.reduce((a, b) => a * b, 1n);
};

export const campaignCountsForDegree = (campaign, degree) => {
  const result = [];
  for (const relation of campaign.countFormulas ?? []) for (const category of relation.categories ?? []) {
    const cases = countExpression(category.caseFormula, degree, relation.operandCount);
    result.push({ relationId: relation.relationId, categoryId: category.categoryId, cases: cases.toString(), operandSamples: (cases * BigInt(relation.operandCount)).toString(), limbSamples: (cases * BigInt(relation.operandCount) * BigInt(degree)).toString() });
  }
  return result;
};

export const trackOrderForDescriptor = (descriptorContentDigest) => {
  const parity = Buffer.from(sha256(Buffer.from(descriptorContentDigest, 'utf8')), 'hex')[0] & 1;
  return parity === 0 ? [...GATE_B_TRACKS] : [...GATE_B_TRACKS].reverse();
};

export const validateCampaign = (campaign, { rootDir = laneDir, verifyPins = true } = {}) => {
  const errors = [];
  pushIf(errors, campaign?.contentDigest?.value === contentDigestFor(campaign), 'campaign content digest mismatch');
  pushIf(errors, campaign?.selection === 'none' && campaign?.tupleRef === null, 'campaign must remain selection:none with tupleRef:null');
  pushIf(errors, exactArray(campaign?.cohort?.comparisonFieldSpecs, ['field-spec:m31-d5', 'field-spec:m31-d6', 'field-spec:m61-d3', 'field-spec:m89-d2']), 'campaign comparison cohort or order drift');
  pushIf(errors, campaign?.cohort?.calibrationFieldSpec === 'field-spec:m31-d1' && campaign?.cohort?.killedNegativeControl === 'field-spec:m29-d5-invalid', 'campaign controls drift');
  pushIf(errors, campaign?.cohort?.m89FirstStatus === 'non-ranking-harness-shakedown-only', 'M89-first is not constrained as non-ranking shakedown');
  pushIf(errors, campaign?.cohort?.cohortRankingStatus === 'closed-until-all-four-descriptors-and-both-tracks-share-one-epoch', 'campaign cohort ranking gate drift');
  const tracks = new Map((campaign?.tracks ?? []).map((item) => [item.trackId, item]));
  pushIf(errors, tracks.size === 2 && tracks.get('track:canonical-schoolbook')?.kind === 'canonical-schoolbook' && tracks.get('track:optimized')?.kind === 'optimized', 'campaign track identity/kind mapping drift');
  pushIf(errors, campaign?.counterbalancedRunOrder?.rule === 'first-byte(sha256(descriptor-content-digest-hex-ascii))&1;0=canonical-then-optimized;1=optimized-then-canonical', 'campaign run-order rule drift');
  const generator = campaign?.corpusGenerator;
  pushIf(errors, campaign?.preMeasurementCorrection?.status === 'resolved-before-first-corpus-or-engine-run' && campaign?.preMeasurementCorrection?.supersededContentDigest === '1fed7dcf3e989644b70ddf67d604493882ecb88b5eadaa50926ca63f441f038a' && campaign?.preMeasurementCorrection?.evidenceImpact === 'none-no-corpus-hash-or-engine-result-existed', 'campaign pre-measurement correction record drift');
  pushIf(errors, generator?.algorithm === 'sha256-counter-rejection-v2' && generator?.seedHex === '0123456789abcdef' && generator?.protocolUse === 'host-test-only-not-protocol-hash-or-sampler', 'campaign corpus generator boundary drift');
  pushIf(errors, exactArray(generator?.relationOrder, GATE_B_RELATIONS), 'campaign relation index order drift');
  pushIf(errors, exactArray(generator?.categoryOrder, GATE_B_CATEGORIES), 'campaign category index order drift');
  pushIf(errors, exactArray(generator?.mutationFamilies, GATE_B_MUTATIONS), 'campaign mutation index order drift');
  pushIf(errors, canonicalize(generator?.mutationPlans) === canonicalize(GATE_B_MUTATION_PLANS), 'campaign exact mutation plans drift');
  pushIf(errors, exactArray(campaign?.engines, GATE_B_ENGINES), 'campaign engine order drift');
  pushIf(errors, exactArray(campaign?.metricVector, GATE_B_METRICS), 'campaign metric vector order drift');
  pushIf(errors, canonicalize(campaign?.countFormulas) === canonicalize(EXPECTED_COUNT_FORMULAS), 'campaign count formulas drift');
  pushIf(errors, campaignCountsForDegree(campaign, 2).every((item) => BigInt(item.cases) > 0n), 'campaign includes a zero-size required corpus category');

  const gate = campaign?.gateBContractBinding;
  pushIf(errors, gate?.contractDigest === gateBContractDigest && gate?.schemaDigest === gateBSchemaDigest, 'campaign does not pin unchanged Gate-B v1 artifacts');
  const matrix = campaign?.matrixBinding;
  pushIf(errors, matrix?.sha256 === matrixDigest && matrix?.registryKind === 'prequalification-component-registry' && matrix?.selectionStatus === 'closed', 'campaign candidate-matrix binding drift');
  if (verifyPins) {
    verifyFilePin(errors, gate?.contractPath, gate?.contractDigest, 'campaign Gate-B v1 contract', rootDir);
    verifyFilePin(errors, gate?.schemaPath, gate?.schemaDigest, 'campaign Gate-B v1 schema', rootDir);
    verifyFilePin(errors, matrix?.path, matrix?.sha256, 'campaign candidate matrix', rootDir);
    const matrixJson = loadJsonFile(matrix?.path, rootDir);
    const fields = new Map((matrixJson?.fieldSpecs ?? []).map((item) => [item.fieldSpecId, item]));
    for (const id of campaign?.cohort?.comparisonFieldSpecs ?? []) pushIf(errors, fields.get(id)?.disposition === 'first-arithmetic-shortlist', `campaign comparison field ${id} is unresolved or not shortlisted`);
    pushIf(errors, fields.get(campaign?.cohort?.calibrationFieldSpec)?.disposition === 'measured-base-control', 'campaign calibration control is unresolved');
    pushIf(errors, fields.get(campaign?.cohort?.killedNegativeControl)?.disposition === 'killed', 'campaign killed control is unresolved');
  }
  pushIf(errors, uniqueBy(campaign?.sourcePins, 'sourceId') && uniqueBy(campaign?.sourcePins, 'path'), 'campaign source pins contain duplicates');
  for (const pin of campaign?.sourcePins ?? []) if (verifyPins) verifyFilePin(errors, pin.path, pin.sha256, `campaign source pin ${pin.sourceId}`, rootDir);
  return errors;
};

const verifyContentBinding = (errors, binding, expected, label, rootDir) => {
  verifyFilePin(errors, binding?.path, binding?.fileDigest, `${label} file`, rootDir);
  const artifact = loadJsonFile(binding?.path, rootDir);
  pushIf(errors, artifact !== null && artifact?.contentDigest?.value === binding?.contentDigest && contentDigestFor(artifact) === binding?.contentDigest, `${label} file content digest mismatch`);
  pushIf(errors, binding?.contentDigest === expected?.contentDigest?.value, `${label} object content digest mismatch`);
};

const ARITHMETIC_ARTIFACT_SCHEMAS = Object.freeze({
  corpus: 'content-addressed-corpus',
  'native-result': 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1',
  'libauth-result': 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1',
  'bchn-result': 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1',
  'leanbch-result': 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1',
  'metric-report': 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1',
  'cross-engine-summary': 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1'
});
const ARITHMETIC_ARTIFACT_SCHEMA_BINDINGS = Object.freeze([
  { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', path: 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json' },
  { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', path: 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json' },
  { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1', path: 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json' }
]);
const METRIC_VALUE_STATUSES = new Set(['measured', 'measured-noncomparable', 'derived-common', 'derived-engine']);
const METRIC_UNAVAILABLE_STATUSES = new Set(['not-reached', 'not-exposed', 'not-applicable']);
const isSha256 = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
export const arithmeticCaseKey = (entry) => [entry?.relationId, entry?.categoryId, entry?.caseIndex, entry?.vectorAttempt].join('|');
const metricCellKey = (cell) => [cell?.engineId, cell?.caseKey, cell?.metricId].join('|');
const metricAgreementKey = (agreement) => [agreement?.caseKey, agreement?.metricId].join('|');
const engineResultKind = (engineId) => ({
  'engine:native': 'native-result',
  'engine:libauth': 'libauth-result',
  'engine:bchn': 'bchn-result',
  'engine:leanbch': 'leanbch-result'
})[engineId];

const validCorpusCases = (corpus, errors) => {
  const cases = corpus?.cases;
  pushIf(errors, Array.isArray(cases) && cases.length > 0, 'run corpus artifact has no cases');
  if (!Array.isArray(cases)) return [];
  const keys = cases.map(arithmeticCaseKey);
  pushIf(errors, new Set(keys).size === cases.length, 'run corpus artifact has duplicate case identities');
  for (const entry of cases) {
    pushIf(errors, GATE_B_RELATIONS.includes(entry?.relationId) && GATE_B_CATEGORIES.includes(entry?.categoryId), 'run corpus artifact has an unknown relation or category');
    pushIf(errors, Number.isInteger(entry?.caseIndex) && Number.isInteger(entry?.vectorAttempt), 'run corpus artifact has an invalid case coordinate');
    pushIf(errors, ['accept', 'reject'].includes(entry?.expected?.verdict), 'run corpus artifact has an invalid expected verdict');
  }
  return cases;
};

const validateEngineArtifact = (artifact, engineId, corpusDigest, corpusCases, errors) => {
  pushIf(errors, artifact?.schema === 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', `run ${engineId} result schema mismatch`);
  pushIf(errors, artifact?.engineId === engineId, `run ${engineId} result engine identity mismatch`);
  pushIf(errors, artifact?.corpusDigest === corpusDigest, `run ${engineId} result corpus digest mismatch`);
  const execution = artifact?.execution;
  pushIf(errors, execution?.status === 'measured' && execution?.evidenceBoundary === 'gate-b0-primitive-evidence-only', `run ${engineId} execution is not measured within the component boundary`);
  pushIf(errors, isSha256(execution?.implementationDigest), `run ${engineId} execution implementation digest is invalid`);
  const external = execution?.mode === 'external';
  pushIf(errors, external || execution?.mode === 'in-process', `run ${engineId} execution mode is invalid`);
  pushIf(errors, external ? execution?.entrypoint?.kind === 'argv' && Array.isArray(execution?.entrypoint?.argv) && execution.entrypoint.argv.length > 0 && execution.entrypoint.modulePath === null : execution?.entrypoint?.kind === 'module' && execution.entrypoint.argv === null && typeof execution.entrypoint.modulePath === 'string' && execution.entrypoint.modulePath.length > 0, `run ${engineId} execution entrypoint does not match mode`);
  for (const streamName of ['stdin', 'stdout', 'stderr']) {
    const stream = execution?.[streamName];
    if (external) pushIf(errors, typeof stream?.text === 'string' && isSha256(stream?.sha256) && stream?.byteLength === Buffer.byteLength(stream.text, 'utf8') && stream.sha256 === sha256(Buffer.from(stream.text, 'utf8')), `run ${engineId} external ${streamName} digest or byte length mismatch`);
    else pushIf(errors, stream?.text === null && stream?.sha256 === null && stream?.byteLength === 0, `run ${engineId} in-process ${streamName} must be explicit null/empty`);
  }
  const rows = Array.isArray(artifact?.cases) ? artifact.cases : [];
  const expected = corpusCases.map(arithmeticCaseKey);
  pushIf(errors, exactSet(rows.map((item) => item?.caseKey), expected), `run ${engineId} result lacks exact per-case coverage`);
  for (const row of rows) {
    pushIf(errors, isSha256(row?.fixtureDigest) && isSha256(row?.transactionDigest) && isSha256(row?.sourceOutputsDigest), `run ${engineId} result has an invalid input digest`);
    pushIf(errors, ['accept', 'reject'].includes(row?.verdict), `run ${engineId} result has an invalid verdict`);
    pushIf(errors, row?.rawObservation !== null && typeof row?.rawObservation === 'object' && !Array.isArray(row.rawObservation) && Object.keys(row.rawObservation).length > 0, `run ${engineId} result lacks a raw per-case observation`);
  }
  return new Map(rows.map((item) => [item.caseKey, item]));
};

const validateMetricReport = (artifact, corpusDigest, corpusCases, engineArtifactDigests, errors) => {
  pushIf(errors, artifact?.schema === 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', 'run metric report schema mismatch');
  pushIf(errors, artifact?.corpusDigest === corpusDigest, 'run metric report corpus digest mismatch');
  const cells = Array.isArray(artifact?.cells) ? artifact.cells : [];
  const expected = [];
  for (const engineId of GATE_B_ENGINES) for (const entry of corpusCases) for (const metricId of GATE_B_METRICS) expected.push(`${engineId}|${arithmeticCaseKey(entry)}|${metricId}`);
  pushIf(errors, exactSet(cells.map(metricCellKey), expected), 'run metric report lacks exact four-engine by case by metric accounting');
  for (const cell of cells) {
    const status = cell?.status;
    pushIf(errors, isSha256(cell?.fixtureDigest), 'run metric report has an invalid fixture digest');
    if (METRIC_VALUE_STATUSES.has(status)) {
      pushIf(errors, cell?.value !== null && cell?.value !== undefined && cell?.provenance !== null && typeof cell?.provenance === 'object' && isSha256(cell.provenance.sourceArtifactDigest) && typeof cell.provenance.method === 'string' && cell.provenance.method.length > 0 && cell.reason === null, 'run metric report measured or derived cell lacks value/provenance');
      if (status === 'derived-common') pushIf(errors, cell?.provenance?.sourceArtifactDigest === cell?.fixtureDigest, 'run metric report common-derived cell is not bound to its fixture digest');
      else pushIf(errors, cell?.provenance?.sourceArtifactDigest === engineArtifactDigests.get(cell?.engineId), 'run metric report engine-derived cell is not bound to its raw engine result');
    } else if (METRIC_UNAVAILABLE_STATUSES.has(status)) {
      pushIf(errors, cell?.value === null && cell?.provenance === null && typeof cell?.reason === 'string' && cell.reason.length > 0, 'run metric report unavailable cell lacks null/value reason discipline');
    } else errors.push('run metric report has an unknown metric status');
    pushIf(errors, !(status === 'measured-noncomparable' && cell?.metricId === 'verdict'), 'run metric report uses noncomparable status for a verdict claim');
  }
  return new Map(cells.map((item) => [metricCellKey(item), item]));
};

const validateCrossEngineSummaryArtifact = (artifact, corpusDigest, corpusCases, engineRows, metricCells, errors) => {
  pushIf(errors, artifact?.schema === 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1', 'run cross-engine summary schema mismatch');
  pushIf(errors, artifact?.corpusDigest === corpusDigest, 'run cross-engine summary corpus digest mismatch');
  const rows = Array.isArray(artifact?.cases) ? artifact.cases : [];
  const expectedCaseKeys = corpusCases.map(arithmeticCaseKey);
  pushIf(errors, exactSet(rows.map((item) => item?.caseKey), expectedCaseKeys), 'run summary lacks exact fixture coverage');
  const corpusByKey = new Map(corpusCases.map((item) => [arithmeticCaseKey(item), item]));
  for (const row of rows) {
    const expected = corpusByKey.get(row?.caseKey);
    pushIf(errors, expected?.expected?.verdict === row?.expectedVerdict, 'run summary expected verdict differs from corpus');
    pushIf(errors, isSha256(row?.fixtureDigest) && isSha256(row?.transactionDigest) && isSha256(row?.sourceOutputsDigest), 'run summary has an invalid fixture/input digest');
    const verdicts = Array.isArray(row?.engineVerdicts) ? row.engineVerdicts : [];
    pushIf(errors, exactSet(verdicts.map((item) => item?.engineId), GATE_B_ENGINES), 'run summary has incomplete engine verdict coverage');
    for (const engineId of GATE_B_ENGINES) {
      const observed = engineRows.get(engineId)?.get(row.caseKey);
      const summaryVerdict = verdicts.find((item) => item.engineId === engineId);
      pushIf(errors, observed?.fixtureDigest === row.fixtureDigest && observed?.transactionDigest === row.transactionDigest && observed?.sourceOutputsDigest === row.sourceOutputsDigest, `run summary fixture digest mismatch for ${engineId}`);
      pushIf(errors, observed?.verdict === summaryVerdict?.verdict, `run summary verdict mismatch for ${engineId}`);
    }
  }

  const agreements = Array.isArray(artifact?.metricAgreements) ? artifact.metricAgreements : [];
  const expectedAgreements = [];
  for (const entry of corpusCases) for (const metricId of GATE_B_METRICS) expectedAgreements.push(`${arithmeticCaseKey(entry)}|${metricId}`);
  pushIf(errors, exactSet(agreements.map(metricAgreementKey), expectedAgreements), 'run summary lacks exact metric agreement coverage');
  const summaryByKey = new Map(rows.map((item) => [item.caseKey, item]));
  for (const agreement of agreements) {
    const summaryRow = summaryByKey.get(agreement?.caseKey);
    for (const engineId of GATE_B_ENGINES) {
      const cell = metricCells.get(`${engineId}|${agreement.caseKey}|${agreement.metricId}`);
      pushIf(errors, cell?.fixtureDigest === summaryRow?.fixtureDigest, `run metric fixture digest mismatch for ${engineId}`);
    }
    const exposed = GATE_B_ENGINES.map((engineId) => metricCells.get(`${engineId}|${agreement.caseKey}|${agreement.metricId}`)).filter((cell) => cell && (cell.status === 'measured' || cell.status === 'derived-engine'));
    const engineIds = exposed.map((cell) => cell.engineId);
    pushIf(errors, exactArray(agreement?.comparableEngineIds, engineIds), 'run summary comparable engine set drifts from exposed metric cells');
    if (exposed.length >= 2) {
      const first = canonicalize(exposed[0].value);
      pushIf(errors, agreement?.status === 'agree' && exposed.every((cell) => canonicalize(cell.value) === first) && agreement?.valueDigest === sha256(first), 'run summary overlapping exposed metric disagreement');
    } else {
      pushIf(errors, agreement?.status === 'not-comparable' && agreement?.valueDigest === null, 'run summary incorrectly claims unavailable metric comparison');
    }
  }
  const allVerdictsAgree = rows.every((row) => row.engineVerdicts.every((item) => item.verdict === row.expectedVerdict));
  const allMetricAccounting = agreements.length === expectedAgreements.length && errors.every((error) => !error.includes('metric report') && !error.includes('metric agreement') && !error.includes('overlapping exposed'));
  pushIf(errors, artifact?.verdictAgreement === allVerdictsAgree, 'run summary verdictAgreement boolean is false or inflated');
  pushIf(errors, artifact?.metricCoverageAgreement === allMetricAccounting, 'run summary metricCoverageAgreement boolean is false or inflated');
};

export const validateArithmeticRun = (run, descriptor, campaign, { rootDir = laneDir, verifyArtifacts = true } = {}) => {
  const errors = [];
  pushIf(errors, run?.contentDigest?.value === contentDigestFor(run), 'run content digest mismatch');
  pushIf(errors, ['measured-component-only', 'failed', 'formal-coverage-blocked'].includes(run?.status), 'run status is invalid');
  pushIf(errors, run?.selection === 'none' && run?.tupleRef === null && run?.evidenceClassification === 'gate-b0-primitive-evidence-only', 'run evidence boundary drift');
  pushIf(errors, run?.descriptorBinding?.contentDigest === descriptor?.contentDigest?.value, 'run descriptor digest mismatch');
  pushIf(errors, run?.campaignBinding?.contentDigest === campaign?.contentDigest?.value, 'run campaign digest mismatch');
  if (verifyArtifacts) {
    verifyContentBinding(errors, run?.descriptorBinding, descriptor, 'run descriptor binding', rootDir);
    verifyContentBinding(errors, run?.campaignBinding, campaign, 'run campaign binding', rootDir);
    verifyFilePin(errors, run?.hostProfileBinding?.path, run?.hostProfileBinding?.sha256, 'run host profile', rootDir);
  }
  pushIf(errors, run?.hostProfileBinding?.sha256 === executionProfileDigest, 'run host profile digest drift');

  const expectedOrder = trackOrderForDescriptor(descriptor?.contentDigest?.value ?? '');
  pushIf(errors, exactArray(run?.trackOrder, expectedOrder), 'run counterbalanced track order mismatch');
  pushIf(errors, GATE_B_TRACKS.includes(run?.trackId) && run?.trackOrder?.[run?.trackPosition] === run?.trackId, 'run track position mismatch');
  if (run?.runMode === 'non-ranking-harness-shakedown') {
    pushIf(errors, run?.cohortEpochId === null, 'shakedown run must not claim a cohort epoch');
    pushIf(errors, descriptor?.registryBinding?.fieldSpecRef === 'field-spec:m89-d2', 'only M89 may use the first non-ranking shakedown mode');
  } else if (run?.runMode === 'full-cohort-epoch') {
    pushIf(errors, typeof run?.cohortEpochId === 'string', 'full cohort run lacks an epoch identity');
  } else errors.push('run mode is invalid');

  const expectedCounts = campaignCountsForDegree(campaign, descriptor?.registryBinding?.extensionDegree);
  pushIf(errors, run?.corpus?.generator === campaign?.corpusGenerator?.algorithm, 'run corpus generator does not match campaign');
  pushIf(errors, canonicalize(run?.corpus?.counts) === canonicalize(expectedCounts), 'run corpus counts do not match campaign formulas');
  pushIf(errors, exactSet((run?.engines ?? []).map((item) => item.engineId), GATE_B_ENGINES), 'run engine roster drift');
  pushIf(errors, exactSet((run?.toolchains ?? []).map((item) => item.engineId), GATE_B_ENGINES), 'run toolchain roster drift');
  pushIf(errors, uniqueBy(run?.artifacts, 'artifactId') && uniqueBy(run?.artifacts, 'kind') && exactSet((run?.artifacts ?? []).map((item) => item.kind), GATE_B_ARTIFACT_KINDS), 'run artifact roster contains a missing, duplicate, or unexpected kind');
  const schemaBindings = run?.artifactSchemaBindings ?? [];
  pushIf(errors, schemaBindings.length === ARITHMETIC_ARTIFACT_SCHEMA_BINDINGS.length && uniqueBy(schemaBindings, 'schemaId') && uniqueBy(schemaBindings, 'path') && ARITHMETIC_ARTIFACT_SCHEMA_BINDINGS.every((expected) => schemaBindings.some((binding) => binding?.schemaId === expected.schemaId && binding?.path === expected.path)), 'run artifact schema binding roster drift');
  const artifactRecords = new Map((run?.artifacts ?? []).map((item) => [item.kind, item]));
  const artifacts = new Map((run?.artifacts ?? []).map((item) => [item.kind, item.sha256]));
  for (const [kind, artifactSchema] of Object.entries(ARITHMETIC_ARTIFACT_SCHEMAS)) pushIf(errors, artifactRecords.get(kind)?.artifactSchema === artifactSchema, `run artifact schema binding mismatch for ${kind}`);
  pushIf(errors, artifacts.get('corpus') === run?.corpus?.digest, 'run corpus digest is not bound to raw corpus artifact');
  pushIf(errors, artifacts.get('cross-engine-summary') === run?.crossEngineSummary?.summaryArtifactDigest, 'run summary digest is not bound to raw summary artifact');
  for (const engine of run?.engines ?? []) {
    pushIf(errors, exactArray(engine.metricIds, GATE_B_METRICS) || (engine.engineId === 'engine:leanbch' && engine.status === 'explicit-unsupported' && engine.metricIds.length === 0), `run metric coverage drift for ${engine.engineId}`);
    pushIf(errors, engine.engineId === 'engine:leanbch' || engine.status !== 'explicit-unsupported', `only LeanBCH may be explicitly unsupported`);
    const artifactKind = engine.engineId === 'engine:native' ? 'native-result' : engine.engineId === 'engine:libauth' ? 'libauth-result' : engine.engineId === 'engine:bchn' ? 'bchn-result' : 'leanbch-result';
    pushIf(errors, artifacts.get(artifactKind) === engine.rawArtifactDigest, `run raw artifact binding mismatch for ${engine.engineId}`);
  }
  if (verifyArtifacts) {
    for (const artifact of run?.artifacts ?? []) verifyFilePin(errors, artifact.path, artifact.sha256, `run artifact ${artifact.artifactId}`, rootDir);
    for (const binding of schemaBindings) verifyFilePin(errors, binding.path, binding.sha256, `run artifact schema ${binding.schemaId}`, rootDir);
    const corpusArtifact = loadJsonFile(artifactRecords.get('corpus')?.path, rootDir);
    const corpusCases = validCorpusCases(corpusArtifact, errors);
    const engineRows = new Map();
    for (const engineId of GATE_B_ENGINES) {
      const artifact = loadJsonFile(artifactRecords.get(engineResultKind(engineId))?.path, rootDir);
      engineRows.set(engineId, validateEngineArtifact(artifact, engineId, run?.corpus?.digest, corpusCases, errors));
    }
    const metricReport = loadJsonFile(artifactRecords.get('metric-report')?.path, rootDir);
    const engineArtifactDigests = new Map(GATE_B_ENGINES.map((engineId) => [engineId, artifacts.get(engineResultKind(engineId))]));
    const metricCells = validateMetricReport(metricReport, run?.corpus?.digest, corpusCases, engineArtifactDigests, errors);
    const summary = loadJsonFile(artifactRecords.get('cross-engine-summary')?.path, rootDir);
    validateCrossEngineSummaryArtifact(summary, run?.corpus?.digest, corpusCases, engineRows, metricCells, errors);
    pushIf(errors, summary?.verdictAgreement === run?.crossEngineSummary?.verdictAgreement, 'run summary verdict agreement binding mismatch');
    pushIf(errors, summary?.metricCoverageAgreement === run?.crossEngineSummary?.metricCoverageAgreement, 'run summary metric accounting binding mismatch');
    for (const toolchain of run?.toolchains ?? []) {
      verifyFilePin(errors, toolchain.sourceStatusPath, toolchain.sourceStatusDigest, `run ${toolchain.engineId} source status`, rootDir);
      const sourceStatus = loadJsonFile(toolchain.sourceStatusPath, rootDir);
      pushIf(errors,
        sourceStatus?.primarySourceCommit === toolchain.sourceCommit
          && sourceStatus?.dirty === toolchain.dirty,
        `run ${toolchain.engineId} source status does not match declared commit/dirty state`);
      verifyFilePin(errors, toolchain.lockfilePath, toolchain.lockfileDigest, `run ${toolchain.engineId} lockfile`, rootDir);
      verifyFilePin(errors, toolchain.buildManifestPath, toolchain.buildDigest, `run ${toolchain.engineId} build manifest`, rootDir);
      verifyFilePin(errors, toolchain.commandPath, toolchain.commandDigest, `run ${toolchain.engineId} command`, rootDir);
    }
  }
  if (run?.status === 'measured-component-only') {
    pushIf(errors, run.engines.every((engine) => engine.status === 'measured'), 'measured run has incomplete engine coverage');
    pushIf(errors, run.crossEngineSummary?.verdictAgreement === true, 'measured run lacks verdict agreement');
    pushIf(errors, run.crossEngineSummary?.metricCoverageAgreement === true, 'measured run lacks complete metric coverage agreement');
  }
  if (run?.status === 'failed') pushIf(errors, run.engines?.some((engine) => engine.status === 'failed') || run.crossEngineSummary?.verdictAgreement === false, 'failed run has no recorded engine or verdict failure');
  if (run?.status === 'formal-coverage-blocked') pushIf(errors, run.engines?.some((engine) => engine.engineId === 'engine:leanbch' && engine.status === 'explicit-unsupported'), 'formal coverage block lacks explicit LeanBCH gap');
  return errors;
};
