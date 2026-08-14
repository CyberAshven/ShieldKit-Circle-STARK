import { createHash } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const moduleDir = dirname(fileURLToPath(import.meta.url));
export const laneDir = resolve(moduleDir, '../..');
const workspacePrefix = 'research-lanes/bch-shielded-pool-design/';

const artifactPath = (tail) => 'p2/' + tail;
const sha = (value) => createHash('sha256').update(value).digest('hex');

export const sha256 = sha;

export const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonicalize(value[key])).join(',') + '}';
};

export const canonicalJson = (value) => JSON.stringify(value, null, 2) + String.fromCharCode(10);

export const contentDigestFor = (value) => {
  const copy = structuredClone(value);
  delete copy.contentDigest;
  return sha(canonicalize(copy));
};

export const armDigestFor = (arm) => sha(canonicalize(arm));

export const normalizedCertificateStatement = (certificate) => ({
  certificateEntryId: certificate.certificateEntryId,
  constructionId: certificate.constructionId,
  fieldSpecRef: certificate.fieldSpecRef,
  q: certificate.q,
  p: certificate.p,
  degree: certificate.degree,
  polynomialCanonical: certificate.polynomialCanonical,
});

export const normalizedCertificateStatementDigest = (certificate) => sha(canonicalize(normalizedCertificateStatement(certificate)));

const same = (left, right) => canonicalize(left) === canonicalize(right);
const has = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const pushIf = (errors, condition, message) => { if (!condition) errors.push(message); };
const exactStrings = (actual, expected) => Array.isArray(actual)
  && actual.length === expected.length
  && actual.every((item, index) => item === expected[index]);

export const UPSTREAM = Object.freeze({
  constructionSummary: {
    artifactId: 'construction-freeze:p2-direct-polynomial-small-integer-v1',
    path: artifactPath('construction-freeze/construction-freeze.v1.json'),
    fileSha256: '5b276ff979fdb61c5919ef74c324cd62295fec99a8f2e9f5455f3adfdac237bc',
    contentDigest: '9737fb064d3b706835e441ec0b4d15aefb743fb62b098d4d3692321050e83137',
    schemaId: 'shieldkit-labs/p2/construction-freeze/v1',
    schemaPath: artifactPath('construction-freeze/construction-freeze.v1.schema.json'),
    schemaFileSha256: '86fc5e3ca1f26e813a07c12975aec15f5421e6692ed2082eb1b8f40b8ce16fb6',
  },
  constructionTranscript: {
    artifactId: 'construction-freeze:normalized-decision-transcript-v1',
    path: artifactPath('construction-freeze/construction-freeze.normalized-transcript.v1.json'),
    fileSha256: '58edd442a8700d9d2014f8d238ea6d7116e64baa427b3c89c33bc9d4878c20fe',
    contentDigest: '8eb2039920ae163c3584ca7a4b55ab5804f836760420b9cda185c4487ecf0dea',
    schemaId: 'shieldkit-labs/p2/construction-freeze-normalized-transcript/v1',
    schemaPath: artifactPath('construction-freeze/construction-freeze-normalized-transcript.v1.schema.json'),
    schemaFileSha256: '1d3ea6e7c1136f04e8bcebff211f57761c030add9f274c6b548596eead5492cf',
  },
  schedule: {
    artifactId: 'schedule-freeze:gate-b-direct-arithmetic-formula-envelope-v1',
    path: artifactPath('schedule-freeze/schedule-freeze.v1.json'),
    fileSha256: 'b96da97b99bcf45f34b77ea66c0e44192533634f10a48af1c889b8d0e1fdb173',
    contentDigest: '099bfc6ea2b571829985f74d62e5138a948d977c7f00e2a2eec94e7d643fae6c',
    schemaId: 'shieldkit-labs/p2/schedule-freeze/v1',
    schemaPath: artifactPath('schedule-freeze/schedule-freeze.v1.schema.json'),
    schemaFileSha256: 'ce75be25b66c8663c4d1f71e98485713afe66454fb8e283bab468834df719f6a',
  },
  certificateSet: {
    artifactId: 'direct-construction-cohort-v2',
    path: artifactPath('field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.json'),
    fileSha256: 'f01cf39df0ee4d9b44e8ad5fda9c5d0c44648ee0a74d27ef5967506fd70827da',
    contentDigest: '907dde98933678a81d1623660f9eff0d2f3ddfcfdd417a395048c5531fd82943',
    schemaId: 'shieldkit-labs/p2/direct-construction-cohort-v2/v2',
    schemaPath: artifactPath('field-cert/direct-construction-cohort-v2/direct-construction-cohort-v2.v2.schema.json'),
    schemaFileSha256: 'fb25c73f17c9aec50060daf9b73ec09b5219460013ac0c9539a215a567ba69db',
  },
  repositoryReplay: {
    path: artifactPath('field-cert/direct-construction-cohort-v2/repository-replay-report.v2.txt'),
    sha256: '7529af8adacb43ed38252f57fb0a807f5b235086325f45637e93dd054fc5c1f3',
  },
  repositoryReplaySource: {
    path: artifactPath('field-cert/direct-construction-cohort-v2/repository-replay.mjs'),
    sha256: 'f14e39869c5e11bc5ba5ee37ace4cbf554f282c4f6ec34ce31ef7b23f497f5cb',
  },
  directExtension: {
    path: artifactPath('reference/direct-extension.mjs'),
    sha256: '1ead86eb3bee0cd4e0d78ce6a03146d4d92e5bc4f6de646947a8c2fb5ca21faf',
  },
  directExtensionTest: {
    path: artifactPath('reference/direct-extension.test.mjs'),
    sha256: 'c99d0f8a348b552235352b5b8c50679026a3f0d05dae51861df26b3a4d64b14a',
  },
  relationContract: {
    path: artifactPath('gate-b/equal-relation-experiment.v1.json'),
    sha256: 'cd0e657214a108cd6d5dbf753b5739250f640fc13e03de21ec1be26bbf14c10a',
  },
  relationSchema: {
    path: artifactPath('gate-b/equal-relation-experiment.schema.json'),
    sha256: 'd2d8905fb61ddccb9991ca76d9689de2d60d035e2564c451f5fe0b7244b5c9e5',
  },
  profile: {
    path: 'profiles/bch-current-2026-08-08.json',
    sha256: 'd1ec071c1630d38dc719d5a040f36cc94fa02ac7d7f832769d09788595c80e3f',
    bchnCommit: '864c53ee34924cca6c6b6d96607ff2cedcdccf02',
  },
  descriptorSchema: artifactPath('algebra-component/algebra-component-descriptor.v2.schema.json'),
  legacyM89: {
    path: artifactPath('algebra-component/descriptors/m89-d2-x2-plus-1.v1.json'),
    fileSha256: 'd4ca84c426a5ddfbedc7e8a0052d5571a402db14104ae29291faca64a991f384',
    contentDigest: 'be55d7b3d73c08745aa0aaea1028c7c691318b0e1c1f698127dbf56f5e5d97b6',
  },
  externalReview: {
    path: artifactPath('field-cert/external-direct-construction-cohort-v2/external-review.v2.json'),
    fileSha256: 'cc92d0d967b4befeb0ea530824de20b29acda09d3fce4c366eac7852f26f06fe',
    contentDigest: 'e75e02d9826eef54bb05111e9a2df6d9b40e803a3bd9e8825f52aa17b87719cc',
    schemaId: 'shieldkit-labs/p2/field-cert/external-direct-construction-cohort-v2/external-review/v2',
    schemaPath: artifactPath('field-cert/external-direct-construction-cohort-v2/external-review.v2.schema.json'),
    schemaFileSha256: 'f73e02fc0e0da2a199bc37f3160bb80b840ade5eebdb514cb026e67b812eb278',
    checkerMethods: ['python-stdlib-certificate-replay', 'sympy-cas-irreducibility'],
    sourceBindings: [
      {
        path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/external-direct-construction-cohort-v2/review_direct_construction_v2.py',
        sha256: 'a7d37883bc6a05413312a1ca2ae9cc4babc63cc551e2fd7d6ce3a1bdaa19070d',
      },
      {
        path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/external-direct-construction-cohort-v2/requirements.lock',
        sha256: '12e14bdd332bc1b73ae00e6fe0ec34bd03e1a8df6da1386d997b859f5f16c50e',
      },
      {
        path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/external-direct-construction-cohort-v2/COMMAND.txt',
        sha256: 'b4168cbee459a88eea788c160d4f8b5b04ab3bb4bd8fcf1190ea44d953029d17',
      },
      {
        path: 'research-lanes/bch-shielded-pool-design/p2/field-cert/external-direct-construction-cohort-v2/environment.json',
        sha256: '81bc0de8403888bb2be0e1a61faf68f2b31e4f5fb6311d029b84b57a803ea765',
      },
    ],
  },
});

export const EXPECTED_CONSTRUCTIONS = Object.freeze([
  {
    fileName: 'm89-d2-x2-plus-1.v2.json',
    descriptorId: 'algebra-component:m89-d2-x2-plus-1-v2',
    constructionId: 'algebra-construction:m89-d2-x2-plus-1-v1',
    certificateEntryId: 'certificate-entry:m89-d2-x2-plus-1-v1',
    fieldSpecRef: 'field-spec:m89-d2',
    q: 89,
    p: '618970019642690137449562111',
    degree: 2,
    polynomialCanonical: ['1', '0', '1'],
    quotientRelation: 'x^2=-1',
    constructionFreezeRole: 'cohort-context-only-m89-legacy-shakedown-not-a-selection',
  },
  {
    fileName: 'm61-d3-x3-minus-5.v2.json',
    descriptorId: 'algebra-component:m61-d3-x3-minus-5-v2',
    constructionId: 'algebra-construction:m61-d3-x3-minus-5-v1',
    certificateEntryId: 'certificate-entry:m61-d3-x3-minus-5-v1',
    fieldSpecRef: 'field-spec:m61-d3',
    q: 61,
    p: '2305843009213693951',
    degree: 3,
    polynomialCanonical: ['2305843009213693946', '0', '0', '1'],
    quotientRelation: 'x^3=5',
    constructionFreezeRole: 'frozen-direct-construction-target',
  },
  {
    fileName: 'm31-d5-x5-plus-2x-minus-1.v2.json',
    descriptorId: 'algebra-component:m31-d5-x5-plus-2x-minus-1-v2',
    constructionId: 'algebra-construction:m31-d5-x5-plus-2x-minus-1-v1',
    certificateEntryId: 'certificate-entry:m31-d5-x5-plus-2x-minus-1-v1',
    fieldSpecRef: 'field-spec:m31-d5',
    q: 31,
    p: '2147483647',
    degree: 5,
    polynomialCanonical: ['2147483646', '2', '0', '0', '0', '1'],
    quotientRelation: 'x^5=1-2x',
    constructionFreezeRole: 'frozen-direct-construction-target',
  },
  {
    fileName: 'm31-d6-x6-minus-5.v2.json',
    descriptorId: 'algebra-component:m31-d6-x6-minus-5-v2',
    constructionId: 'algebra-construction:m31-d6-x6-minus-5-v1',
    certificateEntryId: 'certificate-entry:m31-d6-x6-minus-5-v1',
    fieldSpecRef: 'field-spec:m31-d6',
    q: 31,
    p: '2147483647',
    degree: 6,
    polynomialCanonical: ['2147483642', '0', '0', '0', '0', '0', '1'],
    quotientRelation: 'x^6=5',
    constructionFreezeRole: 'frozen-direct-construction-target',
  },
]);

const safeRegularFile = (relativePath, rootDir = laneDir) => {
  if (typeof relativePath !== 'string' || relativePath.length === 0 || isAbsolute(relativePath)) return null;
  const root = realpathSync(rootDir);
  const resolveRoot = relativePath.startsWith(workspacePrefix) ? realpathSync(resolve(root, '../..')) : root;
  const candidate = resolve(resolveRoot, relativePath);
  if (candidate !== resolveRoot && !candidate.startsWith(resolveRoot + sep)) return null;
  if (!existsSync(candidate)) return null;
  const resolved = realpathSync(candidate);
  if (resolved !== resolveRoot && !resolved.startsWith(resolveRoot + sep)) return null;
  return statSync(resolved).isFile() ? resolved : null;
};

export const fileDigest = (relativePath, rootDir = laneDir) => {
  try {
    const path = safeRegularFile(relativePath, rootDir);
    return path === null ? null : sha(readFileSync(path));
  } catch {
    return null;
  }
};

const readJson = (relativePath, rootDir = laneDir) => {
  const path = safeRegularFile(relativePath, rootDir);
  if (path === null) throw new Error('required JSON file is missing or unsafe: ' + relativePath);
  return JSON.parse(readFileSync(path, 'utf8'));
};

const contentDigestOf = (value) => {
  if (typeof value?.contentDigest === 'string') return value.contentDigest;
  if (typeof value?.contentDigest?.value === 'string') return value.contentDigest.value;
  return null;
};

const requirePin = (relativePath, expectedSha256, label, rootDir) => {
  const actual = fileDigest(relativePath, rootDir);
  if (actual === null) throw new Error(label + ' is missing or unsafe');
  if (actual !== expectedSha256) throw new Error(label + ' SHA-256 mismatch');
};

const jsonBindingFor = (meta, rootDir) => {
  requirePin(meta.path, meta.fileSha256, meta.artifactId, rootDir);
  requirePin(meta.schemaPath, meta.schemaFileSha256, meta.artifactId + ' schema', rootDir);
  const artifact = readJson(meta.path, rootDir);
  if (artifact.schema !== meta.schemaId) throw new Error(meta.artifactId + ' schema identity mismatch');
  if (contentDigestOf(artifact) !== meta.contentDigest) throw new Error(meta.artifactId + ' content digest mismatch');
  return {
    artifactId: meta.artifactId,
    path: meta.path,
    fileSha256: meta.fileSha256,
    contentDigest: meta.contentDigest,
    schemaId: meta.schemaId,
    schemaPath: meta.schemaPath,
    schemaFileSha256: meta.schemaFileSha256,
  };
};

const fileBindingFor = (meta, rootDir) => {
  requirePin(meta.path, meta.sha256, meta.path, rootDir);
  return { path: meta.path, sha256: meta.sha256 };
};

const assertExpectedInputs = (rootDir) => {
  const construction = jsonBindingFor(UPSTREAM.constructionSummary, rootDir);
  const transcript = jsonBindingFor(UPSTREAM.constructionTranscript, rootDir);
  const schedule = jsonBindingFor(UPSTREAM.schedule, rootDir);
  const certificateSet = jsonBindingFor(UPSTREAM.certificateSet, rootDir);
  const repositoryReplay = fileBindingFor(UPSTREAM.repositoryReplay, rootDir);
  const repositoryReplaySource = fileBindingFor(UPSTREAM.repositoryReplaySource, rootDir);
  const directExtension = fileBindingFor(UPSTREAM.directExtension, rootDir);
  const directExtensionTest = fileBindingFor(UPSTREAM.directExtensionTest, rootDir);
  const relationContract = fileBindingFor(UPSTREAM.relationContract, rootDir);
  const relationSchema = fileBindingFor(UPSTREAM.relationSchema, rootDir);
  const profile = fileBindingFor(UPSTREAM.profile, rootDir);
  const descriptorSchemaSha256 = fileDigest(UPSTREAM.descriptorSchema, rootDir);
  if (descriptorSchemaSha256 === null) throw new Error('descriptor v2 schema is missing');
  return {
    construction: readJson(UPSTREAM.constructionSummary.path, rootDir),
    transcript: readJson(UPSTREAM.constructionTranscript.path, rootDir),
    schedule: readJson(UPSTREAM.schedule.path, rootDir),
    certificateSet: readJson(UPSTREAM.certificateSet.path, rootDir),
    bindings: {
      construction,
      transcript,
      schedule,
      certificateSet,
      repositoryReplay,
      repositoryReplaySource,
      directExtension,
      directExtensionTest,
      relationContract,
      relationSchema,
      profile,
      descriptorSchema: {
        schemaId: 'shieldkit-labs/p2-algebra-component-descriptor/v2',
        path: UPSTREAM.descriptorSchema,
        fileSha256: descriptorSchemaSha256,
      },
    },
  };
};

const codecFor = (construction) => {
  const limbBytes = construction.codec.baseLimbBytes;
  const elementBytes = construction.codec.elementBytes;
  return {
    codecId: construction.codec.codecId,
    basis: 'direct-power-basis',
    baseLimbEncoding: 'fixed-width-unsigned-little-endian',
    coefficientOrder: 'c0-to-cd-minus-1',
    elementSplit: 'exact-degree-contiguous-equal-width-limbs',
    baseLimbBytes: limbBytes,
    elementBytes,
    modulusBitLength: construction.q,
    unusedHighBits: construction.codec.unusedHighBits,
    unusedHighBitMaskHex: construction.codec.unusedHighBitMaskHex,
    parserSteps: [
      'require-exact-extension-byte-length',
      'split-c0-to-cd-minus-1-fixed-width-limbs',
      'reject-unused-high-bits-before-one-byte-sign-guard-construction',
      'construct-one-byte-00-by-op-1-op-1-op-xor-then-raw-cat-and-bin2num-per-limb',
      'reject-unless-0<=coefficient<p',
      'require-full-consumption',
    ],
    signGuardConstruction: 'exact-one-byte-00-produced-by-OP_1-OP_1-OP_XOR-not-empty-OP_0',
    coefficientRange: 'reject-unless-0<=coefficient<p',
    numericEncode: 'canonical-mod-p-then-op-num2bin-fixed-width-per-limb-concatenate-c0-to-cd-minus-1',
    fullConsumption: true,
    hostNormalization: 'prohibited-before-parser-and-arithmetic',
    aliasPolicy: 'no-noncanonical-or-alternate-encoding-aliases',
    zeroHex: '00'.repeat(elementBytes),
    oneHex: '01' + '00'.repeat(elementBytes - 1),
  };
};

const relationsFor = (construction) => ({
  operations: [
    { operation: 'add', semantics: 'r_i=modp(a_i+b_i) for i=0..d-1' },
    { operation: 'subtract', semantics: 'r_i=modp(a_i-b_i) for i=0..d-1' },
    { operation: 'negate', semantics: 'r_i=modp(-a_i) for i=0..d-1' },
    { operation: 'multiply', semantics: 'r=reduce-direct-quotient-f(sum(i+j=k,a_i*b_j));all-coefficients-canonical-mod-p' },
    { operation: 'square', semantics: 'r=reduce-direct-quotient-f(square-polynomial(A));all-coefficients-canonical-mod-p' },
    { operation: 'equality', semantics: 'accept=canonical(A)&&canonical(B)&&all-c0-to-cd-minus-1-limbs-equal' },
    { operation: 'inverse-hint', semantics: 'accept=canonical(A)&&canonical(H)&&A!=zero&&mul(A,H)==one;never-compute-an-inverse' },
  ],
  gateB: {
    eMac: 'relation:e-mac=eq(D,add(mul(A,B),C));selected-arm-mul-once',
    eSquareMac: 'relation:e-square-mac=eq(D,add(square(A),C));selected-arm-square-once',
    eInverseCheck: 'relation:e-inverse-check=and(ne(A,zero),eq(mul(A,H),one));verify-supplied-hint-only-never-compute-inverse',
  },
  parserBoundary: 'all-malformed-inputs-reject-at-parser-before-selected-arm',
});

const expectedArmBindings = (schedule, construction) => schedule.arms
  .filter((arm) => arm.constructionId === construction.constructionId)
  .map((arm) => ({
    armId: arm.armId,
    trackId: arm.trackId,
    algorithmId: arm.algorithmId,
    constructionId: arm.constructionId,
    codecId: arm.codecId,
    armDigest: armDigestFor(arm),
  }));

const expectedArmCounts = (schedule, construction) => schedule.arms
  .filter((arm) => arm.constructionId === construction.constructionId)
  .map((arm) => ({
    armId: arm.armId,
    multiplyVariableBaseFieldOps: arm.declaredVariableBaseCounts.multiply,
    squareVariableBaseFieldOps: arm.declaredVariableBaseCounts.square,
    countClassification: 'declared-variable-base-field-operation-count-not-vm-or-rank-metric',
  }));

const targetBindingFor = (construction, summary) => {
  const target = (summary.targets || []).find((item) => item.q === construction.q && item.degree === construction.degree);
  if (target === undefined) return null;
  if (target.p !== construction.p || !same(target.winner?.polynomialCanonical, construction.definingPolynomialAscending)) {
    throw new Error('construction-freeze target does not match schedule construction ' + construction.constructionId);
  }
  return {
    q: target.q,
    degree: target.degree,
    p: target.p,
    polynomialCanonical: target.winner.polynomialCanonical,
  };
};

const constructionSpec = (constructionId) => EXPECTED_CONSTRUCTIONS.find((item) => item.constructionId === constructionId);

const assertConstructionRoster = (inputs) => {
  const scheduleConstructions = inputs.schedule.fieldConstructions || [];
  if (scheduleConstructions.length !== EXPECTED_CONSTRUCTIONS.length) throw new Error('schedule construction roster length drift');
  for (let index = 0; index < EXPECTED_CONSTRUCTIONS.length; index += 1) {
    const expected = EXPECTED_CONSTRUCTIONS[index];
    const actual = scheduleConstructions[index];
    if (actual === undefined
      || actual.constructionId !== expected.constructionId
      || actual.fieldSpecRef !== expected.fieldSpecRef
      || actual.q !== expected.q
      || actual.p !== expected.p
      || actual.degree !== expected.degree
      || !same(actual.definingPolynomialAscending, expected.polynomialCanonical)
      || actual.quotientRelation !== expected.quotientRelation) {
      throw new Error('schedule construction roster drift at index ' + index);
    }
  }
  const certificateOrder = inputs.certificateSet.scheduleOrder || [];
  if (certificateOrder.length !== EXPECTED_CONSTRUCTIONS.length) throw new Error('certificate schedule roster length drift');
  for (let index = 0; index < EXPECTED_CONSTRUCTIONS.length; index += 1) {
    const expected = EXPECTED_CONSTRUCTIONS[index];
    const actual = certificateOrder[index];
    if (actual === undefined
      || actual.constructionId !== expected.constructionId
      || actual.certificateEntryId !== expected.certificateEntryId
      || actual.fieldSpecRef !== expected.fieldSpecRef
      || actual.q !== expected.q
      || actual.degree !== expected.degree
      || !same(actual.polynomialCanonical, expected.polynomialCanonical)) {
      throw new Error('certificate schedule roster drift at index ' + index);
    }
  }
};

const externalCertificateEntries = (external) => {
  const entries = external?.entries ?? external?.certificateEntries ?? external?.reviews;
  if (!Array.isArray(entries)) throw new Error('external review has no exact per-certificate entry array');
  return entries;
};

const externalEntryFor = (external, certificate) => {
  const entry = externalCertificateEntries(external).find((item) => item?.certificateEntryId === certificate.certificateEntryId);
  if (entry === undefined) throw new Error('external review is missing certificate entry ' + certificate.certificateEntryId);
  const statementDigest = normalizedCertificateStatementDigest(certificate);
  if (!same(entry.statement, normalizedCertificateStatement(certificate))
    || entry.constructionId !== certificate.constructionId
    || entry.fieldSpecRef !== certificate.fieldSpecRef
    || entry.q !== certificate.q
    || entry.p !== certificate.p
    || entry.degree !== certificate.degree
    || !same(entry.polynomialCanonical, certificate.polynomialCanonical)
    || entry.statementDigest !== statementDigest
    || entry.repositoryCertificateDigest !== certificate.certificateDigest
    || entry.recomputedCertificateDigest !== certificate.certificateDigest
    || !same(entry.checkerVerdicts, {
      'python-stdlib-certificate-replay': 'PASS',
      'sympy-cas-irreducibility': 'PASS',
    })
    || entry.verdict !== 'PASS') {
    throw new Error('external review entry is not an exact dual-method pass: ' + certificate.certificateEntryId);
  }
  return { entry, statementDigest };
};

const externalCertificateSetPins = (external) => {
  const expectedPath = 'research-lanes/bch-shielded-pool-design/' + UPSTREAM.certificateSet.path;
  const binding = external?.inputBindings?.find((item) => item?.path === expectedPath);
  if (binding === undefined) throw new Error('external review has no exact certificate-set binding');
  const fileSha256 = binding.sha256;
  const contentDigest = binding.contentDigest;
  if (typeof fileSha256 !== 'string' || typeof contentDigest !== 'string') {
    throw new Error('external review certificate-set binding lacks exact file/content digests');
  }
  return { fileSha256, contentDigest };
};

export const validateFinalExternalReviewShape = (review, schema, certificateSet) => {
  const errors = [];
  pushIf(errors, review?.reviewId === 'external-direct-construction-cohort-v2'
    && review?.status === 'all-independent-replays-passed'
    && review?.finalVerdict === 'PASS', 'external review final PASS/status mismatch');
  pushIf(errors, review?.selection === 'none' && review?.tupleRef === null, 'external review selection/tuple boundary mismatch');
  pushIf(errors, review?.schema === UPSTREAM.externalReview.schemaId
    && schema?.$id === 'https://shieldkit-labs.local/p2/field-cert/external-direct-construction-cohort-v2/external-review.v2.schema.json'
    && schema?.properties?.schema?.const === review?.schema, 'external review/schema identity mismatch');
  pushIf(errors, review?.contentDigest === UPSTREAM.externalReview.contentDigest
    && review?.contentDigest === contentDigestFor(review), 'external review canonical content digest mismatch');
  pushIf(errors, same(review?.tool?.checkerFamilies, UPSTREAM.externalReview.checkerMethods), 'external review checker-method roster mismatch');
  let certificateSetPins = null;
  try { certificateSetPins = externalCertificateSetPins(review); } catch (error) { errors.push(error.message); }
  if (certificateSetPins !== null) {
    pushIf(errors, certificateSetPins.fileSha256 === UPSTREAM.certificateSet.fileSha256
      && certificateSetPins.contentDigest === UPSTREAM.certificateSet.contentDigest, 'external review certificate-set binding mismatch');
  }
  pushIf(errors, same(review?.sourceBindings?.map((item) => ({ path: item.path, sha256: item.sha256 })), UPSTREAM.externalReview.sourceBindings), 'external review source binding roster mismatch');
  const certificates = certificateSet?.certificates;
  pushIf(errors, Array.isArray(certificates) && Array.isArray(review?.entries) && review.entries.length === certificates?.length, 'external review certificate entry roster mismatch');
  if (Array.isArray(certificates) && Array.isArray(review?.entries) && review.entries.length === certificates.length) {
    for (const certificate of certificates) {
      try { externalEntryFor(review, certificate); } catch (error) { errors.push(error.message); }
    }
  }
  return errors;
};

const loadFinalExternalReview = (rootDir) => {
  const reviewPath = UPSTREAM.externalReview.path;
  const schemaPath = UPSTREAM.externalReview.schemaPath;
  requirePin(reviewPath, UPSTREAM.externalReview.fileSha256, 'external review', rootDir);
  requirePin(schemaPath, UPSTREAM.externalReview.schemaFileSha256, 'external review schema', rootDir);
  const review = readJson(reviewPath, rootDir);
  const schema = readJson(schemaPath, rootDir);
  const certificateSet = readJson(UPSTREAM.certificateSet.path, rootDir);
  const reviewErrors = validateFinalExternalReviewShape(review, schema, certificateSet);
  if (reviewErrors.length > 0) throw new Error(reviewErrors.join('; '));
  for (const source of UPSTREAM.externalReview.sourceBindings) requirePin(source.path, source.sha256, 'external review source ' + source.path, rootDir);
  const certificateSetPins = externalCertificateSetPins(review);
  return {
    review,
    binding: {
      artifactId: review.reviewId,
      path: reviewPath,
      fileSha256: UPSTREAM.externalReview.fileSha256,
      contentDigest: review.contentDigest,
      schemaId: review.schema,
      schemaPath,
      schemaFileSha256: UPSTREAM.externalReview.schemaFileSha256,
    },
    certificateSetPins,
    checkerMethods: UPSTREAM.externalReview.checkerMethods,
    sourceBindings: UPSTREAM.externalReview.sourceBindings,
  };
};

const descriptorFor = (expected, inputs, external) => {
  const construction = inputs.schedule.fieldConstructions.find((item) => item.constructionId === expected.constructionId);
  const certificate = inputs.certificateSet.certificates.find((item) => item.certificateEntryId === expected.certificateEntryId);
  if (construction === undefined || certificate === undefined) throw new Error('missing frozen construction or certificate for ' + expected.constructionId);
  const statementDigest = normalizedCertificateStatementDigest(certificate);
  const externalEntry = externalEntryFor(external.review, certificate);
  if (externalEntry.statementDigest !== statementDigest) throw new Error('external statement digest mismatch for ' + expected.constructionId);
  const targetBinding = targetBindingFor(construction, inputs.construction);
  if (expected.constructionFreezeRole === 'frozen-direct-construction-target' && targetBinding === null) {
    throw new Error('construction-freeze target is missing for ' + expected.constructionId);
  }
  if (expected.constructionFreezeRole !== 'frozen-direct-construction-target' && targetBinding !== null) {
    throw new Error('M89 construction-freeze context unexpectedly claims a target');
  }
  const descriptor = {
    schema: 'shieldkit-labs/p2-algebra-component-descriptor/v2',
    descriptorId: expected.descriptorId,
    status: 'frozen-cohort-formula-bound-nonexecutable',
    contentDigest: { algorithm: 'sha256-jcs-omit-contentDigest', value: null },
    qualification: {
      status: 'gate-b0-component-only-unqualified',
      artifactClassification: 'descriptor-contract',
      executionEvidenceClassification: 'not-execution-evidence',
      selection: 'none',
      tupleRef: null,
      fieldRanking: 'none',
      proofSystemRanking: 'none',
      protocolRanking: 'none',
    },
    lineage: {
      fieldSpecRef: expected.fieldSpecRef,
      constructionId: expected.constructionId,
      certificateEntryId: expected.certificateEntryId,
      fieldSpecRefRole: 'lineage-label-only-not-an-authoritative-candidate-matrix-binding',
      candidateMatrixBinding: null,
    },
    descriptorSchemaBinding: inputs.bindings.descriptorSchema,
    constructionFreezeBinding: {
      summary: inputs.bindings.construction,
      normalizedTranscript: inputs.bindings.transcript,
      bindingRole: expected.constructionFreezeRole,
      targetBinding,
    },
    scheduleFreezeBinding: {
      artifact: inputs.bindings.schedule,
      orderingOwner: 'schedule-freeze-ordering-rule-only',
      resolvedPermutation: null,
    },
    certificateSetBinding: {
      artifact: inputs.bindings.certificateSet,
      repositoryReplay: inputs.bindings.repositoryReplay,
      repositoryReplaySource: inputs.bindings.repositoryReplaySource,
    },
    externalReviewBinding: {
      artifact: external.binding,
      certificateSetFileSha256: external.certificateSetPins.fileSha256,
      certificateSetContentDigest: external.certificateSetPins.contentDigest,
      allPass: true,
      checkerMethods: external.checkerMethods,
      sourceBindings: external.sourceBindings,
    },
    certificateBinding: {
      certificateId: certificate.certificateId,
      certificateDigest: certificate.certificateDigest,
      normalizedStatementDigest: statementDigest,
      checkerFamilies: [
        {
          family: 'repository-rabin-replay',
          statementDigest,
          artifactBinding: inputs.bindings.repositoryReplay,
        },
        {
          family: 'external-python-sympy-review',
          statementDigest,
          artifactBinding: { path: external.binding.path, sha256: external.binding.fileSha256 },
        },
      ],
    },
    directQuotient: {
      kind: 'direct-polynomial',
      basis: 'direct-power-basis',
      p: expected.p,
      q: expected.q,
      degree: expected.degree,
      generatorSymbol: 'x',
      definingPolynomialAscending: expected.polynomialCanonical,
      monic: true,
      quotientRelation: expected.quotientRelation,
      towerPolicy: 'tower-schedules-internal-only-never-algebra-or-codec',
    },
    canonicalCodec: codecFor(construction),
    relationSemantics: relationsFor(construction),
    symbolicBounds: {
      classification: 'formula-level-only-not-a-source-or-vm-measurement',
      integerLift: 'symbolic-nonnegative-coefficient-lift-with-signed-formula-constants',
      perArmCounts: expectedArmCounts(inputs.schedule, construction),
      sourceLoweredMetrics: null,
      opcodeMetrics: null,
      byteMetrics: null,
      stackMetrics: null,
      vmMetrics: null,
    },
    sourcePins: {
      referenceDirectExtension: inputs.bindings.directExtension,
      referenceDirectExtensionTest: inputs.bindings.directExtensionTest,
      relationContract: inputs.bindings.relationContract,
      relationSchema: inputs.bindings.relationSchema,
    },
    executionProfileBinding: {
      profilePath: UPSTREAM.profile.path,
      profileFileSha256: UPSTREAM.profile.sha256,
      bchnCommit: UPSTREAM.profile.bchnCommit,
      usage: 'source-pinned-execution-policy-only-no-lowering-or-vm-metric-claim',
    },
    scheduleArmBindings: expectedArmBindings(inputs.schedule, construction),
    protocolBoundary: {
      capability: 'gate-b0-field-arithmetic-only',
      protocolRoles: [],
      circleDomain: null,
      circleQuery: null,
      deepStrategy: null,
      embeddings: [],
      challengeSamplers: [],
      soundnessEventDag: null,
      hashBindings: [],
      airRole: null,
      transcriptRole: null,
      proofSystemRole: null,
    },
    executionBoundary: {
      executionState: 'closed',
      executionAllowed: false,
      requiredDownstreamArtifacts: [
        'campaign-v2-content-binding',
        'canonical-corpus-v2-content-binding',
        'per-arm-lowering-source-contract-content-bindings',
        'execution-epoch-binding',
      ],
      presentDownstreamBindings: [],
      prohibitedEvidence: 'no-execution-run-corpus-or-ranking-evidence-is-bound-by-this-descriptor',
    },
    legacyLineage: expected.constructionId === EXPECTED_CONSTRUCTIONS[0].constructionId
      ? {
        descriptorPath: UPSTREAM.legacyM89.path,
        descriptorFileSha256: UPSTREAM.legacyM89.fileSha256,
        descriptorContentDigest: UPSTREAM.legacyM89.contentDigest,
        classification: 'legacy-m89-shakedown-only',
        cohortEvidenceEligible: false,
        prohibitedArtifactUses: 'v1-corpus-and-v1-run-cannot-be-v2-cohort-evidence',
      }
      : null,
  };
  descriptor.contentDigest.value = contentDigestFor(descriptor);
  return descriptor;
};

export const generateDescriptorV2Set = ({ rootDir = laneDir } = {}) => {
  const inputs = assertExpectedInputs(rootDir);
  assertConstructionRoster(inputs);
  const external = loadFinalExternalReview(rootDir);
  const descriptors = EXPECTED_CONSTRUCTIONS.map((expected) => descriptorFor(expected, inputs, external));
  for (const descriptor of descriptors) {
    const errors = validateDescriptorV2(descriptor, { rootDir, verifyPins: true });
    if (errors.length > 0) throw new Error('generated descriptor failed semantic validation: ' + errors.join('; '));
  }
  return descriptors;
};

const checkJsonBinding = (errors, actual, expected, label, rootDir) => {
  pushIf(errors, same(actual, expected), label + ' binding mismatch');
  if (!same(actual, expected)) return;
  pushIf(errors, fileDigest(expected.path, rootDir) === expected.fileSha256, label + ' file digest mismatch');
  pushIf(errors, fileDigest(expected.schemaPath, rootDir) === expected.schemaFileSha256, label + ' schema digest mismatch');
  const artifact = (() => { try { return readJson(expected.path, rootDir); } catch { return null; } })();
  pushIf(errors, artifact !== null && artifact.schema === expected.schemaId, label + ' schema identity mismatch');
  pushIf(errors, contentDigestOf(artifact) === expected.contentDigest, label + ' content digest mismatch');
};

const checkFileBinding = (errors, actual, expected, label, rootDir) => {
  pushIf(errors, same(actual, expected), label + ' binding mismatch');
  pushIf(errors, fileDigest(expected.path, rootDir) === expected.sha256, label + ' digest mismatch');
};

const expectedFromDescriptor = (descriptor) => constructionSpec(descriptor?.lineage?.constructionId);

const codecExpected = (construction) => codecFor(construction);

const validateExternalBinding = (descriptor, expected, rootDir, errors, verifyPins) => {
  const binding = descriptor.externalReviewBinding;
  pushIf(errors, binding?.allPass === true, 'external review allPass is required');
  pushIf(errors, binding?.certificateSetFileSha256 === UPSTREAM.certificateSet.fileSha256, 'external review certificate set file digest mismatch');
  pushIf(errors, binding?.certificateSetContentDigest === UPSTREAM.certificateSet.contentDigest, 'external review certificate set content digest mismatch');
  pushIf(errors, same(binding?.checkerMethods, UPSTREAM.externalReview.checkerMethods), 'external review checker-method roster mismatch');
  pushIf(errors, same(binding?.sourceBindings, UPSTREAM.externalReview.sourceBindings), 'external review source binding roster mismatch');
  if (!verifyPins) return null;
  let external;
  try { external = loadFinalExternalReview(rootDir); } catch (error) { errors.push('external review is not final/valid: ' + error.message); return null; }
  pushIf(errors, same(binding.artifact, external.binding), 'external review artifact binding mismatch');
  return external;
};

export const validateDescriptorV2 = (descriptor, { rootDir = laneDir, verifyPins = true } = {}) => {
  const errors = [];
  pushIf(errors, descriptor?.schema === 'shieldkit-labs/p2-algebra-component-descriptor/v2', 'descriptor schema identity mismatch');
  pushIf(errors, descriptor?.status === 'frozen-cohort-formula-bound-nonexecutable', 'descriptor must remain nonexecutable');
  pushIf(errors, descriptor?.contentDigest?.algorithm === 'sha256-jcs-omit-contentDigest'
    && descriptor?.contentDigest?.value === contentDigestFor(descriptor), 'descriptor content digest mismatch');
  pushIf(errors, descriptor?.qualification?.status === 'gate-b0-component-only-unqualified'
    && descriptor?.qualification?.artifactClassification === 'descriptor-contract'
    && descriptor?.qualification?.executionEvidenceClassification === 'not-execution-evidence'
    && descriptor?.qualification?.selection === 'none'
    && descriptor?.qualification?.tupleRef === null
    && descriptor?.qualification?.fieldRanking === 'none'
    && descriptor?.qualification?.proofSystemRanking === 'none'
    && descriptor?.qualification?.protocolRanking === 'none', 'qualification/ranking boundary mismatch');
  const expected = expectedFromDescriptor(descriptor);
  if (expected === undefined) {
    errors.push('unknown construction lineage');
    return errors;
  }
  pushIf(errors, descriptor.descriptorId === expected.descriptorId, 'descriptor identity mismatch');
  const lineage = descriptor.lineage;
  pushIf(errors, lineage?.fieldSpecRef === expected.fieldSpecRef
    && lineage?.constructionId === expected.constructionId
    && lineage?.certificateEntryId === expected.certificateEntryId
    && lineage?.fieldSpecRefRole === 'lineage-label-only-not-an-authoritative-candidate-matrix-binding'
    && lineage?.candidateMatrixBinding === null, 'lineage binding mismatch or authoritative matrix binding introduced');

  const schemaBinding = {
    schemaId: 'shieldkit-labs/p2-algebra-component-descriptor/v2',
    path: UPSTREAM.descriptorSchema,
    fileSha256: fileDigest(UPSTREAM.descriptorSchema, rootDir),
  };
  pushIf(errors, schemaBinding.fileSha256 !== null && same(descriptor.descriptorSchemaBinding, schemaBinding), 'descriptor schema binding mismatch');

  if (verifyPins) {
    let inputs;
    try { inputs = assertExpectedInputs(rootDir); assertConstructionRoster(inputs); } catch (error) { errors.push('upstream pin validation failed: ' + error.message); return errors; }
    checkJsonBinding(errors, descriptor.constructionFreezeBinding?.summary, inputs.bindings.construction, 'construction summary', rootDir);
    checkJsonBinding(errors, descriptor.constructionFreezeBinding?.normalizedTranscript, inputs.bindings.transcript, 'construction transcript', rootDir);
    checkJsonBinding(errors, descriptor.scheduleFreezeBinding?.artifact, inputs.bindings.schedule, 'schedule freeze', rootDir);
    checkJsonBinding(errors, descriptor.certificateSetBinding?.artifact, inputs.bindings.certificateSet, 'certificate set', rootDir);
    checkFileBinding(errors, descriptor.certificateSetBinding?.repositoryReplay, inputs.bindings.repositoryReplay, 'repository replay', rootDir);
    checkFileBinding(errors, descriptor.certificateSetBinding?.repositoryReplaySource, inputs.bindings.repositoryReplaySource, 'repository replay source', rootDir);
    checkFileBinding(errors, descriptor.sourcePins?.referenceDirectExtension, inputs.bindings.directExtension, 'direct extension source', rootDir);
    checkFileBinding(errors, descriptor.sourcePins?.referenceDirectExtensionTest, inputs.bindings.directExtensionTest, 'direct extension test', rootDir);
    checkFileBinding(errors, descriptor.sourcePins?.relationContract, inputs.bindings.relationContract, 'relation contract', rootDir);
    checkFileBinding(errors, descriptor.sourcePins?.relationSchema, inputs.bindings.relationSchema, 'relation schema', rootDir);

    const scheduleConstruction = inputs.schedule.fieldConstructions.find((item) => item.constructionId === expected.constructionId);
    const certificate = inputs.certificateSet.certificates.find((item) => item.certificateEntryId === expected.certificateEntryId);
    const targetBinding = targetBindingFor(scheduleConstruction, inputs.construction);
    const expectedRole = expected.constructionFreezeRole;
    pushIf(errors, descriptor.constructionFreezeBinding?.bindingRole === expectedRole
      && same(descriptor.constructionFreezeBinding?.targetBinding, targetBinding), 'construction-freeze target binding mismatch');
    pushIf(errors, descriptor.scheduleFreezeBinding?.orderingOwner === 'schedule-freeze-ordering-rule-only'
      && descriptor.scheduleFreezeBinding?.resolvedPermutation === null, 'descriptor must not materialize schedule ordering');

    const external = validateExternalBinding(descriptor, expected, rootDir, errors, true);
    const statementDigest = normalizedCertificateStatementDigest(certificate);
    pushIf(errors, descriptor.certificateBinding?.certificateId === certificate.certificateId
      && descriptor.certificateBinding?.certificateDigest === certificate.certificateDigest
      && descriptor.certificateBinding?.normalizedStatementDigest === statementDigest, 'certificate statement/digest binding mismatch');
    const checkerFamilies = descriptor.certificateBinding?.checkerFamilies ?? [];
    pushIf(errors, exactStrings(checkerFamilies.map((item) => item?.family), ['repository-rabin-replay', 'external-python-sympy-review']), 'checker families must be one repository Rabin and one external Python+SymPy review');
    pushIf(errors, new Set(checkerFamilies.map((item) => item?.family)).size === 2, 'checker families must be distinct');
    pushIf(errors, checkerFamilies.every((item) => item?.statementDigest === statementDigest), 'checker statement digest mismatch');
    pushIf(errors, same(checkerFamilies[0]?.artifactBinding, inputs.bindings.repositoryReplay), 'repository checker provenance mismatch');
    if (external !== null) {
      const externalEntry = (() => { try { return externalEntryFor(external.review, certificate); } catch (error) { errors.push(error.message); return null; } })();
      if (externalEntry !== null) pushIf(errors, externalEntry.statementDigest === statementDigest, 'external normalized statement digest mismatch');
      pushIf(errors, checkerFamilies[1]?.artifactBinding?.path === external.binding.path
        && checkerFamilies[1]?.artifactBinding?.sha256 === external.binding.fileSha256, 'external checker provenance mismatch');
    }

    const direct = descriptor.directQuotient;
    const p = (1n << BigInt(expected.q)) - 1n;
    pushIf(errors, direct?.kind === 'direct-polynomial'
      && direct?.basis === 'direct-power-basis'
      && direct?.p === p.toString()
      && direct?.q === expected.q
      && direct?.degree === expected.degree
      && direct?.generatorSymbol === 'x'
      && same(direct?.definingPolynomialAscending, expected.polynomialCanonical)
      && direct?.monic === true
      && direct?.quotientRelation === expected.quotientRelation
      && direct?.towerPolicy === 'tower-schedules-internal-only-never-algebra-or-codec', 'direct quotient mismatch');
    try {
      const coefficients = direct.definingPolynomialAscending;
      pushIf(errors, coefficients.length === expected.degree + 1 && coefficients.at(-1) === '1'
        && coefficients.every((item) => /^(0|[1-9][0-9]*)$/u.test(item) && BigInt(item) >= 0n && BigInt(item) < p), 'direct polynomial monicity/range mismatch');
    } catch { errors.push('direct polynomial values are not canonical decimal strings'); }

    pushIf(errors, same(descriptor.canonicalCodec, codecExpected(scheduleConstruction)), 'canonical direct codec mismatch');
    const armBindings = expectedArmBindings(inputs.schedule, scheduleConstruction);
    const armCounts = expectedArmCounts(inputs.schedule, scheduleConstruction);
    pushIf(errors, same(descriptor.scheduleArmBindings, armBindings), 'schedule arm roster/digest mismatch or arm omitted');
    pushIf(errors, same(descriptor.symbolicBounds?.perArmCounts, armCounts), 'symbolic per-arm counts mismatch');
    for (const arm of descriptor.scheduleArmBindings ?? []) {
      if (arm.armId.includes('tower')) {
        pushIf(errors, arm.codecId === scheduleConstruction.codec.codecId, 'tower schedule arm exposes a non-direct codec');
      }
    }
  }

  pushIf(errors, same(descriptor.relationSemantics, relationsFor({})), 'relation semantics mismatch');
  const bounds = descriptor.symbolicBounds;
  pushIf(errors, bounds?.classification === 'formula-level-only-not-a-source-or-vm-measurement'
    && bounds?.integerLift === 'symbolic-nonnegative-coefficient-lift-with-signed-formula-constants'
    && bounds?.sourceLoweredMetrics === null
    && bounds?.opcodeMetrics === null
    && bounds?.byteMetrics === null
    && bounds?.stackMetrics === null
    && bounds?.vmMetrics === null, 'symbolic/measurement boundary mismatch');
  pushIf(errors, descriptor.executionProfileBinding?.profilePath === UPSTREAM.profile.path
    && descriptor.executionProfileBinding?.profileFileSha256 === UPSTREAM.profile.sha256
    && descriptor.executionProfileBinding?.bchnCommit === UPSTREAM.profile.bchnCommit
    && descriptor.executionProfileBinding?.usage === 'source-pinned-execution-policy-only-no-lowering-or-vm-metric-claim', 'execution profile binding mismatch');
  if (verifyPins) pushIf(errors, fileDigest(UPSTREAM.profile.path, rootDir) === UPSTREAM.profile.sha256, 'execution profile file digest mismatch');
  const protocol = descriptor.protocolBoundary;
  pushIf(errors, protocol?.capability === 'gate-b0-field-arithmetic-only'
    && exactStrings(protocol?.protocolRoles, [])
    && protocol?.circleDomain === null
    && protocol?.circleQuery === null
    && protocol?.deepStrategy === null
    && exactStrings(protocol?.embeddings, [])
    && exactStrings(protocol?.challengeSamplers, [])
    && protocol?.soundnessEventDag === null
    && exactStrings(protocol?.hashBindings, [])
    && protocol?.airRole === null
    && protocol?.transcriptRole === null
    && protocol?.proofSystemRole === null, 'protocol boundary inflation');
  const execution = descriptor.executionBoundary;
  pushIf(errors, execution?.executionState === 'closed'
    && execution?.executionAllowed === false
    && exactStrings(execution?.requiredDownstreamArtifacts, [
      'campaign-v2-content-binding',
      'canonical-corpus-v2-content-binding',
      'per-arm-lowering-source-contract-content-bindings',
      'execution-epoch-binding',
    ])
    && exactStrings(execution?.presentDownstreamBindings, [])
    && execution?.prohibitedEvidence === 'no-execution-run-corpus-or-ranking-evidence-is-bound-by-this-descriptor', 'execution boundary mismatch');
  const isM89 = expected.constructionId === EXPECTED_CONSTRUCTIONS[0].constructionId;
  if (isM89) {
    pushIf(errors, same(descriptor.legacyLineage, {
      descriptorPath: UPSTREAM.legacyM89.path,
      descriptorFileSha256: UPSTREAM.legacyM89.fileSha256,
      descriptorContentDigest: UPSTREAM.legacyM89.contentDigest,
      classification: 'legacy-m89-shakedown-only',
      cohortEvidenceEligible: false,
      prohibitedArtifactUses: 'v1-corpus-and-v1-run-cannot-be-v2-cohort-evidence',
    }), 'M89 legacy lineage mismatch');
    if (verifyPins) {
      pushIf(errors, fileDigest(UPSTREAM.legacyM89.path, rootDir) === UPSTREAM.legacyM89.fileSha256, 'M89 v1 descriptor file digest mismatch');
      const legacy = (() => { try { return readJson(UPSTREAM.legacyM89.path, rootDir); } catch { return null; } })();
      pushIf(errors, contentDigestOf(legacy) === UPSTREAM.legacyM89.contentDigest, 'M89 v1 descriptor content digest mismatch');
    }
  } else {
    pushIf(errors, descriptor.legacyLineage === null, 'only M89 may carry legacy lineage');
  }
  return errors;
};
