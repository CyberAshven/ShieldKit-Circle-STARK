import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const DIRECTORY = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(DIRECTORY, '../../../../');
export const SCHEMA_PATH = 'research-lanes/bch-shielded-pool-design/p2/lowering-freeze/lowering-freeze.v1.schema.json';
export const DESCRIPTOR_SCHEMA_PATH = 'research-lanes/bch-shielded-pool-design/p2/algebra-component/algebra-component-descriptor.v2.schema.json';
export const SCHEDULE_SCHEMA_PATH = 'research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.v1.schema.json';
export const SCHEDULE_PATH = 'research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.v1.json';
export const DESCRIPTORS = [
  ['m89-d2-x2-plus-1.v2.json', 'algebra-component:m89-d2-x2-plus-1-v2'],
  ['m61-d3-x3-minus-5.v2.json', 'algebra-component:m61-d3-x3-minus-5-v2'],
  ['m31-d5-x5-plus-2x-minus-1.v2.json', 'algebra-component:m31-d5-x5-plus-2x-minus-1-v2'],
  ['m31-d6-x6-minus-5.v2.json', 'algebra-component:m31-d6-x6-minus-5-v2']
];
const EXPECTED_DESCRIPTOR_FILES = {
  'm89-d2-x2-plus-1.v2.json': ['1aec3bbc6de2af76b8a2199e1958dbb1b9a94142e4910f88239068a8055a5c52', 'e0bcc3d24a19e18e182acb13bde65dc22329eea18c0a0d0ae4002ef0e1b39b4c'],
  'm61-d3-x3-minus-5.v2.json': ['e844fed91918bc80f86e910f37e9e6d5946d3d93bf9b64fd56d77e79bd6147ad', '80127288a1d7d69163fb3ff0eb039b2c2543466610319a029a7afb87551027b6'],
  'm31-d5-x5-plus-2x-minus-1.v2.json': ['da37dee378f4354c0b024cff9c5335dd36b5bd13303b39893b34473423933af0', '009b6b147a8267ef9a01390c205b86ccb414ebdc7505dde7ca58b57bce8b985f'],
  'm31-d6-x6-minus-5.v2.json': ['74212333384b58d0841e9f8b7eff21c9c26235724228d66197089e8ffd2c8acc', 'e3091752aa9fec967b7bc20d454b9b77e9dbc8d36a154bd95900f781b5e89049']
};
const EXPECTED_SCHEDULE = ['b96da97b99bcf45f34b77ea66c0e44192533634f10a48af1c889b8d0e1fdb173', '099bfc6ea2b571829985f74d62e5138a948d977c7f00e2a2eec94e7d643fae6c'];
const EXPECTED_ARM_DIGESTS = new Map([
  ['arm:canonical:m89-d2-canonical-schoolbook-v1', '87a3895f1a72d57c4b602edbec0d43d4c37d85345f5d4d8cab8e544c9e68d3de'], ['arm:optimized:m89-d2-karatsuba-special-square-v1', '1f21fe3af6927d459e662befd097479352b500d40a6c7933721192ad603b78dd'],
  ['arm:canonical:m61-d3-canonical-schoolbook-v1', 'ed700b61307c2e15267fc9e93bbe37958e3b46190cf2c7253c248a5b3b556a10'], ['arm:optimized:m61-d3-pairwise-d3-v1', '60cfe4f0458a869ee9d885626ecd71d0277b255d92dd88b5beb86c3c29a5501a'], ['arm:optimized:m61-d3-toom3-v1', 'fea84b54a11543f967567537b4b0a38ffcee14c1e2869310f484c182cfc2b991'],
  ['arm:canonical:m31-d5-canonical-schoolbook-v1', '83b4619ee1296cf4ba893ab0103146b852e29d7df76ff460b1eb9a6790e638fe'], ['arm:optimized:m31-d5-pairwise-d5-v1', '3a901b9c146f44ed8c852245434914fdaa2239c167430c9b991a89e6d2e52fd1'], ['arm:optimized:m31-d5-toom5-v1', '4f36470d45ddd214385a4e3f7867d4bfc6d3a5ca9649f3ef74a26aa79a1af8c1'],
  ['arm:canonical:m31-d6-canonical-schoolbook-v1', 'd76d1ea2e12e23e6c4d5524c26af2b09a07acea33c561e14144fb71d5e77de99'], ['arm:optimized:m31-d6-pairwise-d6-v1', '1abb214f89f5153067cb4644e195116118c1a5d8b798b5ba30111661bbbc43c0'], ['arm:optimized:m31-d6-direct-toom6-v1', 'd02397f9986bbd77dcfb286385f2e6736a51304ea0eb0bdaacab83f400a1159d'], ['arm:optimized:m31-d6-tower2x3-six-product-r18-v1', '17c8d8c281b8ac80f25b6666b2e848e8b4b2e564ad8496d18bd7b891e1a8d19e'], ['arm:optimized:m31-d6-tower2x3-outer-toom3-v1', '90768e0c58c157113297e7f40c429e02f9a39ca64d9267d65298a801d7fcc4c0'], ['arm:optimized:m31-d6-tower3x2-quadratic-toom3-v1', 'a2efe763f25d39c1a3c8292db724c1f0041deb0106888b2749311c3686ff8701']
]);
const descriptorDir = 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors';
const descriptorPath = (file) => `${descriptorDir}/${file}`;
const legacyContextSchemas = [
  ['campaign-v1', 'research-lanes/bch-shielded-pool-design/p2/gate-b/equal-relation-arithmetic-campaign.v1.schema.json'],
  ['run-v1', 'research-lanes/bch-shielded-pool-design/p2/gate-b/equal-relation-arithmetic-run.v1.schema.json'],
  ['engine-result-v1', 'research-lanes/bch-shielded-pool-design/p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json'],
  ['metric-report-v1', 'research-lanes/bch-shielded-pool-design/p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json'],
  ['cross-engine-summary-v1', 'research-lanes/bch-shielded-pool-design/p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json']
];

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const canonicalize = (value) => {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
};
export const canonicalJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
export const contentDigestFor = (value) => {
  const copy = structuredClone(value);
  delete copy.contentDigest;
  return sha256(canonicalize(copy));
};
const fileBinding = (repoPath, extra = {}) => {
  const bytes = readFileSync(resolve(REPO, repoPath));
  return { path: repoPath, byteCount: bytes.length, sha256: sha256(bytes), ...extra };
};
const jsonBinding = (repoPath, extra = {}) => {
  const value = JSON.parse(readFileSync(resolve(REPO, repoPath), 'utf8'));
  return { ...fileBinding(repoPath, extra), contentDigest: value.contentDigest?.value ?? null, value };
};

const relationIds = ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'];
const relationDescriptions = {
  'relation:e-mac': 'eq(D,add(mul(A,B),C))',
  'relation:e-square-mac': 'eq(D,add(square(A),C))',
  'relation:e-inverse-check': 'and(ne(A,zero),eq(mul(A,H),one));never-compute-inverse'
};
const nullMetrics = Object.fromEntries([
  'verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct',
  'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax',
  'elementMax', 'limits', 'headroom'
].map((name) => [name, null]));
const metricStatuses = Object.fromEntries(Object.keys(nullMetrics).map((name) => [name, 'not-reached-execution-closed']));

const exactParserSteps = [
  'require-exact-extension-byte-length',
  'split-c0-to-cd-minus-1-fixed-width-limbs',
  'reject-unused-high-bits-before-one-byte-sign-guard-construction',
  'construct-one-byte-00-by-OP_1-OP_1-OP_XOR-then-raw-cat-and-bin2num-per-limb',
  'reject-unless-0<=coefficient<p',
  'require-full-consumption'
];
const sourceSlot = () => ({
  status: 'pending',
  pendingReason: 'execution-closed; source lowering has not been produced',
  sourceListing: null,
  sourceListingSha256: null,
  bytecodeHex: null,
  bytecodeSha256: null,
  buildManifest: null,
  command: null,
  compilerEnvironment: null,
  sourceMap: null,
  rangeLedger: null,
  loweringReport: null
});

export function generateLoweringFreeze() {
  const descriptorSchema = fileBinding(DESCRIPTOR_SCHEMA_PATH);
  const scheduleSchema = fileBinding(SCHEDULE_SCHEMA_PATH);
  const schedule = jsonBinding(SCHEDULE_PATH, { schemaPath: SCHEDULE_SCHEMA_PATH, schemaSha256: scheduleSchema.sha256 });
  if (descriptorSchema.sha256 !== 'b05a1e15567cd5f5fb0ff8e20206f6e4350dac4e7decf1560e637a64400e3374' || scheduleSchema.sha256 !== 'ce75be25b66c8663c4d1f71e98485713afe66454fb8e283bab468834df719f6a') throw new Error('upstream schema drift');
  if (schedule.sha256 !== EXPECTED_SCHEDULE[0] || schedule.contentDigest !== EXPECTED_SCHEDULE[1]) throw new Error('schedule freeze drift');
  if (schedule.value.schema !== 'shieldkit-labs/p2/schedule-freeze/v1') throw new Error('unexpected schedule schema');
  const descriptorRecords = DESCRIPTORS.map(([file, expectedId], orderIndex) => {
    const path = descriptorPath(file);
    const parsed = jsonBinding(path, { schemaPath: DESCRIPTOR_SCHEMA_PATH, schemaSha256: descriptorSchema.sha256 });
    if (parsed.value.descriptorId !== expectedId) throw new Error(`descriptor identity drift: ${path}`);
    const expected = EXPECTED_DESCRIPTOR_FILES[file];
    if (!expected || parsed.sha256 !== expected[0] || parsed.contentDigest !== expected[1]) throw new Error(`descriptor bytes drift: ${path}`);
    const { value, ...binding } = parsed;
    const matching = schedule.value.fieldConstructions.find((c) => c.q === value.directQuotient.q && c.degree === value.directQuotient.degree && c.p === value.directQuotient.p);
    if (!matching) throw new Error(`descriptor construction drift: ${path}`);
    return { orderIndex, ...binding, descriptorId: value.descriptorId,
      constructionId: matching.constructionId, fieldSpecRef: matching.fieldSpecRef, descriptor: value };
  });
  const constructions = schedule.value.fieldConstructions.map((c, orderIndex) => ({
    orderIndex, constructionId: c.constructionId, fieldSpecRef: c.fieldSpecRef, q: c.q, degree: c.degree, p: c.p,
    definingPolynomialAscending: c.definingPolynomialAscending, codecId: c.codec.codecId
  }));
  const descriptorByConstruction = new Map(descriptorRecords.map((x) => [x.constructionId, x]));
  const arms = schedule.value.arms.map((arm, orderIndex) => {
    const descriptor = descriptorByConstruction.get(arm.constructionId);
    if (!descriptor) throw new Error(`arm has no descriptor: ${arm.armId}`);
    const binding = descriptor.descriptor.scheduleArmBindings.find((x) => x.armId === arm.armId);
    const armDigest = sha256(canonicalize(arm));
    if (!binding || binding.armDigest !== armDigest || EXPECTED_ARM_DIGESTS.get(arm.armId) !== armDigest) throw new Error(`arm digest drift: ${arm.armId}`);
    return {
      orderIndex, armId: arm.armId, constructionId: arm.constructionId, fieldSpecRef: arm.fieldSpecRef,
      codecId: arm.codecId, trackId: arm.trackId, algorithmId: arm.algorithmId, armDigest,
      formulaId: arm.formula.formulaId, formulaDigest: sha256(canonicalize(arm.formula)),
      formulaSchema: 'schedule-freeze.v1.formula-object', sourceLowering: sourceSlot(), metrics: structuredClone(nullMetrics), metricStatuses: structuredClone(metricStatuses)
    };
  });
  const relationTargets = [];
  for (const arm of arms) for (const relationId of relationIds) relationTargets.push({
    orderIndex: relationTargets.length, relationTargetId: `relation-target:${arm.armId}:${relationId}`,
    armId: arm.armId, constructionId: arm.constructionId, fieldSpecRef: arm.fieldSpecRef, codecId: arm.codecId,
    algorithmId: arm.algorithmId, relationId, relationFormula: relationDescriptions[relationId], status: 'pending-source-lowering',
    sourceLowering: sourceSlot(), metrics: structuredClone(nullMetrics), metricStatuses: structuredClone(metricStatuses)
  });
  const artifact = {
    schema: { id: 'shieldkit-labs/p2/lowering-freeze/v1', path: SCHEMA_PATH, fileSha256: fileBinding(SCHEMA_PATH).sha256 },
    artifactId: 'lowering-freeze:direct-arithmetic-pre-execution-v1',
    status: 'frozen-pre-execution-lowering-contract', evidenceClassification: 'not-evidence', selection: 'none', tupleRef: null,
    protocolBoundary: 'component-only',
    executionBoundary: {
      state: 'closed',
      executionAllowed: false,
      sourceImplementationAllowed: true,
      sourceImplementationScope: 'produce-content-addressed-source-and-bytecode-only-no-campaign-execution-or-metrics',
      metricsAllowed: false,
      requiredBeforeExecution: [
        'source-set-v1-content-binding',
        'campaign-v2-content-binding',
        'canonical-corpus-v2-content-binding',
        'execution-epoch-v2-content-binding'
      ]
    },
    boundaryProhibitions: [
      'does-not-establish-executable-source-or-bytecode', 'does-not-measure-cost-or-vm-limits',
      'does-not-select-an-arm-or-field', 'does-not-bind-campaign-or-run-instance',
      'no-exact-construction-result-may-eliminate-an-entire-p-family', 'no-field-family-elimination-or-protocol-conclusion'
    ],
    upstreamBindings: {
      descriptorSchema: descriptorSchema,
      scheduleSchema: scheduleSchema,
      schedule: { path: SCHEDULE_PATH, byteCount: schedule.byteCount, sha256: schedule.sha256, contentDigest: schedule.contentDigest, schemaPath: SCHEDULE_SCHEMA_PATH, schemaSha256: scheduleSchema.sha256, artifactId: schedule.value.artifactId },
      descriptors: descriptorRecords.map(({ descriptor, ...record }) => record),
      legacyContextSchemas: legacyContextSchemas.map(([id, path]) => ({
        id,
        role: 'legacy-context-only-not-a-v2-execution-binding',
        ...fileBinding(path)
      }))
    },
    downstreamBindings: {
      sourceSetV1: null,
      campaignV2: null,
      canonicalCorpusV2: null,
      executionEpochV2: null
    },
    constructionOrder: constructions,
    arms,
    relationTargets,
    relationTargetCount: relationTargets.length,
    codecParserContract: {
      wireBasis: 'direct-power-basis-only', towerPolicy: 'tower-internal-only-never-wire-or-codec', coefficientOrder: 'c0-to-cd-minus-1',
      parserBeforeArithmetic: true, parserSteps: exactParserSteps,
      signGuardConstruction: 'exact-one-byte-00-produced-by-OP_1-OP_1-OP_XOR-not-empty-OP_0',
      coefficientRange: 'reject-unless-0<=coefficient<p', fullConsumption: true,
      canonicalResidues: '0<=coefficient<p; unsigned fixed-width little-endian limbs',
      directOnlyRule: 'wire-and-codec-are-direct-power-basis; tower coordinates are internal schedule notation only'
    },
    stackAbi: {
      version: 'stack-abi:direct-extension-lowering-v1', representation: 'BCH Script stack with byte-vector and ScriptNum typed values',
      operandOrder: 'push-left-then-right; binary operator consumes-right-then-left; result occupies one stack slot',
      relationOperandOrder: { eMac: ['D', 'C', 'B', 'A'], eSquareMac: ['D', 'C', 'A'], eInverseCheck: ['H', 'A'] },
      coefficientOrder: 'decoded coefficients remain c0-to-cd-minus-1; no implicit reorder',
      parserBoundary: 'exact initial OP_DEPTH; decode and canonicality check before arithmetic; final clean primary stack=true and altstack empty', noImplicitReordering: true,
      altStackPolicy: 'OP_TOALTSTACK/OP_FROMALTSTACK only at declared parser/algorithm nodes; final altstack empty'
    },
    typedIR: {
      version: 'typed-ir:lowering-freeze-v1', scalarTypes: ['base-field-canonical', 'base-field-signed-lift', 'scriptnum', 'boolean', 'byte-vector'],
      extensionTypes: ['direct-extension-element', 'tower-internal-element'],
      operationTypes: ['push', 'decode-limb', 'normalize', 'range-check', 'add', 'sub', 'mul', 'square', 'scale', 'reduce', 'encode', 'compare', 'assert'],
      noImplicitCoercion: true, everyValueHasDeclaredType: true, towerWireBoundary: 'tower-internal-only'
    },
    normalizationPolicy: {
      canonicalResidue: '0<=x<p', signedLift: 'only at explicitly declared scalar/range-ledger boundary',
      normalizationBoundary: 'only declared reduction and encode boundaries', hostNormalization: 'prohibited', aliasAcceptance: 'no non-canonical aliases'
    },
    rangeLedgerPolicy: { requiredPerNode: true, fields: ['nodeId', 'type', 'inputRanges', 'outputRange', 'normalizationState', 'modulus', 'reason'], status: 'pending-source-lowering' },
    scalarLowering: { constants: 'explicit formula constants and canonical fixed inverse scalars only', division: 'OP_DIV-forbidden', inverse: 'fixed-canonical-inverse-scalar-multiplication-only', unknownScalars: 'must be explicit and bound before execution' },
    dagPolicy: { everyDeclaredNodeReachesOutput: true, commonSubexpressionElimination: 'forbidden', deadNodes: 'forbidden', optionalNodes: 'forbidden' },
    sourceListingFormat: { encoding: 'UTF-8', lineEnding: 'LF', serialization: 'exact source bytes; no pretty-print normalization', pathPolicy: 'repository-relative only' },
    bytecodeFormat: { encoding: 'lowercase-hex', lineEnding: 'LF', byteOrder: 'script-byte-order', completeArtifactRequired: true, sourceBindingRequired: true },
    bchScriptProvenance: {
      sourceCommit: '864c53ee34924cca6c6b6d96607ff2cedcdccf02', sourcePath: 'src/script/script.h',
      sourceFileSha256: 'fdd6f1326c72032b4eeb5cf6605b1153d47798e84f8a39a69a66d83a64fc52ed',
      opcodeFacts: { OP_1: '0x51', OP_16: '0x60', OP_TOALTSTACK: '0x6b', OP_FROMALTSTACK: '0x6c', OP_DEPTH: '0x74', OP_PICK: '0x79', OP_CAT: '0x7e', OP_NUM2BIN: '0x80', OP_BIN2NUM: '0x81', OP_XOR: '0x86', OP_EQUALVERIFY: '0x88', OP_DIV: '0x96', OP_MOD: '0x97', OP_NUMEQUALVERIFY: '0x9d' },
      rationale: 'OP_1 through OP_16 cover dedicated small-integer constants; K=16 is design rationale only, not a measured-cost or lower-bound claim',
      provenanceNote: 'opcode values are source-pinned facts; any lookup-table fallback is non-authoritative'
    },
    metrics: structuredClone(nullMetrics), metricStatuses: structuredClone(metricStatuses), metricPolicy: 'all metrics remain null until an execution epoch binds source-bytecode-corpus-toolchain-run',
    contentDigest: { algorithm: 'sha256-jcs-omit-contentDigest', value: null }
  };
  artifact.contentDigest.value = contentDigestFor(artifact);
  return artifact;
}

export function validateLoweringFreezeSemantics(artifact, { checkFiles = true } = {}) {
  const errors = [];
  const fail = (message) => errors.push(message);
  if (!artifact || artifact.artifactId !== 'lowering-freeze:direct-arithmetic-pre-execution-v1') fail('artifact identity');
  if (artifact.status !== 'frozen-pre-execution-lowering-contract' || artifact.evidenceClassification !== 'not-evidence' || artifact.selection !== 'none' || artifact.tupleRef !== null || artifact.protocolBoundary !== 'component-only') fail('boundary');
  if (artifact.executionBoundary?.state !== 'closed' || artifact.executionBoundary.executionAllowed !== false || artifact.executionBoundary.sourceImplementationAllowed !== true) fail('execution boundary');
  if (artifact.contentDigest?.value !== contentDigestFor(artifact)) fail('content digest');
  if (artifact.constructionOrder?.length !== 4 || artifact.arms?.length !== 14 || artifact.relationTargets?.length !== 42) fail('counts');
  if (artifact.relationTargetCount !== 42) fail('relation count');
  const expected = generateLoweringFreeze();
  if (canonicalize(artifact.constructionOrder) !== canonicalize(expected.constructionOrder)) fail('construction roster/order');
  if (canonicalize(artifact.arms.map(({ sourceLowering, metrics, metricStatuses, ...x }) => x)) !== canonicalize(expected.arms.map(({ sourceLowering, metrics, metricStatuses, ...x }) => x))) fail('arm roster/order/digest');
  if (canonicalize(artifact.relationTargets.map(({ sourceLowering, metrics, metricStatuses, ...x }) => x)) !== canonicalize(expected.relationTargets.map(({ sourceLowering, metrics, metricStatuses, ...x }) => x))) fail('relation roster/order');
  if (artifact.upstreamBindings.schedule?.path !== SCHEDULE_PATH || artifact.upstreamBindings.scheduleSchema?.path !== SCHEDULE_SCHEMA_PATH || artifact.upstreamBindings.descriptorSchema?.path !== DESCRIPTOR_SCHEMA_PATH) fail('upstream binding paths');
  if (artifact.codecParserContract?.parserSteps?.[3] !== 'construct-one-byte-00-by-OP_1-OP_1-OP_XOR-then-raw-cat-and-bin2num-per-limb') fail('codec micro-template');
  if (artifact.scalarLowering?.division !== 'OP_DIV-forbidden') fail('division policy');
  if (artifact.dagPolicy?.commonSubexpressionElimination !== 'forbidden' || artifact.dagPolicy?.deadNodes !== 'forbidden') fail('DAG policy');
  if (artifact.codecParserContract?.wireBasis !== 'direct-power-basis-only' || artifact.codecParserContract?.towerPolicy !== 'tower-internal-only-never-wire-or-codec') fail('wire/tower rule');
  for (let i = 0; i < (artifact.arms ?? []).length; i++) {
    const arm = artifact.arms[i];
    if (arm.orderIndex !== i || arm.sourceLowering?.status !== 'pending' || arm.sourceLowering?.sourceListing !== null || arm.sourceLowering?.bytecodeHex !== null) fail(`arm pending/order ${i}`);
    if (Object.values(arm.metrics ?? {}).some((v) => v !== null)) fail(`arm metrics ${i}`);
  }
  for (let i = 0; i < (artifact.relationTargets ?? []).length; i++) {
    const row = artifact.relationTargets[i];
    if (row.orderIndex !== i || row.status !== 'pending-source-lowering' || row.sourceLowering?.sourceListing !== null || Object.values(row.metrics ?? {}).some((v) => v !== null)) fail(`relation target ${i}`);
  }
  if (checkFiles) {
    const check = (binding) => { try { const b = readFileSync(resolve(REPO, binding.path)); if (b.length !== binding.byteCount || sha256(b) !== binding.sha256) fail(`input digest ${binding.path}`); } catch { fail(`input missing ${binding?.path}`); } };
    check(artifact.upstreamBindings.descriptorSchema); check(artifact.upstreamBindings.scheduleSchema); check(artifact.upstreamBindings.schedule);
    for (const d of artifact.upstreamBindings.descriptors ?? []) check(d);
    for (const s of artifact.upstreamBindings.legacyContextSchemas ?? []) check(s);
    if (artifact.schema.fileSha256 !== sha256(readFileSync(resolve(REPO, artifact.schema.path)))) fail('artifact schema digest');
    if (artifact.bchScriptProvenance.sourceFileSha256 !== 'fdd6f1326c72032b4eeb5cf6605b1153d47798e84f8a39a69a66d83a64fc52ed') fail('BCH source pin');
  }
  return errors;
}
