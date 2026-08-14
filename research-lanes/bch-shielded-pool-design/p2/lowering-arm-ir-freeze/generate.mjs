#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, lstatSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, normalize, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { generateArmSsa, validateArmSsaProgram } from './arm-ssa.mjs';
import {
  CANONICAL_RELATION_IDS,
  generatePhysicalPlans,
  validatePhysicalPlan
} from './physical-plan.mjs';

export const DIRECTORY = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(DIRECTORY, '../../../../');
export const ARTIFACT_RELATIVE_PATH = 'research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.json';
export const SCHEMA_PATH = 'research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/lowering-arm-ir-freeze.v1.schema.json';
export const ARTIFACT_PATH = resolve(REPO, ARTIFACT_RELATIVE_PATH);
export const MANIFEST_PATH = resolve(DIRECTORY, 'MANIFEST.json');
export const SHA256SUMS_PATH = resolve(DIRECTORY, 'SHA256SUMS');

const PACKAGE_PREFIX = 'research-lanes/bch-shielded-pool-design/p2/lowering-arm-ir-freeze/';
const BASE_COMMIT = '8e55004e6be0c76bb6aa8aba4d9edbadf2c767f0';
const BCHN_COMMIT = '864c53ee34924cca6c6b6d96607ff2cedcdccf02';
const BCHN_LOCAL_ROOT = '/home/toorik/Projects/BCH/bchn-src';
const BCHN_SCRIPT_PATH = 'src/script/script.h';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const DOMAIN_FRAME = 'utf8(domain)||00||canonical-json-utf8';

const canonicalValue = (value) => {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
};

export const canonicalJson = (value) => `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
export const domainHash = (domain, value) => sha256(Buffer.concat([
  Buffer.from(domain, 'utf8'),
  Buffer.from([0]),
  Buffer.from(canonicalJson(value), 'utf8')
]));
const clone = (value) => structuredClone(value);
const without = (value, key) => {
  const copy = clone(value);
  delete copy[key];
  return copy;
};
const packageDigest = (domain, value) => ({
  algorithm: 'sha256',
  canonicalization: CANONICALIZATION,
  domain,
  frame: DOMAIN_FRAME,
  value: domainHash(domain, value)
});
const upstreamDigest = (domain, value) => ({
  algorithm: 'sha256-upstream-canonical-json-v1',
  domain,
  value
});
const rawDigest = (bytes) => ({ algorithm: 'sha256', preimage: 'exact-file-bytes', value: sha256(bytes) });

const ROOT_DOMAIN = 'shieldkit-labs/p2/lowering-arm-ir-freeze/v1/root';
export const contentDigestFor = (value) => domainHash(ROOT_DOMAIN, without(value, 'contentDigest'));
const rowDigest = (kind, value) => packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/index/${kind}`, without(value, 'rowDigest'));

const repoPath = (path) => resolve(REPO, path);
const assertRelativePath = (path) => {
  if (typeof path !== 'string' || path.length === 0 || path.startsWith('/') || path.includes('\\') || normalize(path) !== path || path.split('/').includes('..')) {
    throw new Error(`non-canonical repository-relative path: ${String(path)}`);
  }
};

export const assertContainedPathWithoutSymlinks = (root, path) => {
  assertRelativePath(path);
  const absoluteRoot = resolve(root);
  if (lstatSync(absoluteRoot).isSymbolicLink()) throw new Error(`trusted root may not be a symlink: ${absoluteRoot}`);
  const absoluteTarget = resolve(absoluteRoot, path);
  const lexicalRelative = relative(absoluteRoot, absoluteTarget);
  if (lexicalRelative === '..' || lexicalRelative.startsWith(`..${sep}`) || resolve(absoluteTarget) !== absoluteTarget) {
    throw new Error(`path escapes trusted root: ${path}`);
  }
  let cursor = absoluteRoot;
  for (const component of path.split('/')) {
    cursor = resolve(cursor, component);
    if (lstatSync(cursor).isSymbolicLink()) throw new Error(`symlink component forbidden: ${path} at ${component}`);
  }
  const realRoot = realpathSync(absoluteRoot);
  const realTarget = realpathSync(absoluteTarget);
  const realRelative = relative(realRoot, realTarget);
  if (realRelative === '..' || realRelative.startsWith(`..${sep}`)) throw new Error(`real path escapes trusted root: ${path}`);
  return absoluteTarget;
};

const declaredContentDigest = (value, identity) => {
  const digest = value?.contentDigest;
  if (!digest) return null;
  if (typeof digest === 'string') return { algorithm: 'sha256-upstream-declared', domain: identity, value: digest };
  if (typeof digest?.value === 'string') return { algorithm: digest.algorithm ?? 'sha256-upstream-declared', domain: identity, value: digest.value };
  return null;
};

const filePin = (id, role, path, parsed = null) => {
  const absolute = assertContainedPathWithoutSymlinks(REPO, path);
  const bytes = readFileSync(absolute);
  return {
    id,
    role,
    path,
    byteCount: bytes.length,
    fileDigest: rawDigest(bytes),
    artifactIdentity: parsed?.artifactId ?? parsed?.descriptorId ?? parsed?.$id ?? null,
    contentDigest: declaredContentDigest(parsed, parsed?.artifactId ?? parsed?.descriptorId ?? id)
  };
};

const jsonPin = (id, role, path) => filePin(id, role, path, JSON.parse(readFileSync(repoPath(path), 'utf8')));

const UPSTREAM_FILES = Object.freeze([
  ['upstream:arm-ssa-module', 'frozen-authority-generator', `${PACKAGE_PREFIX}arm-ssa.mjs`, false],
  ['upstream:arm-ssa-tests', 'frozen-authority-test', `${PACKAGE_PREFIX}arm-ssa.test.mjs`, false],
  ['upstream:physical-plan-module', 'frozen-authority-generator', `${PACKAGE_PREFIX}physical-plan.mjs`, false],
  ['upstream:physical-plan-tests', 'frozen-authority-test', `${PACKAGE_PREFIX}physical-plan.test.mjs`, false],
  ['upstream:schedule-freeze', 'frozen-schedule-input', 'research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.v1.json', true],
  ['upstream:schedule-schema', 'frozen-schedule-schema', 'research-lanes/bch-shielded-pool-design/p2/schedule-freeze/schedule-freeze.v1.schema.json', true],
  ['upstream:lowering-freeze', 'frozen-lowering-input', 'research-lanes/bch-shielded-pool-design/p2/lowering-freeze/lowering-freeze.v1.json', true],
  ['upstream:lowering-schema', 'frozen-lowering-schema', 'research-lanes/bch-shielded-pool-design/p2/lowering-freeze/lowering-freeze.v1.schema.json', true],
  ['upstream:construction-freeze', 'frozen-construction-input', 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze.v1.json', true],
  ['upstream:construction-schema', 'frozen-construction-schema', 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze.v1.schema.json', true],
  ['upstream:construction-transcript', 'frozen-construction-transcript', 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze.normalized-transcript.v1.json', true],
  ['upstream:construction-transcript-schema', 'frozen-construction-transcript-schema', 'research-lanes/bch-shielded-pool-design/p2/construction-freeze/construction-freeze-normalized-transcript.v1.schema.json', true],
  ['upstream:descriptor-schema', 'frozen-descriptor-schema', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/algebra-component-descriptor.v2.schema.json', true],
  ['upstream:descriptor-m89-d2', 'frozen-construction-descriptor', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m89-d2-x2-plus-1.v2.json', true],
  ['upstream:descriptor-m61-d3', 'frozen-construction-descriptor', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m61-d3-x3-minus-5.v2.json', true],
  ['upstream:descriptor-m31-d5', 'frozen-construction-descriptor', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m31-d5-x5-plus-2x-minus-1.v2.json', true],
  ['upstream:descriptor-m31-d6', 'frozen-construction-descriptor', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m31-d6-x6-minus-5.v2.json', true]
]);

const IMPLEMENTATION_FILES = Object.freeze([
  ['implementation:generator', 'package-generator', `${PACKAGE_PREFIX}generate.mjs`, false],
  ['implementation:validator', 'package-validator', `${PACKAGE_PREFIX}validate.mjs`, false],
  ['implementation:schema', 'package-schema', SCHEMA_PATH, true],
  ['implementation:tests', 'package-tests', `${PACKAGE_PREFIX}lowering-arm-ir-freeze.test.mjs`, false],
  ['implementation:direct-extension-reference', 'arithmetic-reference', 'research-lanes/bch-shielded-pool-design/p2/reference/direct-extension.mjs', false],
  ['implementation:root-package', 'node-dependency-manifest', 'package.json', true],
  ['implementation:root-lockfile', 'node-dependency-lock', 'package-lock.json', true]
]);

const pins = (rows) => rows.map(([id, role, path, json]) => json ? jsonPin(id, role, path) : filePin(id, role, path));

const histogram = (entries, field, vocabulary) => Object.fromEntries(vocabulary.map((key) => [key, entries.filter((entry) => entry[field] === key).length]));
const moduleSummary = (module, orderIndex) => {
  const row = {
    orderIndex,
    moduleId: module.moduleId,
    moduleKind: module.moduleKind,
    constructionId: module.constructionId ?? null,
    codecId: module.codecId ?? null,
    relationTargetId: module.relationTargetId ?? null,
    templateModuleId: module.templateModuleId ?? null,
    parserModuleId: module.parserModuleId ?? null,
    degree: module.degree ?? null,
    armProgramKind: module.armProgramKind ?? null,
    instructionTemplateCount: Array.isArray(module.instructionTemplates) ? module.instructionTemplates.length : 0,
    primitiveCounts: Array.isArray(module.instructionTemplates)
      ? [...new Set(module.instructionTemplates.map((entry) => entry.primitive))].sort().map((primitive) => ({
        primitive,
        count: module.instructionTemplates.filter((entry) => entry.primitive === primitive).length
      }))
      : [],
    upstreamModuleDigest: upstreamDigest('upstream/physical-plan/module', module.contentDigest),
    moduleDigest: packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/module/${module.moduleId}`, module)
  };
  row.rowDigest = rowDigest('module', row);
  return row;
};

const rangeSummary = (program) => {
  const rows = program.rangeLedger;
  const mins = rows.map((row) => BigInt(row.outputRange.minInclusive));
  const maxes = rows.map((row) => BigInt(row.outputRange.maxInclusive));
  return {
    rowCount: rows.length,
    digest: packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/range/${program.programId}`, rows),
    minimumInclusive: String(mins.reduce((a, b) => a < b ? a : b)),
    maximumInclusive: String(maxes.reduce((a, b) => a > b ? a : b)),
    canonicalNodeCount: rows.filter((row) => row.normalizationState === 'canonical-mod-p').length
  };
};

const programSummary = (arm, program, orderIndex) => {
  const row = {
    orderIndex,
    programId: program.programId,
    armId: arm.armId,
    constructionId: arm.constructionId,
    kind: program.kind,
    modulus: program.modulus,
    degree: program.degree,
    inputCount: program.inputs.length,
    outputCount: program.outputs.length,
    nodeCount: program.nodes.length,
    nodeOpCounts: histogram(program.nodes, 'op', ['add', 'mul', 'reduce', 'scale', 'square', 'sub']),
    variableBaseCounts: clone(program.variableBaseCounts),
    rangeLedger: rangeSummary(program),
    formulaOccurrenceCount: program.formulaOccurrences.length,
    matrixOccurrenceCount: program.matrixOccurrences.length,
    mapOccurrenceCount: program.mapOccurrences.length,
    directReductionDisposition: clone(program.directReductionDisposition),
    upstreamProgramDigest: upstreamDigest('upstream/arm-ssa/program', program.programDigest),
    programDigest: packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/program/${program.programId}`, program)
  };
  row.rowDigest = rowDigest('program', row);
  return row;
};

const terminalSummary = (terminal) => ({
  primary: terminal.primary.map(({ valueId, type, value }) => ({ valueId, type, value })),
  alt: terminal.alt.map(({ valueId, type, value }) => ({ valueId, type, value }))
});

const planSummary = (plan, orderIndex) => {
  const row = {
    orderIndex,
    planId: plan.planId,
    relationTargetId: plan.relationTargetId,
    constructionId: plan.constructionId,
    programId: plan.upstreamBinding.programId,
    parserModuleId: plan.parserModuleId,
    wrapperInstanceModuleId: plan.wrapperBinding.wrapperInstanceModuleId,
    parserInvocations: plan.parserInvocations.map((invocation) => ({
      invocationKey: `${plan.planId}#${invocation.invocationId}`,
      invocationId: invocation.invocationId,
      parserModuleId: invocation.parserModuleId,
      rawRole: invocation.rawRole,
      rawValueId: invocation.rawValueId,
      outputPrefix: invocation.outputPrefix,
      parseIndex: invocation.parseIndex
    })),
    parserInvocationCount: plan.parserInvocations.length,
    instructionCount: plan.instructions.length,
    traceRowCount: plan.simulation.trace.length,
    initialPrimaryItems: plan.initialStack.primary.length,
    initialAltItems: plan.initialStack.alt.length,
    terminal: terminalSummary(plan.simulation.terminal),
    maxPrimaryDepth: plan.simulation.maxPrimaryDepth,
    maxAltDepth: plan.simulation.maxAltDepth,
    maxCombinedDepth: plan.simulation.maxCombinedDepth,
    upstreamPlanDigest: upstreamDigest('upstream/physical-plan/plan', plan.contentDigest),
    planDigest: packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/plan/${plan.planId}`, plan),
    instructionDigest: packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/instructions/${plan.planId}`, plan.instructions),
    traceDigest: packageDigest(`shieldkit-labs/p2/lowering-arm-ir-freeze/v1/trace/${plan.planId}`, plan.simulation.trace)
  };
  row.rowDigest = rowDigest('plan', row);
  return row;
};

const deriveCardinalities = (arms, physical) => {
  const programs = arms.flatMap((arm) => [arm.programs.multiply, arm.programs.square]);
  const plans = physical.plans;
  const nodeOps = Object.fromEntries(['add', 'mul', 'reduce', 'scale', 'square', 'sub'].map((op) => [op, programs.reduce((sum, program) => sum + program.nodes.filter((node) => node.op === op).length, 0)]));
  return {
    constructions: new Set(arms.map((arm) => arm.constructionId)).size,
    arms: arms.length,
    programs: programs.length,
    ssaNodes: programs.reduce((sum, program) => sum + program.nodes.length, 0),
    rangeLedgerRows: programs.reduce((sum, program) => sum + program.rangeLedger.length, 0),
    multiplyProgramNodes: programs.filter((program) => program.kind === 'multiply').reduce((sum, program) => sum + program.nodes.length, 0),
    squareProgramNodes: programs.filter((program) => program.kind === 'square').reduce((sum, program) => sum + program.nodes.length, 0),
    programInputs: programs.reduce((sum, program) => sum + program.inputs.length, 0),
    programOutputs: programs.reduce((sum, program) => sum + program.outputs.length, 0),
    formulaOccurrenceRows: programs.reduce((sum, program) => sum + program.formulaOccurrences.length, 0),
    matrixOccurrenceRows: programs.reduce((sum, program) => sum + program.matrixOccurrences.length, 0),
    mapOccurrenceRows: programs.reduce((sum, program) => sum + program.mapOccurrences.length, 0),
    nodeOps,
    multiplyKindVariableBaseOps: programs.filter((program) => program.kind === 'multiply').reduce((sum, program) => sum + program.variableBaseCounts.actual, 0),
    squareKindVariableBaseOps: programs.filter((program) => program.kind === 'square').reduce((sum, program) => sum + program.variableBaseCounts.actual, 0),
    physicalRelationPlanOccurrences: plans.reduce((sum, plan) => sum + plan.ssaProgram.variableBaseCounts.actual, 0),
    parserModules: physical.parserModules.length,
    wrapperTemplates: physical.wrapperTemplates.length,
    wrapperInstances: physical.wrapperInstances.length,
    physicalPlans: plans.length,
    parserInvocations: plans.reduce((sum, plan) => sum + plan.parserInvocations.length, 0),
    instructions: plans.reduce((sum, plan) => sum + plan.instructions.length, 0),
    storedTraceRows: plans.reduce((sum, plan) => sum + plan.simulation.trace.length, 0),
    initialPrimaryItems: plans.reduce((sum, plan) => sum + plan.initialStack.primary.length, 0),
    initialAltItems: plans.reduce((sum, plan) => sum + plan.initialStack.alt.length, 0),
    terminalBoolItems: plans.reduce((sum, plan) => sum + plan.simulation.terminal.primary.filter((item) => item.type === 'Bool').length, 0),
    terminalAltItems: plans.reduce((sum, plan) => sum + plan.simulation.terminal.alt.length, 0),
    maxPrimaryDepth: Math.max(...plans.map((plan) => plan.simulation.maxPrimaryDepth)),
    maxAltDepth: Math.max(...plans.map((plan) => plan.simulation.maxAltDepth)),
    maxCombinedDepth: Math.max(...plans.map((plan) => plan.simulation.maxCombinedDepth))
  };
};

export const EXPECTED_CARDINALITIES = Object.freeze({
  constructions: 4, arms: 14, programs: 28, ssaNodes: 4806, rangeLedgerRows: 4806,
  multiplyProgramNodes: 2648, squareProgramNodes: 2158, programInputs: 192, programOutputs: 128,
  formulaOccurrenceRows: 528, matrixOccurrenceRows: 628, mapOccurrenceRows: 90,
  nodeOps: { add: 996, mul: 297, reduce: 2403, scale: 748, square: 41, sub: 321 },
  multiplyKindVariableBaseOps: 192, squareKindVariableBaseOps: 146, physicalRelationPlanOccurrences: 530,
  parserModules: 4, wrapperTemplates: 3, wrapperInstances: 12, physicalPlans: 42,
  parserInvocations: 126, instructions: 25098, storedTraceRows: 25098,
  initialPrimaryItems: 126, initialAltItems: 0, terminalBoolItems: 42, terminalAltItems: 0,
  maxPrimaryDepth: 392, maxAltDepth: 24, maxCombinedDepth: 392
});

const assertAuthority = (arms, physical) => {
  for (const arm of arms) {
    for (const program of Object.values(arm.programs)) {
      const errors = validateArmSsaProgram(program);
      if (errors.length) throw new Error(`SSA authority failed ${program.programId}: ${errors.join('; ')}`);
    }
  }
  for (const plan of physical.plans) {
    const errors = validatePhysicalPlan(plan, { strictAuthority: true });
    if (errors.length) throw new Error(`physical authority failed ${plan.planId}: ${errors.join('; ')}`);
  }
};

export function generatePackage() {
  const bchnHead = execFileSync('git', ['-C', BCHN_LOCAL_ROOT, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  if (bchnHead !== BCHN_COMMIT) throw new Error(`BCHN opcode authority commit drift: ${bchnHead}`);
  const bchnScriptPath = assertContainedPathWithoutSymlinks(BCHN_LOCAL_ROOT, BCHN_SCRIPT_PATH);
  const arms = generateArmSsa();
  const physical = generatePhysicalPlans();
  assertAuthority(arms, physical);
  const cardinalities = deriveCardinalities(arms, physical);
  if (canonicalJson(cardinalities) !== canonicalJson(EXPECTED_CARDINALITIES)) throw new Error(`authority cardinality drift: ${canonicalJson(cardinalities)}`);

  const constructionOrder = [...new Set(arms.map((arm) => arm.constructionId))];
  const armOrder = arms.map((arm) => arm.armId);
  const programs = arms.flatMap((arm) => [arm.programs.multiply, arm.programs.square]);
  const modules = [...physical.parserModules, ...physical.wrapperTemplates, ...physical.wrapperInstances];
  const programIndex = arms.flatMap((arm) => [arm.programs.multiply, arm.programs.square]).map((program, orderIndex) => {
    const arm = arms.find((candidate) => candidate.armId === program.programId.split(':multiply:')[0] || candidate.armId === program.programId.split(':square:')[0]);
    return programSummary(arm, program, orderIndex);
  });
  const moduleIndex = modules.map(moduleSummary);
  const planIndex = physical.plans.map(planSummary);

  const artifact = {
    schema: {
      id: 'shieldkit-labs/p2/lowering-arm-ir-freeze/v1',
      path: SCHEMA_PATH,
      fileDigest: rawDigest(readFileSync(repoPath(SCHEMA_PATH)))
    },
    artifactId: 'lowering-arm-ir-freeze:direct-arithmetic-symbolic-stack-v1',
    status: 'frozen-host-validated-pre-source-ir',
    evidenceClassification: 'not-execution-evidence',
    selection: 'none',
    tupleRef: null,
    protocolBoundary: 'component-only',
    executionBoundary: {
      packageValidationRequired: true,
      sourceEmissionAllowed: false,
      bytecodeEmissionAllowed: false,
      vmExecutionAllowed: false,
      metricsAllowed: false
    },
    digestAlgorithms: {
      rawFile: { algorithm: 'sha256', preimage: 'exact-file-bytes' },
      packageObject: { algorithm: 'sha256', canonicalization: CANONICALIZATION, frame: DOMAIN_FRAME },
      upstreamAuthority: { algorithm: 'sha256-upstream-canonical-json-v1', note: 'opaque upstream identity; package roots are independently domain-separated' }
    },
    upstreamBindings: {
      files: pins(UPSTREAM_FILES),
      externalAuthorities: [{
        id: 'bchn:opcode-authority',
        repository: 'Bitcoin-Cash-Node',
        commit: BCHN_COMMIT,
        path: BCHN_SCRIPT_PATH,
        byteCount: readFileSync(bchnScriptPath).length,
        fileDigest: rawDigest(readFileSync(bchnScriptPath))
      }]
    },
    implementationBindings: {
      runtime: { runtime: 'node', version: process.version, platform: process.platform, arch: process.arch },
      repositorySnapshot: {
        baseCommit: BASE_COMMIT,
        sourceState: 'dirty-untracked-working-tree',
        authorityPathState: 'untracked',
        note: 'raw file digests are authoritative; baseCommit is provenance and intentionally not current-HEAD validation'
      },
      files: pins(IMPLEMENTATION_FILES)
    },
    constructionOrder,
    programIndex,
    moduleIndex,
    planIndex,
    cardinalities,
    validationContract: {
      verdict: 'pass',
      armOrder,
      programOrder: 'arm-major-then-multiply-square',
      moduleOrder: 'parser-modules-then-wrapper-templates-then-wrapper-instances',
      relationOrder: [...CANONICAL_RELATION_IDS],
      planOrder: 'arm-major-then-canonical-relation-order',
      parserInvocationIdentity: '(planId,invocationId)',
      completeAuthorityDigests: {
        arms: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/authority/arms', arms),
        programs: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/authority/programs', programs),
        modules: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/authority/modules', modules),
        plans: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/authority/plans', physical.plans)
      },
      compactIndexDigests: {
        programs: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/compact/program-index', programIndex),
        modules: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/compact/module-index', moduleIndex),
        plans: packageDigest('shieldkit-labs/p2/lowering-arm-ir-freeze/v1/compact/plan-index', planIndex)
      },
      sourceEmissionGate: 'a consumer must validate this exact artifact and refuse missing, stale, unknown, or non-pass package digests'
    },
    downstreamBindings: {
      sourceSetV1: null,
      campaignV2: null,
      canonicalCorpusV2: null,
      executionEpochV2: null
    },
    nonClaims: [
      'not BCH source or bytecode and not a BCH-VM-exact stack proof',
      'not Libauth, BCHN, LeanBCH, corpus, campaign, or benchmark execution evidence',
      'no byte size, operation cost, standardness, consensus-limit, proof-size, transaction-fit, or prover-time result',
      'no construction ranking, field selection, Circle-domain selection, query selection, protocol selection, or promotion',
      'no soundness, zero-knowledge, post-quantum, full-transaction, or release qualification claim'
    ],
    contentDigest: null
  };
  artifact.contentDigest = packageDigest(ROOT_DOMAIN, without(artifact, 'contentDigest'));
  return artifact;
}

const PACKAGE_FILES = Object.freeze([
  'README.md', 'COMMAND.txt', 'arm-ssa.mjs', 'arm-ssa.test.mjs', 'physical-plan.mjs', 'physical-plan.test.mjs',
  'generate.mjs', 'validate.mjs', 'lowering-arm-ir-freeze.test.mjs', 'lowering-arm-ir-freeze.v1.schema.json', 'lowering-arm-ir-freeze.v1.json'
]);

const packageBytes = (name, artifactBytes) => {
  const absolute = assertContainedPathWithoutSymlinks(DIRECTORY, name);
  const bytes = name === 'lowering-arm-ir-freeze.v1.json' ? artifactBytes : readFileSync(absolute);
  if (bytes.includes(0x0d)) throw new Error(`package payload contains CR bytes: ${name}`);
  return bytes;
};
export const manifestFor = (artifactBytes) => ({
  schema: 'shieldkit-labs/p2/lowering-arm-ir-freeze/raw-manifest/v1',
  files: PACKAGE_FILES.map((path, orderIndex) => {
    const bytes = packageBytes(path, artifactBytes);
    return { orderIndex, path, byteCount: bytes.length, fileDigest: rawDigest(bytes) };
  })
});
export const sha256SumsFor = (artifactBytes, manifestBytes) => `${[
  ...PACKAGE_FILES.map((name) => `${sha256(packageBytes(name, artifactBytes))}  ${name}`),
  `${sha256(manifestBytes)}  MANIFEST.json`
].join('\n')}\n`;

const checkPin = (pin, errors) => {
  try {
    const absolute = assertContainedPathWithoutSymlinks(REPO, pin.path);
    const bytes = readFileSync(absolute);
    if (bytes.length !== pin.byteCount) errors.push(`byte count mismatch: ${pin.path}`);
    if (sha256(bytes) !== pin.fileDigest?.value) errors.push(`file digest mismatch: ${pin.path}`);
  } catch (error) {
    errors.push(`file pin invalid ${pin?.path}: ${error.message}`);
  }
};

export function validatePackageSemantics(artifact, { checkFiles = true, expected = null } = {}) {
  const errors = [];
  const fail = (message) => errors.push(message);
  if (!artifact || artifact.artifactId !== 'lowering-arm-ir-freeze:direct-arithmetic-symbolic-stack-v1') fail('artifact identity');
  if (artifact?.status !== 'frozen-host-validated-pre-source-ir' || artifact?.evidenceClassification !== 'not-execution-evidence') fail('status/evidence boundary');
  if (artifact?.selection !== 'none' || artifact?.tupleRef !== null || artifact?.protocolBoundary !== 'component-only') fail('selection/protocol boundary');
  if (artifact?.contentDigest?.value !== contentDigestFor(artifact) || artifact?.contentDigest?.domain !== ROOT_DOMAIN) fail('content digest');
  expected ??= generatePackage();
  if (canonicalJson(artifact) !== canonicalJson(expected)) fail('deterministic regeneration mismatch');

  const allPins = [...(artifact?.upstreamBindings?.files ?? []), ...(artifact?.implementationBindings?.files ?? [])];
  const paths = allPins.map((pin) => pin.path);
  if (new Set(paths).size !== paths.length) fail('duplicate file pin path');
  const ids = allPins.map((pin) => pin.id);
  if (new Set(ids).size !== ids.length) fail('duplicate file pin id');
  if (checkFiles) allPins.forEach((pin) => checkPin(pin, errors));

  const programIds = artifact?.programIndex?.map((row) => row.programId) ?? [];
  const moduleIds = artifact?.moduleIndex?.map((row) => row.moduleId) ?? [];
  const planIds = artifact?.planIndex?.map((row) => row.planId) ?? [];
  if (new Set(programIds).size !== 28 || new Set(moduleIds).size !== 19 || new Set(planIds).size !== 42) fail('index identity uniqueness');
  const invocations = (artifact?.planIndex ?? []).flatMap((plan) => plan.parserInvocations ?? []);
  if (new Set(invocations.map((row) => row.invocationKey)).size !== 126) fail('composite parser invocation identity');
  if (new Set(invocations.map((row) => row.invocationId)).size >= 126) fail('bare parser invocation IDs unexpectedly global');
  if (canonicalJson(artifact?.cardinalities) !== canonicalJson(EXPECTED_CARDINALITIES)) fail('cardinality contract');
  if ((artifact?.planIndex ?? []).some((row) => row.terminal.primary.length !== 1 || row.terminal.primary[0].type !== 'Bool' || row.terminal.primary[0].value !== 'true' || row.terminal.alt.length !== 0)) fail('terminal contract');

  if (checkFiles) {
    const artifactBytes = Buffer.from(canonicalJson(artifact), 'utf8');
    if (!artifactBytes.equals(readFileSync(ARTIFACT_PATH))) fail('artifact file is not canonical regenerated bytes');
    assertContainedPathWithoutSymlinks(DIRECTORY, 'MANIFEST.json');
    assertContainedPathWithoutSymlinks(DIRECTORY, 'SHA256SUMS');
    const manifestBytes = Buffer.from(canonicalJson(manifestFor(artifactBytes)), 'utf8');
    if (!manifestBytes.equals(readFileSync(MANIFEST_PATH))) fail('MANIFEST.json mismatch');
    if (readFileSync(SHA256SUMS_PATH, 'utf8') !== sha256SumsFor(artifactBytes, manifestBytes)) fail('SHA256SUMS mismatch');
  }
  return errors;
}

export function assertKnownPassingPackageDigest(artifact, expectedContentDigest) {
  if (typeof expectedContentDigest !== 'string' || !/^[0-9a-f]{64}$/.test(expectedContentDigest)) {
    throw new Error('emitter refused missing or unknown package digest');
  }
  if (artifact?.validationContract?.verdict !== 'pass') throw new Error('emitter refused non-pass package verdict');
  if (artifact?.contentDigest?.value !== expectedContentDigest) throw new Error('emitter refused stale package digest');
  const errors = validatePackageSemantics(artifact);
  if (errors.length) throw new Error(`emitter refused invalid package: ${errors.join('; ')}`);
  return true;
}

export function writePackage() {
  for (const output of ['lowering-arm-ir-freeze.v1.json', 'MANIFEST.json', 'SHA256SUMS']) {
    if (existsSync(resolve(DIRECTORY, output))) assertContainedPathWithoutSymlinks(DIRECTORY, output);
  }
  const artifact = generatePackage();
  const artifactBytes = Buffer.from(canonicalJson(artifact), 'utf8');
  const manifestBytes = Buffer.from(canonicalJson(manifestFor(artifactBytes)), 'utf8');
  writeFileSync(ARTIFACT_PATH, artifactBytes);
  writeFileSync(MANIFEST_PATH, manifestBytes);
  writeFileSync(SHA256SUMS_PATH, sha256SumsFor(artifactBytes, manifestBytes), 'utf8');
  return { artifact, artifactBytes, manifestBytes };
}

const isMain = process.argv[1] && (
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  || process.argv[1].replaceAll('\\', '/').endsWith('/lowering-arm-ir-freeze/generate.mjs')
  || process.argv[1].replaceAll('\\', '/') === `${PACKAGE_PREFIX}generate.mjs`
);
if (isMain) {
  if (process.argv.includes('--write')) {
    const { artifact, artifactBytes } = writePackage();
    process.stdout.write(`WROTE ${ARTIFACT_RELATIVE_PATH}\nBYTES ${artifactBytes.length}\nSHA256 ${sha256(artifactBytes)}\nCONTENT_DIGEST ${artifact.contentDigest.value}\n`);
  } else {
    const artifact = JSON.parse(readFileSync(ARTIFACT_PATH, 'utf8'));
    const errors = validatePackageSemantics(artifact);
    if (errors.length) throw new Error(errors.join('; '));
    process.stdout.write(`OK ${ARTIFACT_RELATIVE_PATH}\nSHA256 ${sha256(readFileSync(ARTIFACT_PATH))}\nCONTENT_DIGEST ${artifact.contentDigest.value}\n`);
  }
}
