/**
 * Frozen-epoch execution adapters.
 *
 * This is intentionally a serializer/parser and host-reference library. It
 * never spawns a process at import time (or anywhere in this module), writes
 * no evidence, and does not turn this component fixture into a transaction
 * admission claim. A future, separately-authorized evidence writer must
 * re-check the frozen authority before calling an engine.
 */

import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  FIXTURE_ARTIFACT_ID,
  REPOSITORY_ROOT,
  assertContainedRegularFile,
  deriveExecutionFixture,
  hex as bytesToHex,
  loadSourceSetPlan,
  parseLowercaseEvenHex,
  sha256,
} from '../cohort-freeze-v2/execution-fixture.mjs';
import { buildFixtureRoster, validateFixtureRoster } from '../cohort-freeze-v2/fixture-roster.mjs';
import { ENGINE_ORDER, canonicalJson } from '../cohort-freeze-v2/epoch.mjs';
import { createDirectExtension } from '../../reference/direct-extension.mjs';
import { decodeTransaction, decodeTransactionOutputs } from '../../../../../node_modules/@bitauth/libauth/build/lib/message/transaction-encoding.js';
import { createVirtualMachineBch2026 } from '../../../../../node_modules/@bitauth/libauth/build/lib/vm/instruction-sets/bch/2026/bch-2026-vm.js';

const here = dirname(fileURLToPath(import.meta.url));
export const COHORT_FREEZE_DIRECTORY = resolve(here, '../cohort-freeze-v2');
export const ADAPTER_SCOPE = 'synthetic-one-input-one-output-p2sh32-component-only';
export const TX_CHECKS_UNSUPPORTED = 'unsupported-for-component-only-script-engine-boundary';
export const PREFLIGHT_TERMINAL_STATUS = 'explicit-unsupported-preflight-limit';
export const LEAN_INCOMPLETE_TERMINAL_STATUS = 'explicit-unsupported-incomplete-lean-costprobe';
export const READY_FIXTURE_STATUS = 'preflight-ready-no-vm-execution';
export const LIMIT_FIXTURE_STATUS = 'preflight-limit-violation';
export const FROZEN_COUNTS = Object.freeze({
  fixtures: 4732,
  readyFixtures: 4608,
  preflightLimitFixtures: 124,
  workItems: 18928,
  preflightLimitWorkItems: 496,
});

const COHORT_PATHS = Object.freeze({
  sourceSet: 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json',
  corpus: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json',
  fixtureRoster: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/fixture-roster.v2.json',
  workItemRoster: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/work-item-roster.v2.json',
  epoch: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json',
  engines: Object.freeze({
    'engine:native': 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/native.v2.json',
    'engine:libauth': 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/libauth.v2.json',
    'engine:bchn': 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/bchn.v2.json',
    'engine:leanbch': 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/leanbch.v2.json',
  }),
});

const DESCRIPTORS = Object.freeze({
  'algebra-component:m89-d2-x2-plus-1-v2': 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m89-d2-x2-plus-1.v2.json',
  'algebra-component:m61-d3-x3-minus-5-v2': 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m61-d3-x3-minus-5.v2.json',
  'algebra-component:m31-d5-x5-plus-2x-minus-1-v2': 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m31-d5-x5-plus-2x-minus-1.v2.json',
  'algebra-component:m31-d6-x6-minus-5-v2': 'research-lanes/bch-shielded-pool-design/p2/algebra-component/descriptors/m31-d6-x6-minus-5.v2.json',
});

const RELATION_OPERAND_NAMES = Object.freeze({
  'relation:e-mac': Object.freeze(['D', 'C', 'B', 'A']),
  'relation:e-square-mac': Object.freeze(['D', 'C', 'A']),
  'relation:e-inverse-check': Object.freeze(['H', 'A']),
});
const ALLOWED_BCHN_PHASES = new Set(['ok', 'execute', 'tx_decode', 'utxo_decode', 'malformed_vector', 'exception']);
const BCHN_EFFECT_KEYS = Object.freeze([
  'ident', 'outcome', 'error_class', 'native_error', 'phase', 'op_cost', 'op_cost_limit',
  'hash_iters', 'hash_iters_limit', 'sig_checks', 'sig_checks_limit', 'tx_checks', 'stack_hash',
]);
const SAFE_TOKEN = /^[^\s\u0000-\u001f]+$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

const require = (condition, message) => {
  if (!condition) throw new TypeError(`cohort execution adapter: ${message}`);
};
const exactKeys = (value, keys, label) => require(
  value !== null && typeof value === 'object' && !Array.isArray(value)
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort()),
  `${label} shape drift`,
);
const canonicalEqual = (left, right) => canonicalJson(left) === canonicalJson(right);
const lowerHex = (value, label) => {
  require(typeof value === 'string' && /^[0-9a-f]*$/u.test(value) && value.length % 2 === 0, `${label} must be lowercase even hex`);
  return value;
};
const integer = (value, label) => {
  require(Number.isSafeInteger(value) && value >= 0, `${label} must be a nonnegative safe integer`);
  return value;
};
const nullableInteger = (value, label) => {
  if (value === null) return null;
  return integer(value, label);
};
const immutable = (value) => Object.freeze(value);

const readFrozenJson = (relativePath) => {
  const path = assertContainedRegularFile(REPOSITORY_ROOT, relativePath);
  const bytes = readFileSync(path);
  require(bytes.length > 0 && bytes[bytes.length - 1] === 0x0a, `${relativePath} must end in LF`);
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new TypeError(`cohort execution adapter: invalid JSON ${relativePath}: ${error.message}`);
  }
};

/** Read the frozen inputs only; this does not regenerate fixtures or invoke an engine. */
export const loadFrozenEpochArtifacts = () => {
  const engines = Object.fromEntries(ENGINE_ORDER.map((engineId) => [engineId, readFrozenJson(COHORT_PATHS.engines[engineId])]));
  return immutable({
    sourceSet: readFrozenJson(COHORT_PATHS.sourceSet),
    corpus: readFrozenJson(COHORT_PATHS.corpus),
    fixtureRoster: readFrozenJson(COHORT_PATHS.fixtureRoster),
    workItemRoster: readFrozenJson(COHORT_PATHS.workItemRoster),
    epoch: readFrozenJson(COHORT_PATHS.epoch),
    engines: immutable(engines),
  });
};

const contentDigestValue = (value) => value?.value ?? value;
const fixtureIdentityEqual = (left, right) => canonicalEqual(left, right);
const caseDigest = (caseEntry) => contentDigestValue(caseEntry.caseDigest);

const assertFrozenArtifactShape = (artifacts) => {
  require(artifacts !== null && typeof artifacts === 'object', 'artifacts required');
  const { sourceSet, corpus, fixtureRoster, workItemRoster, epoch, engines } = artifacts;
  require(sourceSet?.planIndex?.length === 42, 'source-set must retain exactly 42 plans');
  require(corpus?.counts?.total === 1288 && Array.isArray(corpus.constructions) && corpus.constructions.length === 4, 'corpus cardinality drift');
  require(fixtureRoster?.records?.length === FROZEN_COUNTS.fixtures, 'fixture roster cardinality drift');
  require(workItemRoster?.workItems?.length === FROZEN_COUNTS.workItems, 'work roster cardinality drift');
  require(epoch?.status === 'frozen-contract-only-unexecuted' && epoch.execution === null && epoch.result === null && epoch.metric === null && epoch.ranking === null && epoch.selection === null, 'epoch execution boundary drift');
  require(fixtureRoster.executionAllowed === false && fixtureRoster.metricsAllowed === false && fixtureRoster.ranking === null && fixtureRoster.selection === null, 'fixture roster execution boundary drift');
  require(workItemRoster.executionAllowed === false && workItemRoster.metricsAllowed === false && workItemRoster.ranking === null && workItemRoster.selection === null, 'work roster execution boundary drift');
  require(engines !== null && typeof engines === 'object', 'engine records required');
  for (const engineId of ENGINE_ORDER) {
    const engine = engines[engineId];
    require(engine?.engineId === engineId && engine.executionAllowed === false && engine.selection === null, `${engineId} execution boundary drift`);
  }
  return true;
};

const flattenCorpusCases = (corpus) => corpus.constructions.flatMap((construction) => construction.cases);
const identityForCasePlan = (caseEntry, planId) => ({
  constructionIndex: caseEntry.constructionIndex,
  constructionId: caseEntry.constructionId,
  planId,
  caseKey: caseEntry.caseKey,
  caseDigest: caseDigest(caseEntry),
  vectorAttempt: caseEntry.vectorAttempt,
});

const findCorpusCase = (corpus, identity) => {
  const found = flattenCorpusCases(corpus).find((caseEntry) => (
    caseEntry.constructionIndex === identity.constructionIndex
      && caseEntry.constructionId === identity.constructionId
      && caseEntry.caseKey === identity.caseKey
      && caseDigest(caseEntry) === identity.caseDigest
      && caseEntry.vectorAttempt === identity.vectorAttempt
  ));
  require(found !== undefined, `missing frozen corpus case ${identity.caseKey}`);
  return found;
};

const assertRecordShape = (record) => {
  require(record?.artifactId === FIXTURE_ARTIFACT_ID, 'fixture artifact identity drift');
  require(typeof record.fixtureKey === 'string' && /^fixture:[0-9a-f]{64}$/u.test(record.fixtureKey), 'fixture key drift');
  require(typeof record.planId === 'string' && typeof record.relationId === 'string', 'fixture plan/relation identity drift');
  require(record.epochIdentity?.planId === record.planId, 'fixture epoch identity plan drift');
  require(record.status === READY_FIXTURE_STATUS || record.status === LIMIT_FIXTURE_STATUS, 'fixture status drift');
  require(record.byteBindings !== null && typeof record.byteBindings === 'object', 'fixture byte bindings required');
  return record;
};

const assertByteBinding = (value, binding, label) => {
  require(value instanceof Uint8Array, `${label} bytes required`);
  require(binding !== null && typeof binding === 'object' && value.length === binding.byteLength && sha256(value) === binding.sha256, `${label} byte binding drift`);
};

/** Typed arrays remain mutable after their containing fixture is frozen: hash every emitted byte field. */
const assertFixtureByteBindings = (fixture) => {
  require(fixture?.artifactId === FIXTURE_ARTIFACT_ID && fixture.bytes !== null && typeof fixture.bytes === 'object' && fixture.bindings !== null && typeof fixture.bindings === 'object', 'exact fixture byte fields required');
  require(Array.isArray(fixture.bytes.operandsBottomToTop) && Array.isArray(fixture.bindings.operandsBottomToTop) && fixture.bytes.operandsBottomToTop.length === fixture.bindings.operandsBottomToTop.length, 'fixture operand binding cardinality drift');
  fixture.bytes.operandsBottomToTop.forEach((operand, index) => assertByteBinding(operand, fixture.bindings.operandsBottomToTop[index], `fixture operand ${index}`));
  for (const field of ['redeemBytecode', 'operandUnlockingBytecode', 'redeemPush', 'unlockingBytecode', 'sourceLockingBytecode', 'transaction', 'sourceOutputs', 'outputLockingBytecode']) {
    assertByteBinding(fixture.bytes[field], fixture.bindings[field], `fixture ${field}`);
  }
  return fixture;
};

const assertFixtureMatchesRecord = (fixture, record) => {
  assertRecordShape(record);
  assertFixtureByteBindings(fixture);
  require(fixture?.artifactId === FIXTURE_ARTIFACT_ID, 'derived fixture artifact identity drift');
  require(fixture.planId === record.planId && fixture.planOrder === record.planOrder, 'derived fixture plan identity drift');
  require(canonicalEqual(fixture.bindings, record.byteBindings), `derived fixture byte binding drift for ${record.fixtureKey}`);
  require(canonicalEqual(fixture.sourceBinding, record.sourceBinding), `derived fixture source binding drift for ${record.fixtureKey}`);
  const preflight = {
    verifiedExecutionCeilingBytes: record.preflightLimitViolation?.verifiedExecutionCeilingBytes,
    scriptSig: fixture.bindings.unlockingBytecode.byteLength > record.preflightLimitViolation?.verifiedExecutionCeilingBytes,
    redeem: fixture.bindings.redeemBytecode.byteLength > record.preflightLimitViolation?.verifiedExecutionCeilingBytes,
  };
  require(canonicalEqual(preflight, record.preflightLimitViolation), `derived fixture preflight binding drift for ${record.fixtureKey}`);
  const expectedStatus = preflight.scriptSig || preflight.redeem ? LIMIT_FIXTURE_STATUS : READY_FIXTURE_STATUS;
  require(record.status === expectedStatus, `derived fixture status drift for ${record.fixtureKey}`);
  return fixture;
};

/** Re-derive one fixture from the exact corpus stack bytes and verify every frozen byte binding. */
export const deriveVerifiedFixtureForRecord = ({ record, corpus } = {}) => {
  assertRecordShape(record);
  require(corpus?.constructions !== undefined, 'frozen corpus required');
  const caseEntry = findCorpusCase(corpus, record.epochIdentity);
  require(caseEntry.relationId === record.relationId, `fixture/corpus relation drift for ${record.fixtureKey}`);
  require(fixtureIdentityEqual(identityForCasePlan(caseEntry, record.planId), record.epochIdentity), `fixture/corpus identity drift for ${record.fixtureKey}`);
  require(Array.isArray(caseEntry.stackArgsBottomToTop), `corpus stack ABI missing for ${record.fixtureKey}`);
  const sourcePlan = loadSourceSetPlan(record.planId);
  const fixture = deriveExecutionFixture({
    sourcePlan,
    operandsBottomToTop: caseEntry.stackArgsBottomToTop.map((raw, index) => parseLowercaseEvenHex(raw, `corpus operand ${index}`)),
  });
  assertFixtureMatchesRecord(fixture, record);
  return immutable({ record, caseEntry, fixture });
};

const assertWorkItem = (workItem, record) => {
  require(workItem !== null && typeof workItem === 'object', 'work item required');
  require(workItem.fixtureKey === record.fixtureKey && workItem.planId === record.planId, 'work item fixture/plan binding drift');
  require(workItem.constructionIndex === record.epochIdentity.constructionIndex && workItem.constructionId === record.epochIdentity.constructionId, 'work item construction binding drift');
  require(workItem.caseKey === record.epochIdentity.caseKey && workItem.caseDigest === record.epochIdentity.caseDigest && workItem.vectorAttempt === record.epochIdentity.vectorAttempt, 'work item case binding drift');
  require(workItem.relationId === record.relationId && workItem.categoryId === record.categoryId && workItem.caseIndex === record.caseIndex, 'work item relation/category binding drift');
  require(ENGINE_ORDER.includes(workItem.engineId) && typeof workItem.workItemId === 'string' && SAFE_TOKEN.test(workItem.workItemId), 'work item identity drift');
  return workItem;
};

/**
 * Rebuild all 4,732 fixtures from source-set bytecode and raw corpus operands,
 * compare every frozen byte binding, then join all 18,928 work items.
 * This is static fixture derivation only; it never invokes an engine.
 */
export const verifyFrozenFixtureAuthority = ({ artifacts = loadFrozenEpochArtifacts() } = {}) => {
  assertFrozenArtifactShape(artifacts);
  validateFixtureRoster(artifacts.fixtureRoster, { sourceSet: artifacts.sourceSet, corpus: artifacts.corpus });
  const regenerated = buildFixtureRoster({ sourceSet: artifacts.sourceSet, corpus: artifacts.corpus });
  require(regenerated.records.length === FROZEN_COUNTS.fixtures, 'regenerated fixture cardinality drift');
  require(canonicalEqual(regenerated, artifacts.fixtureRoster), 'frozen fixture roster differs from exact fixture re-derivation');

  const records = new Map();
  for (const record of artifacts.fixtureRoster.records) {
    assertRecordShape(record);
    require(!records.has(record.fixtureKey), `duplicate fixture key ${record.fixtureKey}`);
    records.set(record.fixtureKey, record);
  }
  const perFixtureEngines = new Map();
  for (const workItem of artifacts.workItemRoster.workItems) {
    const record = records.get(workItem.fixtureKey);
    require(record !== undefined, `work item references unknown fixture ${workItem.fixtureKey}`);
    assertWorkItem(workItem, record);
    const ids = perFixtureEngines.get(workItem.fixtureKey) ?? new Set();
    require(!ids.has(workItem.engineId), `duplicate engine work item for ${workItem.fixtureKey}/${workItem.engineId}`);
    ids.add(workItem.engineId);
    perFixtureEngines.set(workItem.fixtureKey, ids);
  }
  let violations = 0;
  for (const record of records.values()) {
    const engineIds = perFixtureEngines.get(record.fixtureKey);
    require(engineIds?.size === ENGINE_ORDER.length && ENGINE_ORDER.every((id) => engineIds.has(id)), `incomplete engine obligations for ${record.fixtureKey}`);
    if (record.status === LIMIT_FIXTURE_STATUS) violations += 1;
  }
  require(violations === FROZEN_COUNTS.preflightLimitFixtures, 'preflight fixture count drift');
  require(violations * ENGINE_ORDER.length === FROZEN_COUNTS.preflightLimitWorkItems, 'preflight work-item count drift');
  return immutable({
    fixtureCount: records.size,
    readyFixtureCount: records.size - violations,
    preflightLimitFixtureCount: violations,
    workItemCount: artifacts.workItemRoster.workItems.length,
    preflightLimitWorkItemCount: violations * ENGINE_ORDER.length,
  });
};

/** Construct a verified row suitable for a later engine-specific codec. */
export const buildVerifiedAdapterRow = ({ workItem, fixtureRecord, corpus } = {}) => {
  assertWorkItem(workItem, fixtureRecord);
  const derived = deriveVerifiedFixtureForRecord({ record: fixtureRecord, corpus });
  return immutable({
    workItem,
    fixtureRecord,
    fixture: derived.fixture,
    caseEntry: derived.caseEntry,
    expected: derived.caseEntry.expected,
  });
};

/** Preflight-only terminal classification; this must never be counted as execution or agreement. */
export const classifyPreflightWorkItem = (row) => {
  require(row?.fixtureRecord !== undefined && row?.workItem !== undefined, 'verified adapter row required');
  assertWorkItem(row.workItem, row.fixtureRecord);
  require(row.fixtureRecord.status === LIMIT_FIXTURE_STATUS, 'preflight classification only applies to a limit violation');
  return immutable({
    workItemId: row.workItem.workItemId,
    fixtureKey: row.fixtureRecord.fixtureKey,
    terminalStatus: PREFLIGHT_TERMINAL_STATUS,
    supportStatus: 'unsupported',
    phase: 'preflight-limit',
    scope: ADAPTER_SCOPE,
    txChecks: TX_CHECKS_UNSUPPORTED,
    executed: false,
    countedAsExecution: false,
    agreement: false,
    countedAsAgreement: false,
    preflightLimitViolation: row.fixtureRecord.preflightLimitViolation,
  });
};

const descriptorFor = (constructionId) => {
  const relativePath = DESCRIPTORS[constructionId];
  require(relativePath !== undefined, `unknown frozen construction ${constructionId}`);
  const descriptor = readFrozenJson(relativePath);
  require(descriptor.descriptorId === constructionId, `descriptor identity drift for ${constructionId}`);
  const q = descriptor.directQuotient;
  require(q?.p !== undefined && Number.isSafeInteger(q.degree) && q.degree > 0 && Array.isArray(q.definingPolynomialAscending), `direct extension descriptor drift for ${constructionId}`);
  return immutable({
    descriptor,
    extension: createDirectExtension({
      modulus: BigInt(q.p),
      degree: q.degree,
      limbBytes: descriptor.canonicalCodec?.baseLimbBytes,
      definingPolynomial: q.definingPolynomialAscending.map((coefficient) => BigInt(coefficient)),
    }),
  });
};

const rawOperandsFromBottomToTop = (relationId, operandsBottomToTop) => {
  const names = RELATION_OPERAND_NAMES[relationId];
  require(names !== undefined, `unknown frozen relation ${relationId}`);
  require(Array.isArray(operandsBottomToTop) && operandsBottomToTop.length === names.length, `${relationId} operand count drift`);
  const rawOperands = {};
  names.forEach((name, index) => {
    const value = operandsBottomToTop[index];
    require(value instanceof Uint8Array, `${relationId} operand ${index} must be raw bytes`);
    rawOperands[name] = bytesToHex(value);
  });
  return rawOperands;
};

const parserStage = (error) => {
  const message = String(error?.message ?? error);
  if (/unused high bit/u.test(message)) return 'unused-high-bit-check-before-numeric-decode';
  if (/>= p/u.test(message)) return 'coefficient-range-check-before-arithmetic';
  return 'canonical-parser-reject';
};

const finalizeNativeReplay = (caseEntry, { verdict, stage }) => {
  const result = immutable({
    engineId: 'engine:native',
    scope: ADAPTER_SCOPE,
    txChecks: TX_CHECKS_UNSUPPORTED,
    terminalStatus: 'supported',
    phase: 'semantic-reference',
    verdict,
    stage,
  });
  require(canonicalEqual({ verdict: result.verdict, stage: result.stage }, caseEntry.expected), `native replay differs from frozen expected case ${caseEntry.caseKey}`);
  return result;
};

/**
 * Replay one canonical corpus case using the descriptor-specific DirectExtension
 * configuration. The result is host semantic reference only, never BCH VM
 * execution or transaction admission evidence.
 */
export const replayNativeDirectExtension = ({ caseEntry, fixture = null } = {}) => {
  require(caseEntry !== null && typeof caseEntry === 'object', 'corpus case required');
  const { extension } = descriptorFor(caseEntry.constructionId);
  const operandBytes = fixture === null
    ? caseEntry.stackArgsBottomToTop.map((value, index) => parseLowercaseEvenHex(value, `case operand ${index}`))
    : fixture.bytes?.operandsBottomToTop;
  if (fixture !== null) {
    require(fixture.planId?.includes(`:relation:${caseEntry.relationId.slice('relation:'.length)}:v1`), 'native fixture relation binding drift');
  }
  const rawOperands = rawOperandsFromBottomToTop(caseEntry.relationId, operandBytes);
  require(canonicalEqual(rawOperands, caseEntry.rawOperands), 'native replay raw stack ABI drift');
  const required = RELATION_OPERAND_NAMES[caseEntry.relationId];
  const values = {};
  for (const name of required) {
    const raw = parseLowercaseEvenHex(rawOperands[name], `native ${name}`);
    if (raw.length !== extension.elementBytes) {
      return finalizeNativeReplay(caseEntry, { verdict: 'reject', stage: 'exact-extension-element-length-check-before-limb-decode' });
    }
    try {
      values[name] = extension.decode(raw);
    } catch (error) {
      return finalizeNativeReplay(caseEntry, { verdict: 'reject', stage: parserStage(error) });
    }
  }
  let replay;
  if (caseEntry.relationId === 'relation:e-mac') replay = extension.equal(values.D, extension.add(extension.mul(values.A, values.B), values.C));
  else if (caseEntry.relationId === 'relation:e-square-mac') replay = extension.equal(values.D, extension.add(extension.square(values.A), values.C));
  else {
    try { replay = extension.verifyInverseHint(values.A, values.H); } catch { replay = false; }
  }
  return finalizeNativeReplay(caseEntry, {
    verdict: replay ? 'accept' : 'reject',
    stage: replay ? 'accept' : caseEntry.relationId === 'relation:e-inverse-check' ? 'inverse-relation-check' : 'relation-check',
  });
};

/** Replay the host reference across all four construction descriptors and all 1,288 corpus cases. */
export const replayAllFrozenNativeCases = ({ corpus } = {}) => {
  require(corpus?.constructions?.length === 4, 'frozen four-construction corpus required');
  let replayed = 0;
  const byConstruction = {};
  for (const construction of corpus.constructions) {
    require(DESCRIPTORS[construction.constructionId] !== undefined, `unknown frozen construction ${construction.constructionId}`);
    let count = 0;
    for (const caseEntry of construction.cases) {
      replayNativeDirectExtension({ caseEntry });
      count += 1;
    }
    byConstruction[construction.constructionId] = count;
    replayed += count;
  }
  require(replayed === 1288, 'native replay corpus cardinality drift');
  return immutable({ replayed, byConstruction: immutable(byConstruction) });
};

/** Decode the exact frozen v2 transaction and source-output vector for Libauth. No VM is run here. */
export const decodeLibauthProgramFromExactFixture = (fixture) => {
  require(fixture?.artifactId === FIXTURE_ARTIFACT_ID, 'exact execution fixture required for Libauth');
  assertFixtureByteBindings(fixture);
  require(fixture.bytes?.transaction instanceof Uint8Array && fixture.bytes?.sourceOutputs instanceof Uint8Array, 'exact transaction/sourceOutputs bytes required');
  const transaction = decodeTransaction(fixture.bytes.transaction);
  const sourceOutputs = decodeTransactionOutputs(fixture.bytes.sourceOutputs);
  require(typeof transaction !== 'string', `Libauth transaction decode failed: ${transaction}`);
  require(typeof sourceOutputs !== 'string', `Libauth sourceOutputs decode failed: ${sourceOutputs}`);
  require(transaction.version === 2 && transaction.inputs.length === 1 && transaction.outputs.length === 1 && sourceOutputs.length === 1, 'Libauth decoded fixture shape drift');
  return immutable({ inputIndex: 0, transaction, sourceOutputs });
};

/** The high-level Libauth path accepts only a roster-bound, fully re-hashed fixture row. */
export const decodeLibauthProgramFromVerifiedRow = (row) => {
  assertAdapterRow(row, 'engine:libauth');
  return decodeLibauthProgramFromExactFixture(row.fixture);
};

/**
 * Explicit Libauth script-engine evaluation entrypoint. It evaluates only the
 * decoded frozen component fixture and intentionally does not call vm.verify:
 * transaction/token admission remains unsupported at this adapter boundary.
 */
export const evaluateLibauthExactFixture = (fixture, { vmFactory = createVirtualMachineBch2026 } = {}) => {
  require(typeof vmFactory === 'function', 'Libauth VM factory required');
  const program = decodeLibauthProgramFromExactFixture(fixture);
  const vm = vmFactory(true);
  const state = vm.evaluate(program);
  const success = vm.stateSuccess(state);
  const accepted = success === true;
  // Metrics are a raw VM-state projection, not acceptance evidence. Preserve
  // every finite numeric source field for either terminal verdict; reject
  // states can still expose accounting that the later normalizer must bind.
  const metrics = state.metrics !== null && typeof state.metrics === 'object'
    ? Object.fromEntries(Object.entries(state.metrics).filter(([, value]) => typeof value === 'number' && Number.isFinite(value)))
    : null;
  return immutable({
    engineId: 'engine:libauth',
    scope: ADAPTER_SCOPE,
    txChecks: TX_CHECKS_UNSUPPORTED,
    terminalStatus: 'supported',
    phase: 'script-engine',
    verdict: accepted ? 'accept' : 'reject',
    error: accepted ? null : String(success),
    metrics,
  });
};

/** Explicit VM entrypoint for later evidence code; tests intentionally never call it. */
export const evaluateLibauthVerifiedRow = (row, options = {}) => {
  assertAdapterRow(row, 'engine:libauth');
  return evaluateLibauthExactFixture(row.fixture, options);
};

const assertAdapterRow = (row, engineId, { allowPreflight = false } = {}) => {
  require(row !== null && typeof row === 'object', 'adapter row required');
  exactKeys(row, ['caseEntry', 'expected', 'fixture', 'fixtureRecord', 'workItem'], 'adapter row');
  assertWorkItem(row.workItem, row.fixtureRecord);
  require(row.workItem.engineId === engineId, `row engine must be ${engineId}`);
  assertFixtureMatchesRecord(row.fixture, row.fixtureRecord);
  require(canonicalEqual(row.expected, row.caseEntry.expected), 'adapter row expected verdict drift');
  require(row.caseEntry.caseKey === row.workItem.caseKey, 'adapter row case identity drift');
  if (!allowPreflight) require(row.fixtureRecord.status === READY_FIXTURE_STATUS, `preflight limit fixture cannot be submitted to ${engineId}`);
  return row;
};

const assertBatchRows = (rows, engineId) => {
  require(Array.isArray(rows) && rows.length > 0, `${engineId} requires nonempty rows`);
  const ids = new Set();
  for (const row of rows) {
    assertAdapterRow(row, engineId);
    require(!ids.has(row.workItem.workItemId), `duplicate work item ${row.workItem.workItemId}`);
    ids.add(row.workItem.workItemId);
  }
  return rows;
};
const fixtureTransactionHex = (row) => bytesToHex(row.fixture.bytes.transaction);
const fixtureSourceOutputsHex = (row) => bytesToHex(row.fixture.bytes.sourceOutputs);

/** Encode the exact BCHN script-only vmb batch. This function does not spawn BCHN. */
export const encodeBchnBatchStdin = (rows) => {
  assertBatchRows(rows, 'engine:bchn');
  const pack = rows.map((row) => [
    row.workItem.workItemId,
    'cohort-freeze-v2 exact synthetic P2SH32 component fixture',
    '',
    '',
    fixtureTransactionHex(row),
    fixtureSourceOutputsHex(row),
    0,
  ]);
  return `${JSON.stringify(pack)}\n`;
};

const expectedIdSet = (rows, engineId) => new Set(assertBatchRows(rows, engineId).map((row) => row.workItem.workItemId));
const expectedVerdictsById = (rows, engineId) => new Map(assertBatchRows(rows, engineId).map((row) => [row.workItem.workItemId, row.expected.verdict]));
const assertBchnMetricShape = (effect) => {
  for (const field of ['op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks', 'sig_checks_limit']) nullableInteger(effect[field], `BCHN ${field}`);
  if (effect.outcome === 'accept') {
    require(effect.error_class === 0 && effect.phase === 'ok' && effect.native_error === '', 'BCHN accepted effect identity drift');
    for (const field of ['op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks', 'sig_checks_limit']) require(effect[field] !== null, `BCHN accepted ${field} missing`);
  } else {
    require(effect.error_class !== 0 && effect.phase !== 'ok', 'BCHN rejected effect identity drift');
    for (const field of ['op_cost', 'op_cost_limit', 'hash_iters', 'hash_iters_limit', 'sig_checks']) require(effect[field] === null, `BCHN rejected ${field} must be unavailable`);
  }
};

/** Strictly parse one BCHN NDJSON batch and retain the script-only tx_checks boundary. */
export const parseBchnBatchStdout = (stdout, { rows } = {}) => {
  require(typeof stdout === 'string' && stdout.endsWith('\n') && !stdout.includes('\r'), 'BCHN stdout must be LF-terminated NDJSON without CR');
  const expected = expectedIdSet(rows, 'engine:bchn');
  const lines = stdout.slice(0, -1).split('\n');
  require(lines.length === expected.size && lines.every((line) => line.length > 0), 'BCHN output cardinality or blank-line drift');
  const effects = new Map();
  for (const line of lines) {
    let effect;
    try { effect = JSON.parse(line); } catch (error) { throw new TypeError(`cohort execution adapter: BCHN invalid JSON: ${error.message}`); }
    exactKeys(effect, BCHN_EFFECT_KEYS, 'BCHN effect');
    require(typeof effect.ident === 'string' && expected.has(effect.ident) && !effects.has(effect.ident), 'BCHN ident missing, unknown, or duplicate');
    require(effect.outcome === 'accept' || effect.outcome === 'reject', 'BCHN outcome drift');
    integer(effect.error_class, 'BCHN error_class');
    require(typeof effect.native_error === 'string' && ALLOWED_BCHN_PHASES.has(effect.phase), 'BCHN native error/phase drift');
    require(effect.tx_checks === 'unsupported' && effect.stack_hash === null, 'BCHN component-only boundary drift');
    assertBchnMetricShape(effect);
    effects.set(effect.ident, immutable({
      ...effect,
      supportStatus: 'supported',
      scope: ADAPTER_SCOPE,
      txChecks: TX_CHECKS_UNSUPPORTED,
      phaseClass: effect.phase === 'execute' || effect.phase === 'ok' ? 'script-engine' : 'outer-or-vector-unsupported-for-agreement',
      metrics: effect.outcome === 'accept' ? immutable({ operationCost: effect.op_cost, maximumOperationCost: effect.op_cost_limit, hashDigestIterations: effect.hash_iters, maximumHashDigestIterations: effect.hash_iters_limit, signatureCheckCount: effect.sig_checks, maximumSignatureCheckCount: effect.sig_checks_limit }) : null,
    }));
  }
  require(effects.size === expected.size, 'BCHN output lacks expected work items');
  return immutable(effects);
};

const expectedVerdictToken = (row) => row.expected.verdict === 'accept' ? '1' : '0';
const leanLineFor = (row, prefix) => `${prefix} ${row.workItem.workItemId} ${fixtureTransactionHex(row)} ${fixtureSourceOutputsHex(row)} 0`;

/** Encode exact Lean vmbconf input. This function does not spawn Lean. */
export const encodeLeanVmbconfStdin = (rows) => {
  assertBatchRows(rows, 'engine:leanbch');
  return `${rows.map((row) => leanLineFor(row, expectedVerdictToken(row))).join('\n')}\n`;
};

/** Encode exact Lean costprobe input. `KERNEL` is accepted then ignored by CostProbe's expected token slot. */
export const encodeLeanCostprobeStdin = (rows) => {
  assertBatchRows(rows, 'engine:leanbch');
  return `${rows.map((row) => leanLineFor(row, 'KERNEL')).join('\n')}\n`;
};

const parseLeanList = (payload, label) => {
  try {
    const value = JSON.parse(payload);
    require(Array.isArray(value) && value.every((item) => typeof item === 'string' && SAFE_TOKEN.test(item)), `${label} list drift`);
    return value;
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`cohort execution adapter: ${label} must be JSON string list`);
  }
};
const parseCount = (text, label) => {
  require(/^(?:0|[1-9][0-9]*)$/u.test(text), `${label} count drift`);
  return Number(text);
};
const assertKnownUniqueIds = (ids, expected, label) => {
  const seen = new Set();
  for (const id of ids) {
    require(expected.has(id) && !seen.has(id), `${label} contains unknown or duplicate id`);
    seen.add(id);
  }
};

/**
 * Strictly parse Lean's seven-line aggregate vmbconf report. It intentionally
 * returns no per-work-item terminal verdicts: the runner's capped id lists are
 * insufficient to establish complete per-item phase attribution.
 */
export const parseLeanVmbconfAggregate = (stdout, { rows } = {}) => {
  require(typeof stdout === 'string' && stdout.endsWith('\n') && !stdout.includes('\r'), 'Lean vmbconf stdout must be LF-terminated without CR');
  const expected = expectedIdSet(rows, 'engine:leanbch');
  const expectedVerdicts = expectedVerdictsById(rows, 'engine:leanbch');
  const lines = stdout.slice(0, -1).split('\n');
  require(lines.length === 7, 'Lean vmbconf must emit exactly seven lines');
  const oracle = /^ORACLE ([^\s]+)$/u.exec(lines[0]);
  const pass = /^PASS ([0-9]+) \/ ([0-9]+)$/u.exec(lines[1]);
  const rejectedValid = /^REJECTED-VALID ([0-9]+): (\[.*\])$/u.exec(lines[2]);
  const acceptedInvalid = /^ACCEPTED-INVALID ([0-9]+): (\[.*\])$/u.exec(lines[3]);
  const standard = /^STD-TRUE ([0-9]+) STD-FALSE ([0-9]+)$/u.exec(lines[4]);
  const trueIds = /^STD-TRUE-IDS: (\[.*\])$/u.exec(lines[5]);
  const falseIds = /^STD-FALSE-IDS: (\[.*\])$/u.exec(lines[6]);
  require(oracle?.[1] === 'reject' && pass && rejectedValid && acceptedInvalid && standard && trueIds && falseIds, 'Lean vmbconf grammar or frozen oracle drift');
  const result = {
    oracle: oracle[1],
    passed: parseCount(pass[1], 'Lean pass'),
    total: parseCount(pass[2], 'Lean total'),
    rejectedValid: parseCount(rejectedValid[1], 'Lean rejected-valid'),
    acceptedInvalid: parseCount(acceptedInvalid[1], 'Lean accepted-invalid'),
    standardTrue: parseCount(standard[1], 'Lean standard true'),
    standardFalse: parseCount(standard[2], 'Lean standard false'),
    rejectedValidIds: parseLeanList(rejectedValid[2], 'Lean rejected-valid'),
    acceptedInvalidIds: parseLeanList(acceptedInvalid[2], 'Lean accepted-invalid'),
    standardTrueIds: parseLeanList(trueIds[1], 'Lean standard true'),
    standardFalseIds: parseLeanList(falseIds[1], 'Lean standard false'),
  };
  require(result.total === expected.size && result.passed + result.rejectedValid + result.acceptedInvalid === result.total, 'Lean vmbconf aggregate count drift');
  require(result.standardTrue + result.standardFalse === result.total, 'Lean vmbconf standard count drift');
  require(result.rejectedValidIds.length === Math.min(result.rejectedValid, 20) && result.acceptedInvalidIds.length === Math.min(result.acceptedInvalid, 20), 'Lean vmbconf mismatch-list truncation drift');
  require(result.standardTrueIds.length === Math.min(result.standardTrue, 200) && result.standardFalseIds.length === Math.min(result.standardFalse, 200), 'Lean vmbconf standard-list truncation drift');
  for (const [ids, label] of [[result.rejectedValidIds, 'rejected-valid'], [result.acceptedInvalidIds, 'accepted-invalid'], [result.standardTrueIds, 'standard-true'], [result.standardFalseIds, 'standard-false']]) assertKnownUniqueIds(ids, expected, `Lean ${label}`);
  require(result.rejectedValidIds.every((id) => expectedVerdicts.get(id) === 'accept'), 'Lean rejected-valid list conflicts with frozen expected verdicts');
  require(result.acceptedInvalidIds.every((id) => expectedVerdicts.get(id) === 'reject'), 'Lean accepted-invalid list conflicts with frozen expected verdicts');
  require(!result.standardTrueIds.some((id) => result.standardFalseIds.includes(id)), 'Lean standard lists overlap');
  return immutable({
    ...result,
    engineId: 'engine:leanbch',
    supportStatus: 'supported',
    scope: ADAPTER_SCOPE,
    txChecks: TX_CHECKS_UNSUPPORTED,
    aggregateOnly: true,
    perWorkItemTerminalResults: null,
    phase: 'aggregate-only-insufficient-for-per-item-agreement',
    countedAsExecution: false,
    countedAsAgreement: false,
  });
};

/** Strictly parse Lean costprobe's per-line output without treating it as outer transaction validation. */
export const parseLeanCostprobeStdout = (stdout, { rows } = {}) => {
  require(typeof stdout === 'string' && stdout.endsWith('\n') && !stdout.includes('\r'), 'Lean costprobe stdout must be LF-terminated without CR');
  const expected = expectedIdSet(rows, 'engine:leanbch');
  const lines = stdout.slice(0, -1).split('\n');
  require(lines.length === expected.size + 1 && lines[0] === 'ORACLE reject', 'Lean costprobe oracle or output cardinality drift');
  const parsed = new Map();
  for (const line of lines.slice(1)) {
    const metrics = /^METRICS ([^\s]+) ([01]) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+) ([0-9]+)$/u.exec(line);
    const skip = /^SKIP ([^\s]+) (decode|no-metric-phase)$/u.exec(line);
    require((metrics !== null) !== (skip !== null), 'Lean costprobe line grammar drift');
    const id = metrics?.[1] ?? skip?.[1];
    require(expected.has(id) && !parsed.has(id), 'Lean costprobe id missing, unknown, or duplicate');
    if (metrics) {
      parsed.set(id, immutable({
        status: 'measured-script-engine-only',
        terminalStatus: 'supported-script-engine-only',
        supportStatus: 'supported',
        verdict: metrics[2] === '1' ? 'accept' : 'reject',
        metrics: immutable({
          evaluatedInstructionCount: parseCount(metrics[3], 'costprobe instruction'),
          signatureCheckCount: parseCount(metrics[4], 'costprobe sigchecks'),
          hashDigestIterations: parseCount(metrics[5], 'costprobe hashiters'),
          arithmeticCost: parseCount(metrics[6], 'costprobe arithmetic'),
          stackPushedBytes: parseCount(metrics[7], 'costprobe pushed'),
          nativeConsensus64OperationCost: parseCount(metrics[8], 'costprobe op cost'),
        }),
        scope: ADAPTER_SCOPE,
        txChecks: TX_CHECKS_UNSUPPORTED,
        phase: 'script-engine-only',
      }));
    } else {
      parsed.set(id, immutable({
        status: 'explicit-unsupported-incomplete',
        terminalStatus: LEAN_INCOMPLETE_TERMINAL_STATUS,
        supportStatus: 'unsupported',
        verdict: null,
        metrics: null,
        reason: skip[2],
        scope: ADAPTER_SCOPE,
        txChecks: TX_CHECKS_UNSUPPORTED,
        phase: 'ambiguous-pre-script-or-script-failure-not-agreement',
        executed: false,
        countedAsExecution: false,
        agreement: false,
        countedAsAgreement: false,
      }));
    }
  }
  require(parsed.size === expected.size, 'Lean costprobe output lacks expected work items');
  return immutable(parsed);
};

const frozenEngine = (engineId, artifacts) => {
  require(ENGINE_ORDER.includes(engineId), `unknown engine ${engineId}`);
  const engine = artifacts.engines?.[engineId];
  require(engine?.engineId === engineId && engine.executionAllowed === false && engine.selection === null, `${engineId} frozen engine record drift`);
  require(engine.entrypoint?.kind === (engineId === 'engine:native' || engineId === 'engine:libauth' ? 'module' : 'external'), `${engineId} entrypoint kind drift`);
  return engine;
};
const entrypointCwd = (engine, entrypoint = engine.entrypoint) => {
  const filePath = entrypoint?.file?.realpath;
  const root = engine.repositoryAuthority?.find((candidate) => typeof candidate.realpath === 'string' && typeof filePath === 'string' && filePath.startsWith(`${candidate.realpath}/`));
  require(root !== undefined, `${engine.engineId} entrypoint escapes its pinned repository authority`);
  return root.realpath;
};
const descriptor = (engine, { argv, cwd, stdin, stdinCodec, lifecycle }) => immutable({
  descriptorKind: 'process-invocation-only-not-spawned',
  engineId: engine.engineId,
  scope: ADAPTER_SCOPE,
  txChecks: TX_CHECKS_UNSUPPORTED,
  executionAllowedByFrozenEpoch: false,
  argv: immutable([...argv]),
  cwd,
  environment: immutable({ ...engine.environment }),
  stdinCodec,
  stdin,
  lifecycle,
});

/** Build, but never spawn, the pinned BCHN script-only process invocation. */
export const buildBchnInvocationDescriptor = (rows, { artifacts = loadFrozenEpochArtifacts() } = {}) => {
  const engine = frozenEngine('engine:bchn', artifacts);
  require(engine.stdinCodec === 'vmb-json-array-transaction-and-source-outputs-v2', 'BCHN stdin codec drift');
  return descriptor(engine, {
    argv: engine.entrypoint.argv,
    cwd: entrypointCwd(engine),
    stdin: encodeBchnBatchStdin(rows),
    stdinCodec: engine.stdinCodec,
    lifecycle: 'one-script-only-process-batch-if-separately-authorized',
  });
};

/** Build, but never spawn, the primary Lean vmbconf invocation. */
export const buildLeanVmbconfInvocationDescriptor = (rows, { artifacts = loadFrozenEpochArtifacts() } = {}) => {
  const engine = frozenEngine('engine:leanbch', artifacts);
  require(engine.stdinCodec === 'expected-id-transaction-sourceOutputs-inputIndex-lines-v2', 'Lean stdin codec drift');
  return descriptor(engine, {
    argv: engine.entrypoint.argv,
    cwd: entrypointCwd(engine),
    stdin: encodeLeanVmbconfStdin(rows),
    stdinCodec: engine.stdinCodec,
    lifecycle: 'aggregate-vmbconf-process-not-sufficient-for-per-item-terminal-results',
  });
};

/** Build, but never spawn, the pinned Lean costprobe invocation. */
export const buildLeanCostprobeInvocationDescriptor = (rows, { artifacts = loadFrozenEpochArtifacts() } = {}) => {
  const engine = frozenEngine('engine:leanbch', artifacts);
  const secondary = engine.secondaryEntrypoints?.[0];
  require(secondary?.kind === 'external' && secondary.argv?.length === 1, 'Lean costprobe entrypoint drift');
  return descriptor(engine, {
    argv: secondary.argv,
    cwd: entrypointCwd(engine, secondary),
    stdin: encodeLeanCostprobeStdin(rows),
    stdinCodec: 'expected-id-transaction-sourceOutputs-inputIndex-lines-v2-with-KERNEL-expected-token',
    lifecycle: 'separate-costprobe-process; requires explicit reconciliation with frozen one-lifecycle-per-engine-batch policy',
  });
};

/** Describe an in-process Libauth evaluation without constructing or running a VM. */
export const buildLibauthInvocationDescriptor = (row, { artifacts = loadFrozenEpochArtifacts() } = {}) => {
  const engine = frozenEngine('engine:libauth', artifacts);
  require(engine.stdinCodec === 'in-process-authentication-program-from-exact-synthetic-transaction-v2', 'Libauth stdin codec drift');
  const program = decodeLibauthProgramFromVerifiedRow(row);
  return immutable({
    descriptorKind: 'in-process-invocation-only-not-evaluated',
    engineId: engine.engineId,
    scope: ADAPTER_SCOPE,
    txChecks: TX_CHECKS_UNSUPPORTED,
    executionAllowedByFrozenEpoch: false,
    entrypoint: engine.entrypoint.file.realpath,
    environment: immutable({ ...engine.environment }),
    stdinCodec: engine.stdinCodec,
    workItemId: row.workItem.workItemId,
    fixtureKey: row.fixtureRecord.fixtureKey,
    inputIndex: program.inputIndex,
    transaction: program.transaction,
    sourceOutputs: program.sourceOutputs,
  });
};

/** Describe an in-process native reference replay; it has no process/VM surface. */
export const buildNativeInvocationDescriptor = (row, { artifacts = loadFrozenEpochArtifacts() } = {}) => {
  const engine = frozenEngine('engine:native', artifacts);
  assertAdapterRow(row, 'engine:native', { allowPreflight: true });
  return immutable({
    descriptorKind: 'in-process-host-reference-only-not-bch-vm',
    engineId: engine.engineId,
    scope: ADAPTER_SCOPE,
    txChecks: TX_CHECKS_UNSUPPORTED,
    executionAllowedByFrozenEpoch: false,
    entrypoint: engine.entrypoint.file.realpath,
    environment: immutable({ ...engine.environment }),
    stdinCodec: engine.stdinCodec,
    workItemId: row.workItem.workItemId,
    fixtureKey: row.fixtureRecord.fixtureKey,
  });
};
