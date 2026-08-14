import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  CATEGORY_ORDER, ENGINE_CAPABILITIES, ENGINE_ORDER, EXPECTED_COUNTS, EXPECTED_OPTIMIZED_ARM_SUFFIXES,
  RELATION_ORDER, ROOT_DOMAIN, SCHEMA, STATUS, WORK_ITEM_ROSTER_DOMAIN,
  buildExecutionEpoch, buildPhysicalSchedule, buildTerminalCells, buildWorkItemRoster, canonicalize, canonicalJson,
  contentDigestFor, deriveArmCatalog, fixtureKeyFor, resolveArmOrder, validateEngineRecords, validateExecutionEpoch,
  validatePhysicalSchedule, validateUnsupportedAccounting
} from './epoch.mjs';

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const digest = (seed) => createHash('sha256').update(seed).digest('hex');
const sourceSet = { ...load('../../source-set-v1/source-set.v1.json'), path: 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json', rawSha256: digest('source-set-raw'), schemaSha256: digest('source-set-schema') };
const schema = load('./execution-epoch.v2.schema.json');
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const rosterSchema = load('./work-item-roster.v2.schema.json');
const validateRosterSchema = new Ajv2020({ allErrors: true, strict: true }).compile(rosterSchema);
const engines = ENGINE_ORDER.map((engineId, index) => ({ engineId, artifactId: `engine-artifact:${engineId}`, path: `research/engines/${engineId}.v2.json`, rawSha256: digest(`raw:${engineId}`), contentDigest: digest(`content:${engineId}`), schemaSha256: digest('engine-schema:v2'), capabilityStatus: index === 3 ? 'required-or-explicit-unsupported' : 'required', role: index === 0 ? 'semantic-reference-engine' : 'bch-vm-engine', capabilities: structuredClone(ENGINE_CAPABILITIES) }));
const artifact = (id) => ({ artifactId: id, path: `fixture/${id}.json`, rawSha256: digest(`raw:${id}`), schemaSha256: digest(`schema:${id}`), contentDigest: digest(id) });
const campaign = artifact('campaign:gate-b-v2');
const executionProfile = artifact('execution-profile:gate-b-v2');
const fixtureDerivation = artifact('fixture-derivation:gate-b-v2');
const fixtureRoster = artifact('fixture-roster:gate-b-v2');
const workItemRosterSchemaSha256 = digest('work-item-roster-schema:v2');
const workItemRosterRawSha256 = digest('work-item-roster-raw:v2');

const armSuffix = (armId) => armId.replace(/^arm:(?:canonical|optimized):/u, '');
const descriptorMap = (() => {
  const arms = deriveArmCatalog(sourceSet).filter((arm) => arm.trackId === 'track:optimized');
  const out = new Map();
  for (let rank = 0; rank < EXPECTED_OPTIMIZED_ARM_SUFFIXES.length; rank += 1) {
    const suffix = EXPECTED_OPTIMIZED_ARM_SUFFIXES[rank];
    const arm = arms.find((item) => armSuffix(item.armId) === suffix);
    assert.ok(arm, `missing optimized arm ${suffix}`);
    let nonce = 0;
    while (true) {
      const candidate = digest(`descriptor:${suffix}:${nonce}`);
      const key = createHash('sha256').update(Buffer.concat([Buffer.from(candidate, 'ascii'), Buffer.from([0]), Buffer.from(arm.armId, 'utf8')])).digest();
      if (key[0] === (rank + 1) * 16) { out.set(arm.armId, candidate); break; }
      nonce += 1;
    }
  }
  return out;
})();

const corpus = load('./canonical-corpus.v2.json');
Object.assign(corpus, { path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json', rawSha256: digest('corpus-raw'), schemaSha256: digest('corpus-schema') });

test('canonical digest frame omits only contentDigest and binds each required domain', () => {
  const value = { z: 2, contentDigest: { value: '0'.repeat(64) }, a: { y: true, x: [3, 2] } };
  assert.equal(contentDigestFor(value, WORK_ITEM_ROSTER_DOMAIN), contentDigestFor({ ...value, contentDigest: null }, WORK_ITEM_ROSTER_DOMAIN));
  assert.notEqual(contentDigestFor(value, WORK_ITEM_ROSTER_DOMAIN), contentDigestFor(value, ROOT_DOMAIN));
  assert.deepEqual(canonicalize({ b: 1, a: 2 }), { a: 2, b: 1 });
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{\n  "a": 2,\n  "b": 1\n}\n');
});

test('source-set resolves 4 canonical arms then the exact 10-arm optimized order', () => {
  const resolved = resolveArmOrder(sourceSet, descriptorMap);
  assert.deepEqual(resolved.canonical.map((arm) => armSuffix(arm.armId)), [
    'm89-d2-canonical-schoolbook-v1', 'm61-d3-canonical-schoolbook-v1', 'm31-d5-canonical-schoolbook-v1', 'm31-d6-canonical-schoolbook-v1'
  ]);
  assert.deepEqual(resolved.optimized.map((arm) => armSuffix(arm.armId)), EXPECTED_OPTIMIZED_ARM_SUFFIXES);
});

test('roster expands exact 168 terminal cells, 1288 corpus cases, 4732 arm-cases/engine, and 18928 work items', () => {
  const roster = buildWorkItemRoster({ sourceSet, corpus, descriptors: descriptorMap, engineRecords: engines, rawSha256: workItemRosterRawSha256, schemaSha256: workItemRosterSchemaSha256 });
  assert.deepEqual(roster.counts, EXPECTED_COUNTS);
  assert.equal(roster.terminalCells.length, 168);
  assert.equal(roster.contentDigest.domain, WORK_ITEM_ROSTER_DOMAIN);
  assert.equal(roster.contentDigest.value, contentDigestFor(roster, WORK_ITEM_ROSTER_DOMAIN));
  assert.equal(Object.hasOwn(roster, 'rawSha256'), false, 'roster must not self-bind serialized raw SHA');
  assert.equal(validateRosterSchema(roster), true, JSON.stringify(validateRosterSchema.errors));
  assert.deepEqual(roster.engineOrder, ENGINE_ORDER);
  const firstArm = roster.workItems.filter((item) => item.armId === roster.normativeArmOrder[0]);
  assert.deepEqual(firstArm.slice(0, 4).map((item) => item.engineId), ENGINE_ORDER);
  assert.ok(roster.workItems.every((item) => item.constructionId && item.caseKey && item.caseDigest && item.planBytecodeSha256 && item.fixtureKey));
});

test('engine records reject drop, reorder, and capability substitution', () => {
  assert.doesNotThrow(() => validateEngineRecords(engines));
  assert.throws(() => validateEngineRecords(engines.slice(0, 3)), /exactly four/);
  const reordered = structuredClone(engines); [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  assert.throws(() => validateEngineRecords(reordered), /exact order/);
  const substituted = structuredClone(engines); substituted[0].capabilities.relations.reverse();
  assert.throws(() => validateEngineRecords(substituted), /capabilities/);
});

test('actual constructions.cases order and full identities are fail-closed', () => {
  const reordered = structuredClone(corpus);
  [reordered.constructions[0].cases[0], reordered.constructions[0].cases[1]] = [reordered.constructions[0].cases[1], reordered.constructions[0].cases[0]];
  assert.throws(() => buildWorkItemRoster({ sourceSet, corpus: reordered, descriptors: descriptorMap, engineRecords: engines, rawSha256: workItemRosterRawSha256, schemaSha256: workItemRosterSchemaSha256 }), /order drift|missing\/reordered/);
  const duplicate = structuredClone(corpus);
  duplicate.constructions[0].cases[1] = structuredClone(duplicate.constructions[0].cases[0]);
  assert.throws(() => buildWorkItemRoster({ sourceSet, corpus: duplicate, descriptors: descriptorMap, engineRecords: engines, rawSha256: workItemRosterRawSha256, schemaSha256: workItemRosterSchemaSha256 }), /duplicate|order drift/);
});

test('fixture keys use the approved safe digest-derived identifier and bindings never substitute content for raw SHA', () => {
  const sample = corpus.constructions[0].cases[0];
  const planId = sourceSet.planIndex.find((plan) => plan.planId.includes('m89-d2-canonical-schoolbook') && plan.planId.includes('relation:e-mac')).planId;
  const key = fixtureKeyFor({ constructionIndex: sample.constructionIndex, constructionId: sample.constructionId, planId, caseKey: sample.caseKey, caseDigest: sample.caseDigest.value, vectorAttempt: sample.vectorAttempt });
  assert.match(key, /^fixture:[0-9a-f]{64}$/u);
  assert.equal(key, fixtureKeyFor({ constructionIndex: sample.constructionIndex, constructionId: sample.constructionId, planId, caseKey: sample.caseKey, caseDigest: sample.caseDigest.value, vectorAttempt: sample.vectorAttempt }));
  assert.notEqual(key, fixtureKeyFor({ constructionIndex: sample.constructionIndex, constructionId: sample.constructionId, planId, caseKey: sample.caseKey, caseDigest: digest('different-case'), vectorAttempt: sample.vectorAttempt }));
  const missingRaw = structuredClone(sourceSet); delete missingRaw.rawSha256;
  assert.throws(() => buildExecutionEpoch({ sourceSet: missingRaw, campaign, corpus, executionProfile, engineRecords: engines, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 }), /rawSha256/);
  const substitutedRaw = structuredClone(campaign); substitutedRaw.rawSha256 = substitutedRaw.contentDigest;
  assert.throws(() => buildExecutionEpoch({ sourceSet, campaign: substitutedRaw, corpus, executionProfile, engineRecords: engines, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 }), /must not substitute/);
});

test('unsupported terminal accounting is explicit and never execution or agreement', () => {
  assert.doesNotThrow(() => validateUnsupportedAccounting([{ supportStatus: 'supported', executed: false }, { supportStatus: 'unsupported', executed: false, agreement: false }]));
  assert.throws(() => validateUnsupportedAccounting([{ supportStatus: 'unsupported', executed: true }]), /cannot count/);
  assert.throws(() => validateUnsupportedAccounting([{ supportStatus: 'unknown' }]), /supported or explicit/);
});

test('physical schedule is engine-major, serial, non-retrying, and mutation-sensitive', () => {
  const roster = buildWorkItemRoster({ sourceSet, corpus, descriptors: descriptorMap, engineRecords: engines, rawSha256: workItemRosterRawSha256, schemaSha256: workItemRosterSchemaSha256 });
  const schedule = buildPhysicalSchedule({ roster, engineRecords: engines });
  assert.doesNotThrow(() => validatePhysicalSchedule(schedule, roster, engines));
  assert.deepEqual(schedule.batches.map((batch) => batch.engineId), ENGINE_ORDER);
  assert.equal(schedule.policy.maxConcurrency, 1);
  const rosterPosition = new Map(roster.workItems.map((item, index) => [item.workItemId, index]));
  for (const batch of schedule.batches) {
    const positions = batch.workItemIds.map((id) => rosterPosition.get(id));
    assert.deepEqual(positions, [...positions].sort((a, b) => a - b), `${batch.engineId} reordered normative work items`);
  }
  const mutated = structuredClone(schedule); mutated.policy.maxConcurrency = 2;
  assert.throws(() => validatePhysicalSchedule(mutated, roster, engines), /differs/);
});

test('epoch schema and semantic boundary bind all artifacts and forbid execution/result/metric/ranking/selection', () => {
  const epoch = buildExecutionEpoch({ sourceSet, campaign, corpus, executionProfile, engineRecords: engines, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 });
  assert.equal(epoch.schema, SCHEMA); assert.equal(epoch.status, STATUS);
  assert.equal(validateSchema(epoch), true, JSON.stringify(validateSchema.errors));
  assert.doesNotThrow(() => validateExecutionEpoch(epoch, { sourceSet, campaign, corpus, executionProfile, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 }));
  const rawOnlyProfile = structuredClone(executionProfile); delete rawOnlyProfile.schemaSha256;
  const rawOnlyEpoch = buildExecutionEpoch({ sourceSet, campaign, corpus, executionProfile: rawOnlyProfile, engineRecords: engines, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 });
  assert.equal(validateSchema(rawOnlyEpoch), true, JSON.stringify(validateSchema.errors));
  for (const field of ['execution', 'result', 'metric', 'ranking', 'selection']) { const mutated = structuredClone(epoch); mutated[field] = {}; assert.equal(validateSchema(mutated), false); assert.throws(() => validateExecutionEpoch(mutated, { sourceSet, campaign, corpus, executionProfile, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 }), /must be null/); }
  const rosterPermutation = structuredClone(epoch); rosterPermutation.workItemRoster.contentDigest.value = digest('stale'); assert.equal(validateSchema(rosterPermutation), true); assert.throws(() => validateExecutionEpoch(rosterPermutation, { sourceSet, campaign, corpus, executionProfile, fixtureDerivation, fixtureRoster, descriptors: descriptorMap, workItemRosterRawSha256, workItemRosterSchemaSha256 }), /not reproducible/);
});
