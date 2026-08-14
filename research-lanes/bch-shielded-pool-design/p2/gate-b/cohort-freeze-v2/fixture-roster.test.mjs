import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { digestRecord, fixtureKeyFor } from './epoch.mjs';
import { domainSeparatedSha256 } from './execution-fixture.mjs';
import { buildFixtureRosterRecord, deriveExecutionFixture, loadSourceSetPlan } from './execution-fixture.mjs';
import { ARM_ORDER, FIXTURE_ROSTER_DOMAIN, buildFixtureRoster, validateFixtureRoster } from './fixture-roster.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const schema = JSON.parse(readFileSync(resolve(here, 'fixture-roster.v2.schema.json'), 'utf8'));
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const roster = buildFixtureRoster();
const corpusAuthority = JSON.parse(readFileSync(resolve(here, 'canonical-corpus.v2.json'), 'utf8'));

test('fixture roster is strict, metadata-only, and premeasurement-bound', () => {
  assert.equal(validateSchema(roster), true, JSON.stringify(validateSchema.errors));
  assert.doesNotThrow(() => validateFixtureRoster(roster));
  assert.equal(roster.executionAllowed, false);
  assert.equal(roster.metricsAllowed, false);
  assert.equal(roster.ranking, null);
  assert.equal(roster.selection, null);
  assert.equal(Object.hasOwn(roster, 'rawSha256'), false);
  assert.equal(Object.hasOwn(roster, 'transactionHex'), false);
  assert.equal(Object.hasOwn(roster, 'operandHex'), false);
});

test('exact cardinality, deduplication, and authority bindings', () => {
  assert.deepEqual(roster.normativeArmOrder, ARM_ORDER);
  assert.deepEqual(roster.relationOrder, ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check']);
  assert.deepEqual(roster.categoryOrder, ['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed']);
  assert.deepEqual(roster.engineOrder, ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
  assert.deepEqual(roster.counts, { corpusCases: 1288, armCount: 14, uniquePlanCaseFixtures: 4732, deduplicatedEngineWorkItems: 18928, preflightReady: 4608, preflightLimitViolations: 124, preflightLimitViolationScriptSig: 124, preflightLimitViolationRedeem: 124 });
  assert.equal(roster.records.length, 4732);
  assert.equal(new Set(roster.records.map((record) => record.fixtureKey)).size, 4732);
  assert.equal(roster.records.every((record) => record.engineWorkItemCount === 4), true);
  assert.equal(roster.sourceSet.planCount, 42);
  assert.equal(roster.corpus.caseCount, 1288);
  for (const binding of [roster.sourceSet, roster.corpus, roster.fixtureDerivation]) assert.match(binding.rawSha256, /^[0-9a-f]{64}$/u);
  assert.equal(roster.contentDigest.domain, FIXTURE_ROSTER_DOMAIN);
  assert.deepEqual(roster.contentDigest, digestRecord(roster, FIXTURE_ROSTER_DOMAIN));
});

test('fixture keys independently match plan-case identities and direct-Toom6 e-mac violates the ceiling', () => {
  for (const record of roster.records) {
    assert.equal(record.fixtureKey, fixtureKeyFor(record.epochIdentity));
    const projection = structuredClone(record);
    for (const field of ['armId', 'trackId', 'relationId', 'categoryId', 'caseIndex', 'engineWorkItemCount']) delete projection[field];
    projection.contentDigest = null;
    assert.equal(record.contentDigest.value, domainSeparatedSha256(record.contentDigest.domain, projection));
  }
  const directToom6 = roster.records.filter((record) => record.armId === 'arm:optimized:m31-d6-direct-toom6-v1' && record.relationId === 'relation:e-mac');
  assert.equal(directToom6.length, 124);
  assert.equal(directToom6.every((record) => record.status === 'preflight-limit-violation' && record.preflightLimitViolation.redeem && record.preflightLimitViolation.scriptSig), true);
  assert.equal(directToom6.every((record) => record.byteBindings.redeemBytecode.byteLength > 10000), true);
  assert.equal(roster.records.filter((record) => record.status === 'preflight-limit-violation').length, 124);
});

test('exact helper and epoch work-item fixture keys agree without key rewriting', () => {
  const record = roster.records[0];
  const entry = corpusAuthority.constructions[record.epochIdentity.constructionIndex].cases[record.caseIndex];
  const fixture = deriveExecutionFixture({
    sourcePlan: loadSourceSetPlan(record.planId),
    operandsBottomToTop: entry.stackArgsBottomToTop.map((value) => Uint8Array.from(Buffer.from(value, 'hex'))),
  });
  const helperRecord = buildFixtureRosterRecord({ epochIdentity: record.epochIdentity, fixture });
  assert.deepEqual(helperRecord.epochIdentity, record.epochIdentity);
  assert.equal(helperRecord.fixtureKey, record.fixtureKey);
  assert.equal(helperRecord.fixtureKey, fixtureKeyFor(record.epochIdentity));
  assert.doesNotMatch(readFileSync(resolve(here, 'fixture-roster.mjs'), 'utf8'), /replaceAll\('\|'\s*,/u);
});

test('independent mutation tests fail closed', () => {
  const removed = structuredClone(roster); removed.records.pop();
  assert.equal(validateSchema(removed), false);
  const reordered = structuredClone(roster); [reordered.records[0], reordered.records[1]] = [reordered.records[1], reordered.records[0]];
  assert.equal(validateSchema(reordered), true);
  assert.throws(() => validateFixtureRoster(reordered), /order|fixture key/);
  const substituted = structuredClone(roster); substituted.contentDigest.value = 'f'.repeat(64);
  assert.equal(validateSchema(substituted), true);
  assert.throws(() => validateFixtureRoster(substituted), /content digest/);
  const recordDigest = structuredClone(roster); recordDigest.records[0].contentDigest.value = 'f'.repeat(64);
  assert.equal(validateSchema(recordDigest), true);
  assert.throws(() => validateFixtureRoster(recordDigest), /record content digest/);
  const raw = structuredClone(roster); raw.records[0].operandHex = '00';
  assert.equal(validateSchema(raw), false);
  const boundary = structuredClone(roster); boundary.executionAllowed = true;
  assert.equal(validateSchema(boundary), false);
  const wrongKey = structuredClone(roster); wrongKey.records[0].fixtureKey = `fixture:${'0'.repeat(64)}`;
  assert.equal(validateSchema(wrongKey), true);
  assert.throws(() => validateFixtureRoster(wrongKey), /fixture key/);
});
