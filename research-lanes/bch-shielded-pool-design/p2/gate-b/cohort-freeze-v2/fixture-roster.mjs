import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CATEGORY_ORDER, ENGINE_ORDER, EXPECTED_OPTIMIZED_ARM_SUFFIXES, RELATION_ORDER,
  digestRecord, fixtureKeyFor,
} from './epoch.mjs';
import {
  VERIFIED_EXECUTION_CEILING_BYTES, buildFixtureRosterRecord, deriveExecutionFixture, loadSourceSetPlan,
  domainSeparatedSha256,
} from './execution-fixture.mjs';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const SCHEMA = 'shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-roster';
export const FIXTURE_ROSTER_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-roster';
export const FIXTURE_KEY_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-key';
export const SOURCE_SET_PATH = 'p2/source-set-v1/source-set.v1.json';
export const SOURCE_SET_SCHEMA_PATH = 'p2/source-set-v1/source-set.v1.schema.json';
export const CORPUS_PATH = 'p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json';
export const CORPUS_SCHEMA_PATH = 'p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.schema.json';
export const FIXTURE_DERIVATION_PATH = 'p2/gate-b/cohort-freeze-v2/execution-fixture.mjs';
export const ARM_ORDER = Object.freeze([
  'arm:canonical:m89-d2-canonical-schoolbook-v1',
  'arm:canonical:m61-d3-canonical-schoolbook-v1',
  'arm:canonical:m31-d5-canonical-schoolbook-v1',
  'arm:canonical:m31-d6-canonical-schoolbook-v1',
  ...EXPECTED_OPTIMIZED_ARM_SUFFIXES.map((suffix) => `arm:optimized:${suffix}`),
]);
export const EXPECTED_COUNTS = Object.freeze({ corpusCases: 1288, armCount: 14, uniquePlanCaseFixtures: 4732, deduplicatedEngineWorkItems: 18928 });
const INDEX_FIELDS = Object.freeze(['armId', 'trackId', 'relationId', 'categoryId', 'caseIndex', 'engineWorkItemCount']);

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const readJson = (path) => JSON.parse(readFileSync(resolve(ROOT, path), 'utf8'));
const rawSha256 = (path) => sha256(readFileSync(resolve(ROOT, path)));
const sourceSet = () => readJson(SOURCE_SET_PATH);
const corpus = () => readJson(CORPUS_PATH);
const constructionTag = (armId) => /(?:^|:)((?:m31|m61|m89)-d\d+)(?:-|$)/u.exec(armId)?.[1];
const relationSuffix = (relationId) => relationId.slice('relation:'.length);
const planFor = (source, armId, relationId) => {
  const plan = source.planIndex.find((entry) => entry.planId === `physical-plan:${armId}:relation:${relationSuffix(relationId)}:v1`);
  if (!plan) throw new Error(`missing source-set plan for ${armId}/${relationId}`);
  return plan;
};
const contentDigestValue = (value) => value?.value ?? value;
const bytesFromHex = (hex) => Uint8Array.from(Buffer.from(hex, 'hex'));
const caseDigest = (entry) => contentDigestValue(entry.caseDigest);
const caseIdentity = (entry, planId) => ({
  constructionIndex: entry.constructionIndex,
  constructionId: entry.constructionId,
  planId,
  caseKey: entry.caseKey,
  caseDigest: caseDigest(entry),
  vectorAttempt: entry.vectorAttempt,
});

const fixtureFor = (sourcePlan, entry) => deriveExecutionFixture({
  sourcePlan,
  operandsBottomToTop: entry.stackArgsBottomToTop.map(bytesFromHex),
});

function buildBindings(source, corpusArtifact) {
  const sourceDigest = source.contentDigest;
  return {
    sourceSet: {
      path: SOURCE_SET_PATH,
      rawSha256: rawSha256(SOURCE_SET_PATH),
      schemaPath: SOURCE_SET_SCHEMA_PATH,
      schemaRawSha256: rawSha256(SOURCE_SET_SCHEMA_PATH),
      contentDigest: sourceDigest,
      planCount: source.planIndex.length,
    },
    corpus: {
      path: CORPUS_PATH,
      rawSha256: rawSha256(CORPUS_PATH),
      schemaPath: CORPUS_SCHEMA_PATH,
      schemaRawSha256: rawSha256(CORPUS_SCHEMA_PATH),
      contentDigest: corpusArtifact.contentDigest,
      caseCount: corpusArtifact.counts.total,
    },
    fixtureDerivation: {
      path: FIXTURE_DERIVATION_PATH,
      rawSha256: rawSha256(FIXTURE_DERIVATION_PATH),
      recordSchema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/fixture-roster-record/v2',
      fixtureKeyDomain: FIXTURE_KEY_DOMAIN,
      operandOrder: 'bottom-to-top-exact-raw-bytes-no-normalization',
      executionCeilingBytes: VERIFIED_EXECUTION_CEILING_BYTES,
    },
  };
}

const recordWithIndex = ({ base, armId, relationId, categoryId, caseIndex, engineWorkItemCount }) => ({
    ...base,
    armId,
    trackId: armId.split(':')[1] === 'canonical' ? 'track:canonical' : 'track:optimized',
    relationId,
    categoryId,
    caseIndex,
    engineWorkItemCount,
});

export function buildFixtureRoster({ sourceSet: injectedSourceSet, corpus: injectedCorpus } = {}) {
  const source = injectedSourceSet ?? sourceSet();
  const corpusArtifact = injectedCorpus ?? corpus();
  if (source.planIndex.length !== 42 || corpusArtifact.counts.total !== 1288) throw new Error('source-set/corpus cardinality drift');
  const loadedPlans = new Map();
  const records = [];
  const byArm = {};
  for (const armId of ARM_ORDER) {
    const tag = constructionTag(armId);
    const construction = corpusArtifact.constructions.find((entry) => entry.constructionId.includes(tag));
    if (!construction) throw new Error(`missing corpus construction for ${armId}`);
    const armRecords = [];
    for (const entry of construction.cases) {
      const plan = planFor(source, armId, entry.relationId);
      let loaded = loadedPlans.get(plan.planId);
      if (!loaded) { loaded = loadSourceSetPlan(plan.planId); loadedPlans.set(plan.planId, loaded); }
      const fixture = fixtureFor(loaded, entry);
      const identity = caseIdentity(entry, plan.planId);
      const helperRecord = buildFixtureRosterRecord({ epochIdentity: identity, fixture });
      const record = recordWithIndex({
        base: helperRecord,
        armId,
        relationId: entry.relationId,
        categoryId: entry.categoryId,
        caseIndex: entry.caseIndex,
        engineWorkItemCount: ENGINE_ORDER.length,
      });
      armRecords.push(record);
      records.push(record);
    }
    byArm[armId] = { armId, caseCount: armRecords.length, planIds: RELATION_ORDER.map((relationId) => planFor(source, armId, relationId).planId) };
  }
  const violations = records.filter((record) => record.status === 'preflight-limit-violation');
  const artifact = {
    schema: `${SCHEMA}/v2`,
    artifactId: 'fixture-roster:gate-b-v2',
    status: 'frozen-fixture-roster-no-vm-execution',
    evidenceClassification: 'not-evidence',
    executionAllowed: false,
    metricsAllowed: false,
    ranking: null,
    selection: null,
    sourceSet: buildBindings(source, corpusArtifact).sourceSet,
    corpus: buildBindings(source, corpusArtifact).corpus,
    fixtureDerivation: buildBindings(source, corpusArtifact).fixtureDerivation,
    normativeArmOrder: [...ARM_ORDER],
    relationOrder: [...RELATION_ORDER],
    categoryOrder: [...CATEGORY_ORDER],
    engineOrder: [...ENGINE_ORDER],
    armCatalog: ARM_ORDER.map((armId) => byArm[armId]),
    counts: {
      corpusCases: EXPECTED_COUNTS.corpusCases,
      armCount: EXPECTED_COUNTS.armCount,
      uniquePlanCaseFixtures: records.length,
      deduplicatedEngineWorkItems: records.reduce((sum, record) => sum + record.engineWorkItemCount, 0),
      preflightReady: records.length - violations.length,
      preflightLimitViolations: violations.length,
      preflightLimitViolationScriptSig: violations.filter((record) => record.preflightLimitViolation.scriptSig).length,
      preflightLimitViolationRedeem: violations.filter((record) => record.preflightLimitViolation.redeem).length,
    },
    records,
    contentDigest: null,
  };
  artifact.contentDigest = digestRecord(artifact, FIXTURE_ROSTER_DOMAIN);
  validateFixtureRoster(artifact);
  return artifact;
}

export function validateFixtureRoster(artifact, { sourceSet: authoritySourceSet, corpus: authorityCorpus } = {}) {
  if (!artifact || artifact.schema !== `${SCHEMA}/v2` || artifact.artifactId !== 'fixture-roster:gate-b-v2') throw new Error('fixture roster identity drift');
  if (artifact.evidenceClassification !== 'not-evidence' || artifact.executionAllowed !== false || artifact.metricsAllowed !== false || artifact.ranking !== null || artifact.selection !== null) throw new Error('fixture roster execution boundary drift');
  if (artifact.records.length !== EXPECTED_COUNTS.uniquePlanCaseFixtures || artifact.counts.uniquePlanCaseFixtures !== artifact.records.length) throw new Error('fixture roster cardinality drift');
  if (artifact.counts.deduplicatedEngineWorkItems !== EXPECTED_COUNTS.deduplicatedEngineWorkItems) throw new Error('engine work-item deduplication drift');
  if (artifact.normativeArmOrder.length !== 14 || JSON.stringify(artifact.normativeArmOrder) !== JSON.stringify(ARM_ORDER)) throw new Error('normative arm order drift');
  const keys = new Set();
  const armRank = new Map(ARM_ORDER.map((armId, index) => [armId, index]));
  const relationRank = new Map(RELATION_ORDER.map((relationId, index) => [relationId, index]));
  const categoryRank = new Map(CATEGORY_ORDER.map((categoryId, index) => [categoryId, index]));
  let previousOrder = null;
  let violations = 0;
  for (const record of artifact.records) {
    const currentOrder = [armRank.get(record.armId), record.epochIdentity.constructionIndex, relationRank.get(record.relationId), categoryRank.get(record.categoryId), record.caseIndex, record.epochIdentity.vectorAttempt];
    if (currentOrder.some((value) => value === undefined)) throw new Error('fixture roster record order drift');
    if (previousOrder) { for (let index = 0; index < currentOrder.length; index += 1) { if (currentOrder[index] === previousOrder[index]) continue; if (currentOrder[index] < previousOrder[index]) throw new Error('fixture roster record order drift'); break; } }
    previousOrder = currentOrder;
    if (keys.has(record.fixtureKey)) throw new Error('duplicate fixture key'); keys.add(record.fixtureKey);
    const expectedKey = fixtureKeyFor(record.epochIdentity);
    if (record.fixtureKey !== expectedKey || record.planId !== record.epochIdentity.planId) throw new Error('fixture key/identity mismatch');
    if (record.engineWorkItemCount !== 4) throw new Error('engine work-item deduplication mismatch');
    if (record.status === 'preflight-limit-violation') violations += 1;
    const recordDigestDomain = `shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture/${record.fixtureKey}`;
    const recordDigestProjection = Object.fromEntries(Object.entries(record).filter(([key]) => key !== 'contentDigest' && !INDEX_FIELDS.includes(key)));
    recordDigestProjection.contentDigest = null;
    if (record.contentDigest?.domain !== recordDigestDomain || record.contentDigest?.value !== domainSeparatedSha256(recordDigestDomain, recordDigestProjection)) throw new Error('fixture record content digest is not reproducible');
    for (const value of Object.values(record)) if (typeof value === 'string' && /(?:transaction|operand).*hex|raw.*hex/iu.test(value)) throw new Error('raw transaction/operand hex leaked into roster');
  }
  if (violations !== artifact.counts.preflightLimitViolations) throw new Error('preflight violation count drift');
  if (authoritySourceSet && authoritySourceSet.planIndex?.length !== artifact.sourceSet.planCount) throw new Error('source-set authority drift');
  if (authorityCorpus && authorityCorpus.counts?.total !== artifact.corpus.caseCount) throw new Error('corpus authority drift');
  const expectedDigest = digestRecord(artifact, FIXTURE_ROSTER_DOMAIN);
  if (JSON.stringify(expectedDigest) !== JSON.stringify(artifact.contentDigest)) throw new Error('fixture roster content digest is not reproducible');
  return true;
}

if (process.argv.includes('--check')) {
  const artifact = buildFixtureRoster();
  console.log(JSON.stringify({ counts: artifact.counts, contentDigest: artifact.contentDigest }));
}
