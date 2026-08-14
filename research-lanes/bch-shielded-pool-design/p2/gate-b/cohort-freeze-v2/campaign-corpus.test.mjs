import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';
import { buildCampaign, buildCorpus, digest, sampler, RELATIONS, CATEGORIES } from './campaign-corpus.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(resolve(dir, name), 'utf8'));
const campaign = load('campaign.v2.json');
const corpus = load('canonical-corpus.v2.json');
const ajv = new Ajv2020({ strict: true });
const campaignValid = ajv.compile(load('campaign.v2.schema.json'));
const corpusValid = ajv.compile(load('canonical-corpus.v2.schema.json'));

test('deterministic artifacts and closed schemas', () => {
  assert.deepEqual(buildCampaign(), campaign);
  assert.deepEqual(buildCorpus(campaign), corpus);
  assert.equal(campaignValid(campaign), true, ajv.errorsText(campaignValid.errors));
  assert.equal(corpusValid(corpus), true, ajv.errorsText(corpusValid.errors));
});

test('frozen order, counts, and per-case domain digests', () => {
  assert.deepEqual(campaign.contract.relationOrder, RELATIONS);
  assert.deepEqual(campaign.contract.categoryOrder, CATEGORIES);
  assert.equal(campaign.evidenceClassification, 'not-evidence');
  assert.equal(campaign.selection, null);
  assert.equal(campaign.executionAllowed, false);
  assert.equal(campaign.metricsAllowed, false);
  assert.equal(campaign.rankingAllowed, false);
  assert.equal(campaign.bindings.planRoster.records.length, 42);
  assert.deepEqual(campaign.bindings.planRoster.records, campaign.bindings.sourceSet.plans);
  assert.deepEqual(campaign.bindings.planRoster.contentDigest, digest(campaign.bindings.planRoster.contentDigest.domain, campaign.bindings.planRoster));
  assert.deepEqual(corpus.counts.byConstruction.map((x) => x.total), [266, 294, 350, 378]);
  assert.equal(corpus.counts.total, 1288);
  assert.equal(corpus.evidenceClassification, 'deterministic-test-input-not-execution-evidence');
  assert.equal(corpus.selection, null);
  assert.equal(corpus.executionAllowed, false);
  assert.equal(corpus.metricsAllowed, false);
  assert.equal(corpus.rankingAllowed, false);
  for (const construction of corpus.constructions) {
    assert.equal(construction.cases.length, construction.counts.total);
    for (const item of construction.cases) {
      const withoutCaseDigest = structuredClone(item); delete withoutCaseDigest.caseDigest;
      assert.deepEqual(item.caseDigest, digest(`shieldkit-labs/p2/gate-b/canonical-corpus/v2/case/${item.caseKey}`, withoutCaseDigest));
      const expectedStack = item.relationId === RELATIONS[0] ? ['D', 'C', 'B', 'A'] : item.relationId === RELATIONS[1] ? ['D', 'C', 'A'] : ['H', 'A'];
      assert.equal(item.stackArgsBottomToTop.length, expectedStack.length);
    }
  }
});

test('independent sampler mutation checks', () => {
  const base = { constructionIndex: 0, relationIndex: 0, categoryIndex: 2, operandIndex: 0, limbIndex: 1, caseIndex: 9, vectorAttempt: 0, sampleRetry: 0, p: 618970019642690137449562111n };
  const canonical = sampler(base).value;
  assert.notEqual(canonical, sampler({ ...base, limbIndex: 256 }).value);
  assert.notEqual(canonical, sampler({ ...base, vectorAttempt: 1 }).value);
  assert.notEqual(canonical, sampler({ ...base, constructionIndex: 1 }).value);
  assert.notEqual(canonical, sampler({ ...base, sampleRetry: 1 }).value);
});

test('mutation and wrong-stage checks fail closed', () => {
  const malformed = corpus.constructions.flatMap((x) => x.cases).filter((x) => x.categoryId === 'category:malformed');
  assert.equal(malformed.length, 22 * (2 + 3 + 5 + 6));
  for (const item of malformed) assert.equal(item.expected.verdict, 'reject');
  const lengthCase = malformed.find((x) => x.mutation.family === 'wrong-length');
  assert.equal(lengthCase.expected.stage, 'exact-extension-element-length-check-before-limb-decode');
  const relationCase = malformed.find((x) => x.mutation.family === 'wrong-relation-output');
  assert.equal(relationCase.expected.stage, 'relation-check');
  const inverseCase = malformed.find((x) => x.relationId === 'relation:e-inverse-check' && x.mutation.family === 'zero-inverse-hint');
  assert.equal(inverseCase.expected.stage, 'inverse-relation-check');
  const noOp = structuredClone(corpus); noOp.constructions.pop();
  assert.equal(corpusValid(noOp), false, 'construction removal must fail schema validation');
  const order = structuredClone(campaign); [order.contract.relationOrder[0], order.contract.relationOrder[1]] = [order.contract.relationOrder[1], order.contract.relationOrder[0]];
  assert.equal(campaignValid(order), false, 'relation order mutation must fail schema validation');
  const hash = structuredClone(campaign); hash.bindings.scheduleFreeze.rawSha256 = hash.bindings.scheduleFreeze.rawSha256.replace(/^./, '0');
  assert.notEqual(hash.bindings.scheduleFreeze.rawSha256, campaign.bindings.scheduleFreeze.rawSha256, 'hash substitution must be observable');
  const boundary = structuredClone(campaign); boundary.metricsAllowed = true;
  assert.equal(campaignValid(boundary), false, 'premeasurement boundary mutation must fail schema validation');
});
