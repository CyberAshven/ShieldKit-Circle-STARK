import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import { campaignCountsForDegree, contentDigestFor, validateCampaign } from '../algebra-component/algebra-component-validation.mjs';

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const schema = load('./equal-relation-arithmetic-campaign.v1.schema.json');
const campaign = load('./equal-relation-arithmetic-campaign.v1.json');
const validateSchema = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
const clone = () => structuredClone(campaign);
const refresh = (value) => { value.contentDigest.value = contentDigestFor(value); return value; };

test('arithmetic campaign pins Gate-B v1, current v2 matrix, exact cohort, and non-selection boundary', () => {
  assert.equal(validateSchema(campaign), true, JSON.stringify(validateSchema.errors));
  assert.deepEqual(validateCampaign(campaign), []);
  assert.equal(campaign.contentDigest.value, contentDigestFor(campaign));
  assert.equal(campaign.cohort.m89FirstStatus, 'non-ranking-harness-shakedown-only');
  assert.equal(campaign.cohort.cohortRankingStatus, 'closed-until-all-four-descriptors-and-both-tracks-share-one-epoch');
  assert.equal(campaign.selection, 'none');
});

test('count formulas are deterministic and positive for every relation/category/degree pair', () => {
  const counts = campaignCountsForDegree(campaign, 2);
  assert.equal(counts.length, 15);
  assert.deepEqual(counts.find((item) => item.relationId === 'relation:e-mac' && item.categoryId === 'category:boundary'), { relationId: 'relation:e-mac', categoryId: 'category:boundary', cases: '10', operandSamples: '40', limbSamples: '80' });
  assert.deepEqual(counts.find((item) => item.relationId === 'relation:e-mac' && item.categoryId === 'category:malformed'), { relationId: 'relation:e-mac', categoryId: 'category:malformed', cases: '14', operandSamples: '56', limbSamples: '112' });
  assert.deepEqual(counts.find((item) => item.relationId === 'relation:e-inverse-check' && item.categoryId === 'category:malformed'), { relationId: 'relation:e-inverse-check', categoryId: 'category:malformed', cases: '16', operandSamples: '32', limbSamples: '64' });
  assert.equal(counts.reduce((sum, item) => sum + Number(item.cases), 0), 266);
  assert.ok(counts.every((item) => BigInt(item.cases) > 0n));
});

test('semantic checks reject formula, track mapping, index order, matrix, and sampler drift', () => {
  const zeroCount = clone();
  zeroCount.countFormulas[0].categories[0].caseFormula.value = 0;
  refresh(zeroCount);
  assert.ok(validateCampaign(zeroCount).some((error) => error.includes('count formulas')));

  const trackSwap = clone();
  [trackSwap.tracks[0].kind, trackSwap.tracks[1].kind] = [trackSwap.tracks[1].kind, trackSwap.tracks[0].kind];
  refresh(trackSwap);
  assert.ok(validateCampaign(trackSwap).some((error) => error.includes('track identity')));

  const relationOrder = clone();
  relationOrder.corpusGenerator.relationOrder.reverse();
  refresh(relationOrder);
  assert.ok(validateCampaign(relationOrder).some((error) => error.includes('relation index order')));

  const byteOffset = clone();
  byteOffset.corpusGenerator.mutationPlans.find((item) => item.family === 'truncation').transform = 'remove-an-unspecified-byte';
  refresh(byteOffset);
  assert.ok(validateCampaign(byteOffset).some((error) => error.includes('exact mutation plans')));

  const inverseLeak = clone();
  inverseLeak.corpusGenerator.mutationPlans.find((item) => item.family === 'zero-inverse-hint').relations.unshift('relation:e-mac');
  refresh(inverseLeak);
  assert.ok(validateCampaign(inverseLeak).some((error) => error.includes('exact mutation plans')));

  const matrix = clone();
  matrix.matrixBinding.sha256 = '0'.repeat(64);
  refresh(matrix);
  assert.ok(validateCampaign(matrix).some((error) => error.includes('matrix binding')));

  const protocolSampler = clone();
  protocolSampler.corpusGenerator.protocolUse = 'protocol-sampler';
  refresh(protocolSampler);
  assert.equal(validateSchema(protocolSampler), false);
});

test('schema and content binding reject ranking inflation, missing mutations, and stale digests', () => {
  const ranking = clone();
  ranking.cohort.m89FirstStatus = 'ranked-winner';
  refresh(ranking);
  assert.equal(validateSchema(ranking), false);

  const omittedMutation = clone();
  omittedMutation.corpusGenerator.mutationFamilies.pop();
  refresh(omittedMutation);
  assert.equal(validateSchema(omittedMutation), false);

  const stale = clone();
  stale.contentDigest.value = '0'.repeat(64);
  assert.ok(validateCampaign(stale).some((error) => error.includes('content digest')));
});
