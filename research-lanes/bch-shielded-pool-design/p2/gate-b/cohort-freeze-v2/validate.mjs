import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

import { canonicalJson, validateExecutionEpoch, validateWorkItemRosterOrder } from './epoch.mjs';
import { validateFixtureRoster } from './fixture-roster.mjs';
import { checkPackage } from './generate.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const readJson = (path) => JSON.parse(readFileSync(resolve(here, path), 'utf8'));
const fail = (message) => { throw new Error(`cohort-freeze-v2 validator: ${message}`); };
const equal = (left, right, label) => {
  if (canonicalJson(left) !== canonicalJson(right)) fail(`${label} differs from deterministic authority`);
};

const compile = (path) => {
  const schema = readJson(path);
  return new Ajv2020({ allErrors: true, strict: true, allowUnionTypes: true }).compile(schema);
};
const assertSchema = (validator, value, label) => {
  if (!validator(value)) fail(`${label} schema failure: ${JSON.stringify(validator.errors)}`);
};

export const validatePackage = () => {
  const built = checkPackage();
  const { artifacts, manifest } = built;

  const validators = {
    campaign: compile('campaign.v2.schema.json'),
    corpus: compile('canonical-corpus.v2.schema.json'),
    engine: compile('engine.v2.schema.json'),
    fixtureRoster: compile('fixture-roster.v2.schema.json'),
    workRoster: compile('work-item-roster.v2.schema.json'),
    epoch: compile('execution-epoch.v2.schema.json'),
    manifest: compile('manifest.v1.schema.json'),
  };

  const actual = {
    campaign: readJson('campaign.v2.json'),
    corpus: readJson('canonical-corpus.v2.json'),
    engines: ['native', 'libauth', 'bchn', 'leanbch'].map((id) => readJson(`engines/${id}.v2.json`)),
    fixtureRoster: readJson('fixture-roster.v2.json'),
    workRoster: readJson('work-item-roster.v2.json'),
    epoch: readJson('execution-epoch.v2.json'),
    manifest: readJson('MANIFEST.json'),
  };

  assertSchema(validators.campaign, actual.campaign, 'campaign');
  assertSchema(validators.corpus, actual.corpus, 'corpus');
  for (const [index, engine] of actual.engines.entries()) assertSchema(validators.engine, engine, `engine[${index}]`);
  if (actual.engines.some((engine) => Object.hasOwn(engine, 'repositoryInformationalStatus'))) {
    fail('serialized engine artifacts must exclude non-authoritative repository informational status');
  }
  assertSchema(validators.fixtureRoster, actual.fixtureRoster, 'fixture roster');
  assertSchema(validators.workRoster, actual.workRoster, 'work-item roster');
  assertSchema(validators.epoch, actual.epoch, 'execution epoch');
  assertSchema(validators.manifest, actual.manifest, 'manifest');

  equal(actual.campaign, artifacts.campaign, 'campaign');
  equal(actual.corpus, artifacts.corpus, 'corpus');
  equal(actual.engines, artifacts.engineArtifacts, 'engine artifacts');
  equal(actual.fixtureRoster, artifacts.fixtureRoster, 'fixture roster');
  equal(actual.workRoster, artifacts.workItemRoster, 'work-item roster');
  equal(actual.epoch, artifacts.epoch, 'execution epoch');
  equal(actual.manifest, manifest, 'manifest');

  validateFixtureRoster(actual.fixtureRoster, { sourceSet: artifacts.sourceSet, corpus: artifacts.corpus });
  validateWorkItemRosterOrder(actual.workRoster);
  validateExecutionEpoch(actual.epoch, {
    sourceSet: artifacts.bindings.sourceSet,
    campaign: artifacts.bindings.campaign,
    corpus: artifacts.bindings.corpus,
    executionProfile: artifacts.bindings.executionProfile,
    fixtureDerivation: artifacts.bindings.fixtureDerivation,
    fixtureRoster: artifacts.bindings.fixtureRoster,
    descriptors: artifacts.descriptors,
    workItemRosterRawSha256: artifacts.bindings.workItemRosterRawSha256,
    workItemRosterSchemaSha256: artifacts.bindings.workItemRosterSchemaSha256,
  });

  if (actual.workRoster.rawSha256 !== undefined) fail('work-item roster must not self-bind raw file bytes');
  if (actual.epoch.execution !== null || actual.epoch.result !== null || actual.epoch.metric !== null || actual.epoch.ranking !== null || actual.epoch.selection !== null) fail('epoch premeasurement boundary is open');
  if (actual.fixtureRoster.counts.preflightLimitViolations !== 124 || actual.fixtureRoster.counts.preflightReady !== 4608) fail('preflight counts drift');
  if (actual.engines.some((engine) => engine.executionAllowed !== false || engine.evidenceClassification !== 'not-evidence')) fail('engine execution boundary is open');
  if (actual.engines[2].status !== 'fresh-build-attested-unexecuted' || actual.engines[3].status !== 'fresh-build-attested-unexecuted') fail('external build attestations are not closed');

  return {
    status: 'pass-unexecuted',
    counts: manifest.counts,
    contentDigests: manifest.contentDigests,
  };
};

if (process.argv.includes('--strict') || import.meta.url === `file://${process.argv[1]}`) console.log(JSON.stringify(validatePackage()));
