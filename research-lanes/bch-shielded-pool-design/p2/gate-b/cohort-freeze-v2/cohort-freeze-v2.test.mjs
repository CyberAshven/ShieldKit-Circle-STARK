import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { canonicalJson, contentDigestFor, validateExecutionEpoch } from './epoch.mjs';
import { buildPackage, checkPackage } from './generate.mjs';
import { snapshotExecutionSurfaces } from './engine-snapshot.mjs';
import { validateFixtureRoster } from './fixture-roster.mjs';
import { validatePackage } from './validate.mjs';

let cached;
const packageState = () => cached ??= checkPackage();
const clone = (value) => structuredClone(value);

test('the package is deterministic, strict, and still unexecuted', () => {
  const result = validatePackage();
  assert.equal(result.status, 'pass-unexecuted');
  assert.deepEqual(result.counts, {
    constructions: 4,
    arms: 14,
    plans: 42,
    corpusCases: 1288,
    uniquePlanCaseFixtures: 4732,
    terminalEnginePlanCells: 168,
    armCasesPerEngine: 4732,
    workItems: 18928,
    preflightLimitViolations: 124,
  });
  cached = buildPackage();
  assert.equal(canonicalJson(cached.manifest), canonicalJson(packageState().manifest));
});

test('all 4,732 fixture keys bind exact work-item identities and preserve the 124-item BCH ceiling kill', () => {
  const { artifacts } = packageState();
  const fixtureByKey = new Map(artifacts.fixtureRoster.records.map((record) => [record.fixtureKey, record]));
  assert.equal(fixtureByKey.size, 4732);
  assert.ok(artifacts.workItemRoster.workItems.every((item) => fixtureByKey.has(item.fixtureKey)));
  for (const record of artifacts.fixtureRoster.records) assert.equal(artifacts.workItemRoster.workItems.filter((item) => item.fixtureKey === record.fixtureKey).length, 4);
  const violations = artifacts.fixtureRoster.records.filter((record) => record.status === 'preflight-limit-violation');
  assert.equal(violations.length, 124);
  assert.ok(violations.every((record) => record.planId === 'physical-plan:arm:optimized:m31-d6-direct-toom6-v1:relation:e-mac:v1'));
  assert.ok(violations.every((record) => record.preflightLimitViolation.redeem && record.byteBindings.redeemBytecode.byteLength === 10374));
});

test('fixture, epoch, and build provenance mutations fail closed', () => {
  const { artifacts } = packageState();
  const fixture = clone(artifacts.fixtureRoster);
  fixture.records[0].epochIdentity.caseDigest = '0'.repeat(64);
  assert.throws(() => validateFixtureRoster(fixture), /fixture key|content digest/);

  const epoch = clone(artifacts.epoch);
  epoch.workItemRoster.rawSha256 = epoch.workItemRoster.contentDigest.value;
  assert.throws(() => validateExecutionEpoch(epoch, {
    sourceSet: artifacts.bindings.sourceSet,
    campaign: artifacts.bindings.campaign,
    corpus: artifacts.bindings.corpus,
    executionProfile: artifacts.bindings.executionProfile,
    fixtureDerivation: artifacts.bindings.fixtureDerivation,
    fixtureRoster: artifacts.bindings.fixtureRoster,
    descriptors: artifacts.descriptors,
    workItemRosterRawSha256: artifacts.bindings.workItemRosterRawSha256,
    workItemRosterSchemaSha256: artifacts.bindings.workItemRosterSchemaSha256,
  }), /not reproducible/);

  const engine = clone(artifacts.engineArtifacts[2]);
  engine.buildAttestation.vmEvidence = { verdict: true };
  assert.notEqual(contentDigestFor({ ...engine, contentDigest: null }, engine.contentDigest.domain), engine.contentDigest.value);
});

test('informational worktree diagnostics never perturb serialized package authority', () => {
  const snapshot = snapshotExecutionSurfaces();
  const baseline = buildPackage({ snapshot });
  const informationalOnly = clone(snapshot);
  informationalOnly.engines[0].repositorySnapshots[0].informationalWorktree.statusPorcelainSha256 = 'f'.repeat(64);
  const changedDiagnostic = buildPackage({ snapshot: informationalOnly });
  for (const path of [
    'engines/native.v2.json',
    'engines/libauth.v2.json',
    'engines/bchn.v2.json',
    'engines/leanbch.v2.json',
    'execution-epoch.v2.json',
    'MANIFEST.json',
    'SHA256SUMS',
  ]) assert.deepEqual(changedDiagnostic.output.get(path), baseline.output.get(path), `${path} must exclude informational worktree state`);

  const authorityMutation = clone(snapshot);
  authorityMutation.engines[0].modules[0].rawSha256 = '0'.repeat(64);
  assert.throws(() => buildPackage({ snapshot: authorityMutation }), /source|snapshot|drift|input/i);
});

test('the archived build logs are exact package inputs, including the zero-byte streams', () => {
  const { manifest } = packageState();
  const byPath = new Map(manifest.files.map((file) => [file.path, file]));
  for (const path of ['build-logs/bchn-build.stdout.log', 'build-logs/lean-ffi-build.stderr.log', 'build-logs/lean-lake-build.stderr.log']) {
    assert.equal(readFileSync(new URL(path, import.meta.url)).length, 0);
    assert.equal(byPath.get(path).fileDigest.value, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  }
});
