import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import Ajv from 'ajv/dist/2020.js';

import {
  ARTIFACT_PATH,
  EXPECTED_CARDINALITIES,
  MANIFEST_PATH,
  REPO,
  SCHEMA_PATH,
  assertContainedPathWithoutSymlinks,
  assertKnownPassingPackageDigest,
  canonicalJson,
  contentDigestFor,
  generatePackage,
  manifestFor,
  sha256SumsFor,
  validatePackageSemantics
} from './generate.mjs';

const schema = JSON.parse(readFileSync(resolve(REPO, SCHEMA_PATH), 'utf8'));
const artifact = JSON.parse(readFileSync(ARTIFACT_PATH, 'utf8'));
const schemaValidate = new Ajv({ strict: true, allErrors: true }).compile(schema);
const authority = generatePackage();
const invalid = (value, label) => assert.ok(
  validatePackageSemantics(value, { checkFiles: false, expected: authority }).length > 0,
  label
);
const redigest = (value) => {
  value.contentDigest.value = contentDigestFor(value);
  return value;
};

test('root artifact is strict, canonical, deterministic, and semantically valid', () => {
  assert.equal(schemaValidate(artifact), true, JSON.stringify(schemaValidate.errors));
  assert.deepEqual(validatePackageSemantics(artifact, { expected: authority }), []);
  assert.deepEqual(Buffer.from(canonicalJson(authority)), readFileSync(ARTIFACT_PATH));
  assert.equal(readFileSync(ARTIFACT_PATH).at(-1), 0x0a);
  assert.equal(readFileSync(ARTIFACT_PATH).includes(0x0d), false);
});

test('scope and downstream boundaries stay closed and unselected', () => {
  assert.equal(artifact.selection, 'none');
  assert.equal(artifact.tupleRef, null);
  assert.equal(artifact.protocolBoundary, 'component-only');
  assert.deepEqual(artifact.executionBoundary, {
    packageValidationRequired: true,
    sourceEmissionAllowed: false,
    bytecodeEmissionAllowed: false,
    vmExecutionAllowed: false,
    metricsAllowed: false
  });
  assert.deepEqual(artifact.downstreamBindings, {
    sourceSetV1: null,
    campaignV2: null,
    canonicalCorpusV2: null,
    executionEpochV2: null
  });
});

test('all exact aggregate cardinalities are regenerated, not trusted literals', () => {
  assert.deepEqual(artifact.cardinalities, EXPECTED_CARDINALITIES);
  assert.equal(artifact.programIndex.reduce((sum, row) => sum + row.nodeCount, 0), 4806);
  assert.equal(artifact.programIndex.reduce((sum, row) => sum + row.rangeLedger.rowCount, 0), 4806);
  assert.equal(artifact.planIndex.reduce((sum, row) => sum + row.instructionCount, 0), 25098);
  assert.equal(artifact.planIndex.reduce((sum, row) => sum + row.traceRowCount, 0), 25098);
  assert.equal(Math.max(...artifact.planIndex.map((row) => row.maxCombinedDepth)), 392);
});

test('ordered indexes have exact identity and plan-scoped parser invocations', () => {
  assert.equal(new Set(artifact.programIndex.map((row) => row.programId)).size, 28);
  assert.equal(new Set(artifact.moduleIndex.map((row) => row.moduleId)).size, 19);
  assert.equal(new Set(artifact.planIndex.map((row) => row.planId)).size, 42);
  const invocations = artifact.planIndex.flatMap((plan) => plan.parserInvocations);
  assert.equal(invocations.length, 126);
  assert.equal(new Set(invocations.map((row) => row.invocationKey)).size, 126);
  assert.ok(new Set(invocations.map((row) => row.invocationId)).size < 126);
  assert.deepEqual(artifact.validationContract.relationOrder, [
    'relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'
  ]);
});

test('digest framing is actual domain separation and all compact/full roots are pinned', () => {
  assert.equal(artifact.digestAlgorithms.packageObject.frame, 'utf8(domain)||00||canonical-json-utf8');
  assert.equal(artifact.contentDigest.domain, 'shieldkit-labs/p2/lowering-arm-ir-freeze/v1/root');
  assert.notEqual(
    artifact.validationContract.completeAuthorityDigests.plans.value,
    artifact.validationContract.compactIndexDigests.plans.value
  );
  assert.ok(artifact.programIndex.every((row) => row.programDigest.domain.includes(`/program/${row.programId}`)));
  assert.ok(artifact.planIndex.every((row) => row.planDigest.domain.includes(`/plan/${row.planId}`)));
});

test('raw manifest and SHA256SUMS cover the deterministic package without a self-reference', () => {
  const artifactBytes = readFileSync(ARTIFACT_PATH);
  const expectedManifest = Buffer.from(canonicalJson(manifestFor(artifactBytes)));
  assert.deepEqual(readFileSync(MANIFEST_PATH), expectedManifest);
  const sums = readFileSync(resolve(MANIFEST_PATH, '../SHA256SUMS'), 'utf8');
  assert.equal(sums, sha256SumsFor(artifactBytes, expectedManifest));
  assert.ok(sums.includes('  MANIFEST.json\n'));
  assert.equal(sums.includes('  SHA256SUMS'), false);
});

test('component-walk containment rejects an intermediate-directory symlink', () => {
  const root = mkdtempSync(join(tmpdir(), 'shieldkit-lowering-ir-path-'));
  try {
    mkdirSync(join(root, 'real'));
    writeFileSync(join(root, 'real', 'payload.txt'), 'bound\n');
    assert.equal(assertContainedPathWithoutSymlinks(root, 'real/payload.txt'), join(root, 'real', 'payload.txt'));
    symlinkSync('real', join(root, 'alias'), 'dir');
    assert.throws(
      () => assertContainedPathWithoutSymlinks(root, 'alias/payload.txt'),
      /symlink component forbidden/
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('redigested compact mutations still fail exact regeneration', () => {
  const mutations = [
    (value) => { value.selection = 'chosen'; },
    (value) => { value.upstreamBindings.files[0].fileDigest.value = '0'.repeat(64); },
    (value) => { value.implementationBindings.runtime.version = 'v0.0.0'; },
    (value) => { value.implementationBindings.files[0].path = '../escape'; },
    (value) => { value.cardinalities.instructions += 1; },
    (value) => { [value.programIndex[0], value.programIndex[1]] = [value.programIndex[1], value.programIndex[0]]; },
    (value) => { value.moduleIndex[1].moduleId = value.moduleIndex[0].moduleId; },
    (value) => { value.planIndex[0].parserInvocations[0].invocationKey = 'wrong#key'; },
    (value) => { value.planIndex[0].terminal.primary[0].value = 'false'; },
    (value) => { value.planIndex[0].maxCombinedDepth += 1; },
    (value) => { value.validationContract.completeAuthorityDigests.plans.value = '0'.repeat(64); },
    (value) => { value.nonClaims[0] = 'claim'; }
  ];
  for (const [index, mutate] of mutations.entries()) {
    const value = structuredClone(artifact);
    mutate(value);
    redigest(value);
    invalid(value, `mutation ${index} unexpectedly accepted`);
  }
});

test('unknown properties and missing/reordered indexes are rejected fail-closed', () => {
  const unknown = structuredClone(artifact);
  unknown.unexpected = true;
  assert.equal(schemaValidate(unknown), false);
  const missing = structuredClone(artifact);
  missing.planIndex.pop();
  redigest(missing);
  invalid(missing, 'missing plan');
  const duplicate = structuredClone(artifact);
  duplicate.programIndex[1].programId = duplicate.programIndex[0].programId;
  redigest(duplicate);
  invalid(duplicate, 'duplicate program');
});

test('an emitter must know the exact passing package digest', () => {
  assert.equal(assertKnownPassingPackageDigest(artifact, artifact.contentDigest.value), true);
  assert.throws(() => assertKnownPassingPackageDigest(artifact), /missing or unknown/);
  assert.throws(() => assertKnownPassingPackageDigest(artifact, '0'.repeat(64)), /stale/);
  const nonPass = structuredClone(artifact);
  nonPass.validationContract.verdict = 'fail';
  redigest(nonPass);
  assert.throws(() => assertKnownPassingPackageDigest(nonPass, nonPass.contentDigest.value), /non-pass/);
});
