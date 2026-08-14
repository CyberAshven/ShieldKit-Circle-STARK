import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';

import {
  DOMAIN_DIGEST_CANONICALIZATION,
  DOMAIN_DIGEST_FRAME,
  MAX_DATA_PUSH_BYTES,
  assertContainedRegularFile,
  decodeMinimalDataPushes,
  deriveExecutionFixture,
  deriveExecutionFixtureFromRawHex,
  deriveEpochFixtureKey,
  buildFixtureRosterRecord,
  canonicalJsonUtf8,
  encodeMinimalDataPush,
  loadSourceSetPlan,
  p2sh32LockingBytecode,
} from './execution-fixture.mjs';
import { assertEngineSnapshotSet, assertExactCurrentEngineSnapshot, buildAttestationRequirements, buildEngineArtifactRecords, canonicalPrettyJson, classifyTerminalOutcome, snapshotExecutionSurfaces } from './engine-snapshot.mjs';
import { ENGINE_CAPABILITIES, fixtureKeyFor } from './epoch.mjs';
import Ajv2020 from 'ajv/dist/2020.js';

const digest = (value) => createHash('sha256').update(value).digest('hex');
const planId = 'physical-plan:arm:canonical:m89-d2-canonical-schoolbook-v1:relation:e-mac:v1';
const clone = (value) => structuredClone(value);
const schema = JSON.parse(readFileSync(new URL('./engine.v2.schema.json', import.meta.url), 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateSchema = ajv.compile(schema);
let snapshot;
const currentSnapshot = () => (snapshot ??= snapshotExecutionSurfaces());
const framedDigest = (domain, value) => digest(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.of(0), canonicalJsonUtf8(value)]));
const attestationDirectory = '/tmp/campaign-v2-build-attestation-20260809';
const logBinding = (name) => {
  const bytes = readFileSync(resolve(attestationDirectory, name));
  return { name, byteLength: bytes.length, rawSha256: digest(bytes) };
};
const exitCodeFromLog = (name) => {
  const firstLine = readFileSync(resolve(attestationDirectory, name), 'utf8').split('\n', 1)[0];
  assert.match(firstLine, /^\d+$/u, `${name} must begin with an exit code`);
  return Number(firstLine);
};
const attestationLogDigest = (engineId, logs) => {
  const domain = `shieldkit-labs/p2/gate-b/execution-epoch/v2/build-attestation/${engineId}/logs`;
  return {
    algorithm: 'sha256',
    canonicalization: DOMAIN_DIGEST_CANONICALIZATION,
    domain,
    frame: DOMAIN_DIGEST_FRAME,
    value: framedDigest(domain, logs),
  };
};
const archivedBuildAttestations = (value) => {
  const requirements = buildAttestationRequirements({ snapshot: value });
  const record = (engineId, logNames, exitLogNames) => {
    const logs = logNames.map(logBinding);
    return {
      schema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/build-attestation/v1',
      engineId,
      status: 'fresh-build-attested-unexecuted',
      evidenceClassification: 'build-attestation-only-not-vm-evidence',
      executionAllowed: false,
      vmEvidence: null,
      ...requirements[engineId],
      exitCode: 0,
      exitCodes: exitLogNames.map(exitCodeFromLog),
      logs,
      logDigest: attestationLogDigest(engineId, logs),
    };
  };
  return {
    'engine:bchn': record('engine:bchn', ['preflight.txt', 'bchn-build.exitcode', 'bchn-build.stdout.log', 'bchn-build.stderr.log', 'after.txt'], ['bchn-build.exitcode']),
    'engine:leanbch': record('engine:leanbch', ['preflight.txt', 'lean-ffi-build.exitcode', 'lean-ffi-build.stdout.log', 'lean-ffi-build.stderr.log', 'lean-lake-build.exitcode', 'lean-lake-build.stdout.log', 'lean-lake-build.stderr.log', 'after.txt'], ['lean-ffi-build.exitcode', 'lean-lake-build.exitcode']),
  };
};
const epochIdentity = (fixture, overrides = {}) => ({
  constructionIndex: 0,
  constructionId: 'algebra-component:m89-d2-x2-plus-1-v2',
  planId: fixture.planId,
  caseKey: 'algebra-component:m89-d2-x2-plus-1-v2|relation:e-mac|category:valid|0|0',
  caseDigest: 'a'.repeat(64),
  vectorAttempt: 0,
  ...overrides,
});

test('fixture is deterministic and binds every transport byte without a VM call', () => {
  const fixture = deriveExecutionFixtureFromRawHex({
    planId,
    operandsBottomToTop: ['010000000000000000000000', '020000000000000000000000', '030000000000000000000000', '050000000000000000000000'],
  });
  const again = deriveExecutionFixtureFromRawHex({
    planId,
    operandsBottomToTop: ['010000000000000000000000', '020000000000000000000000', '030000000000000000000000', '050000000000000000000000'],
  });
  assert.deepEqual(fixture.bindings, again.bindings);
  assert.equal(fixture.planOrder, 0);
  assert.equal(fixture.operandOrder, 'bottom-to-top-exact-raw-bytes-no-normalization');
  assert.equal(fixture.bindings.sourceLockingBytecode.byteLength, 35);
  assert.equal(fixture.bytes.sourceLockingBytecode[0], 0xaa);
  assert.equal(fixture.bytes.sourceLockingBytecode[1], 0x20);
  assert.equal(fixture.bytes.sourceLockingBytecode.at(-1), 0x87);
  assert.equal(fixture.bindings.transaction.sha256, digest(fixture.bytes.transaction));
  assert.equal(fixture.bindings.sourceOutputs.sha256, digest(fixture.bytes.sourceOutputs));
  assert.deepEqual(decodeMinimalDataPushes(fixture.bytes.unlockingBytecode), [...fixture.bytes.operandsBottomToTop, fixture.bytes.redeemBytecode]);
});

test('minimal-push encoder rejects nonminimal and oversized encodings without normalizing', () => {
  assert.deepEqual([...encodeMinimalDataPush(Uint8Array.of())], [0x00]);
  assert.deepEqual([...encodeMinimalDataPush(Uint8Array.of(0x00))], [0x01, 0x00]);
  assert.deepEqual([...encodeMinimalDataPush(Uint8Array.of(0x80))], [0x01, 0x80]);
  assert.deepEqual([...encodeMinimalDataPush(Uint8Array.of(1))], [0x51]);
  assert.deepEqual([...encodeMinimalDataPush(Uint8Array.of(0x81))], [0x4f]);
  assert.deepEqual(decodeMinimalDataPushes(Uint8Array.of(0x01, 0x00)), [Uint8Array.of(0x00)]);
  assert.deepEqual(decodeMinimalDataPushes(Uint8Array.of(0x01, 0x80)), [Uint8Array.of(0x80)]);
  assert.throws(() => decodeMinimalDataPushes(Uint8Array.of(0x4c, 1, 0x22)), /nonminimal OP_PUSHDATA1/);
  assert.throws(() => decodeMinimalDataPushes(Uint8Array.of(1)), /truncated push payload/);
  assert.throws(() => encodeMinimalDataPush(new Uint8Array(MAX_DATA_PUSH_BYTES + 1)), /exceeds/);
});

test('fixture rejects source substitution, ABI drift, and operand normalization', () => {
  const plan = loadSourceSetPlan(planId);
  assert.throws(() => deriveExecutionFixture({ sourcePlan: plan, operandsBottomToTop: [Uint8Array.of(1)] }), /operand count/);
  assert.throws(() => deriveExecutionFixtureFromRawHex({ planId, operandsBottomToTop: ['AA', '00', '00', '00'] }), /lowercase/);
  const forged = { ...plan, redeemBytecode: Uint8Array.from(plan.redeemBytecode, (byte, index) => index === 0 ? byte ^ 1 : byte) };
  assert.throws(() => deriveExecutionFixture({ sourcePlan: forged, operandsBottomToTop: Array.from({ length: 4 }, () => Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) }), /redeem binding drift/);
  assert.notDeepEqual(p2sh32LockingBytecode(plan.redeemBytecode), p2sh32LockingBytecode(forged.redeemBytecode));
});

test('component-walk rejects symlink and path escape', () => {
  const sandbox = mkdtempSync(resolve(tmpdir(), 'cohort-fixture-'));
  try {
    mkdirSync(resolve(sandbox, 'nested'));
    writeFileSync(resolve(sandbox, 'nested', 'safe'), 'ok');
    symlinkSync(resolve(sandbox, 'nested', 'safe'), resolve(sandbox, 'linked'));
    assert.equal(assertContainedRegularFile(sandbox, 'nested/safe').endsWith('/nested/safe'), true);
    assert.throws(() => assertContainedRegularFile(sandbox, '../escape'), /escapes|invalid/);
    assert.throws(() => assertContainedRegularFile(sandbox, 'linked'), /symlink/);
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
});

test('compact roster records bind a fixture and retain execution-ceiling violations', () => {
  const ordinary = deriveExecutionFixtureFromRawHex({ planId, operandsBottomToTop: ['000000000000000000000000', '020000000000000000000000', '030000000000000000000000', '050000000000000000000000'] });
  const ordinaryIdentity = epochIdentity(ordinary);
  const record = buildFixtureRosterRecord({ epochIdentity: ordinaryIdentity, fixture: ordinary });
  assert.equal(record.executionAllowed, false);
  assert.equal(Object.hasOwn(record, 'transactionHex'), false);
  assert.equal(record.preflightLimitViolation.redeem, false);
  assert.equal(record.fixtureKey, deriveEpochFixtureKey({ epochIdentity: ordinaryIdentity, fixture: ordinary }));
  assert.equal(record.fixtureKey, fixtureKeyFor(ordinaryIdentity));
  assert.match(record.fixtureKey, /^fixture:[0-9a-f]{64}$/u);
  const byteMutated = clone(ordinary);
  byteMutated.bindings.redeemBytecode.sha256 = 'f'.repeat(64);
  assert.equal(deriveEpochFixtureKey({ epochIdentity: ordinaryIdentity, fixture: byteMutated }), record.fixtureKey);
  assert.throws(() => buildFixtureRosterRecord({ fixtureKey: 'fixture:stale', epochIdentity: ordinaryIdentity, fixture: ordinary }), /input shape/);
  assert.throws(() => buildFixtureRosterRecord({ epochIdentity: epochIdentity(ordinary, { planId: 'wrong' }), fixture: ordinary }), /planId drift/);
  assert.equal(record.contentDigest.canonicalization, DOMAIN_DIGEST_CANONICALIZATION);
  assert.equal(record.contentDigest.frame, DOMAIN_DIGEST_FRAME);
  const rosterProjection = clone(record); rosterProjection.contentDigest = null;
  assert.equal(record.contentDigest.value, framedDigest(record.contentDigest.domain, rosterProjection));
  const large = deriveExecutionFixtureFromRawHex({ planId: 'physical-plan:arm:optimized:m31-d6-direct-toom6-v1:relation:e-mac:v1', operandsBottomToTop: ['00000000', '01000000', '02000000', '03000000'] });
  const largeRecord = buildFixtureRosterRecord({ epochIdentity: epochIdentity(large, { constructionIndex: 3, constructionId: 'algebra-component:m31-d6-x6-minus-5-v2', caseKey: 'algebra-component:m31-d6-x6-minus-5-v2|relation:e-mac|category:valid|0|0', caseDigest: 'b'.repeat(64) }), fixture: large });
  assert.equal(largeRecord.preflightLimitViolation.redeem, true);
  assert.equal(largeRecord.status, 'preflight-limit-violation');
});

test('fixture identities accept actual frozen corpus keys and reject aliases or malformed keys', () => {
  const corpus = JSON.parse(readFileSync(new URL('./canonical-corpus.v2.json', import.meta.url), 'utf8'));
  const sourceSet = JSON.parse(readFileSync(new URL('../../source-set-v1/source-set.v1.json', import.meta.url), 'utf8'));
  for (const construction of corpus.constructions) {
    const entry = construction.cases.find((item) => item.relationId === 'relation:e-mac' && item.categoryId === 'category:valid' && item.caseIndex === 0 && item.vectorAttempt === 0);
    const tag = /:((?:m31|m61|m89)-d\d+)-/u.exec(construction.constructionId)[1];
    const planIdForConstruction = sourceSet.planIndex.find((item) => item.planId.includes(tag) && item.planId.includes(':relation:e-mac:v1')).planId;
    const plan = loadSourceSetPlan(planIdForConstruction);
    const fixture = deriveExecutionFixture({ sourcePlan: plan, operandsBottomToTop: Array.from({ length: plan.expectedOperandCount }, () => Uint8Array.of()) });
    const identity = {
      constructionIndex: construction.constructionIndex,
      constructionId: construction.constructionId,
      planId: plan.planId,
      caseKey: entry.caseKey,
      caseDigest: entry.caseDigest.value,
      vectorAttempt: entry.vectorAttempt,
    };
    assert.match(buildFixtureRosterRecord({ epochIdentity: identity, fixture }).fixtureKey, /^fixture:[0-9a-f]{64}$/u);
  }
  const ordinary = deriveExecutionFixtureFromRawHex({ planId, operandsBottomToTop: ['000000000000000000000000', '020000000000000000000000', '030000000000000000000000', '050000000000000000000000'] });
  const reject = (caseKey, expected = /caseKey/) => assert.throws(() => buildFixtureRosterRecord({ epochIdentity: epochIdentity(ordinary, { caseKey }), fixture: ordinary }), expected);
  reject('case:ordinary-0', /five pipe-delimited/);
  reject('algebra-component:m89-d2-x2-plus-1-v2/relation:e-mac/category:valid/0/0', /five pipe-delimited/);
  reject('algebra-component:m89-d2-x2-plus-1-v2|relation:e-mac|category:valid|00|0', /numeric fields/);
  reject('algebra-component:m89-d2-x2-plus-1-v2|relation:e-mac|category:valid|0|01', /numeric fields/);
  reject('algebra-component:m89-d2-x2-plus-1-v2|relation:unknown|category:valid|0|0', /relationId/);
  reject('algebra-component:m89-d2-x2-plus-1-v2|relation:e-mac|category:unknown|0|0', /categoryId/);
  reject('algebra-component:m89-d2-x2-plus-1-v2|relation:e-mac|category:valid|0|0\u0000', /numeric fields/);
  reject('algebra-component:m89-d2-x2-plus-1-v2|relation:e-mac|category:valid|0|0|tail', /five pipe-delimited/);
});

test('four engine records are strict snapshots, not execution evidence', () => {
  const value = currentSnapshot();
  assert.equal(value.status, 'snapshot-only-no-vm-execution-no-build');
  assert.deepEqual(value.engines.map((engine) => engine.engineId), ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
  assert.equal(assertEngineSnapshotSet(value), true);
  assert.equal(validateSchema(value), true, ajv.errorsText(validateSchema.errors));
  const artifacts = buildEngineArtifactRecords({ snapshot: value });
  assert.equal(artifacts.length, 4);
  const buildStatuses = ['no-build-applicable', 'package-integrity-source-pinned-ready', 'fresh-build-attestation-pending', 'fresh-build-attestation-pending'];
  const capabilityStatuses = ['required', 'required', 'required', 'required-or-explicit-unsupported'];
  for (const [index, artifact] of artifacts.entries()) {
    assert.equal(validateSchema(artifact), true, ajv.errorsText(validateSchema.errors));
    assert.equal(artifact.schema, 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/engine-artifact/v2');
    assert.equal(artifact.artifactId, `artifact:gate-b:execution-epoch-v2:${artifact.engineId.replace('engine:', '')}`);
    assert.equal(artifact.path, `research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engines/${artifact.engineId.replace('engine:', '')}.v2.json`);
    assert.equal(artifact.status, buildStatuses[index]);
    assert.equal(artifact.build.attestation, buildStatuses[index]);
    assert.equal(artifact.capabilityStatus, capabilityStatuses[index]);
    assert.deepEqual(artifact.capabilities, ENGINE_CAPABILITIES);
    assert.equal(artifact.contentDigest.canonicalization, DOMAIN_DIGEST_CANONICALIZATION);
    assert.equal(artifact.contentDigest.frame, DOMAIN_DIGEST_FRAME);
    assert.equal(artifact.sourceInputs.some((input) => input.path === artifact.path), false);
    const artifactProjection = clone(artifact); delete artifactProjection.contentDigest;
    assert.equal(artifact.contentDigest.value, framedDigest(artifact.contentDigest.domain, artifactProjection));
    assert.equal(Object.hasOwn(artifact, 'repositoryInformationalStatus'), false);
    const forbiddenSerializedDiagnostic = clone(artifact);
    forbiddenSerializedDiagnostic.repositoryInformationalStatus = [];
    assert.equal(validateSchema(forbiddenSerializedDiagnostic), false, 'artifact schema must reject serialized informational worktree state');
  }
  assert.equal(canonicalPrettyJson({ z: [2, 1], a: { y: 1, x: 2 } }), '{\n  "a": {\n    "x": 2,\n    "y": 1\n  },\n  "z": [\n    2,\n    1\n  ]\n}\n');
  const informationalOnly = clone(value);
  informationalOnly.engines[0].repositorySnapshots[0].informationalWorktree.statusPorcelainSha256 = 'f'.repeat(64);
  assert.equal(
    canonicalPrettyJson(buildEngineArtifactRecords({ snapshot: informationalOnly })),
    canonicalPrettyJson(artifacts),
    'in-memory whole-worktree diagnostics must not affect any serialized engine bytes'
  );
  for (const engine of value.engines) {
    assert.equal(engine.capability.executionStatus, 'execution-not-authorized');
    assert.equal(engine.capability.unsupportedCountsAsExecution, false);
    assert.equal(engine.capability.unsupportedCountsAsAgreement, false);
  }
});

test('engine source/hash, stale build, environment, and unsupported mutations fail closed', () => {
  const value = currentSnapshot();
  const sourceSubstitution = clone(value);
  sourceSubstitution.engines[1].sourceSetBinding = { ...sourceSubstitution.engines[1].sourceSetBinding };
  sourceSubstitution.engines[1].sourceSetBinding.rootRawSha256 = '0'.repeat(64);
  assert.throws(() => assertEngineSnapshotSet(sourceSubstitution), /source-set substitution/);
  const stale = clone(value); stale.engines[2].build.attestation = 'fresh-build-attested';
  assert.equal(validateSchema(stale), false);
  assert.throws(() => assertEngineSnapshotSet(stale), /build attestation drift/);
  const binary = clone(value); binary.engines[3].build.binary.rawSha256 = 'f'.repeat(64);
  assert.equal(validateSchema(binary), true);
  assert.throws(() => assertExactCurrentEngineSnapshot(binary), /exact source\/binary\/status drift/);
  const missingEnv = clone(value); delete missingEnv.engines[3].environment.LEANBCH_SECP;
  assert.equal(validateSchema(missingEnv), false);
  const policy = clone(value); policy.engines[3].capability.unsupportedCountsAsAgreement = true;
  assert.throws(() => assertEngineSnapshotSet(policy), /unsupported policy/);
  const artifacts = buildEngineArtifactRecords({ snapshot: value });
  const mismatchedCapability = clone(artifacts[1]); mismatchedCapability.capabilityStatus = 'semantic-reference-only';
  assert.equal(validateSchema(mismatchedCapability), false);
  const wrongFrame = clone(artifacts[0]); wrongFrame.contentDigest.frame = 'wrong';
  assert.equal(validateSchema(wrongFrame), false);
  assert.deepEqual(classifyTerminalOutcome({ terminalStatus: 'explicit-unsupported', phase: 'script-engine' }), { terminalStatus: 'explicit-unsupported', phase: 'explicit-unsupported', countsAsExecution: false, countsAsAgreement: false });
  assert.deepEqual(classifyTerminalOutcome({ terminalStatus: 'supported', phase: 'outer-transaction-or-token' }), { terminalStatus: 'supported', phase: 'outer-transaction-or-token', countsAsExecution: true, countsAsAgreement: false });
  assert.doesNotThrow(() => assertExactCurrentEngineSnapshot(value));
});

test('archived build attestations finalize only BCHN and LeanBCH without VM evidence', () => {
  const value = currentSnapshot();
  const attestations = archivedBuildAttestations(value);
  const artifacts = buildEngineArtifactRecords({ snapshot: value, buildAttestations: attestations });
  assert.deepEqual(artifacts.map((artifact) => artifact.status), ['no-build-applicable', 'package-integrity-source-pinned-ready', 'fresh-build-attested-unexecuted', 'fresh-build-attested-unexecuted']);
  assert.equal(artifacts[0].buildAttestation, null);
  assert.equal(artifacts[1].buildAttestation, null);
  for (const artifact of artifacts.slice(2)) {
    assert.equal(artifact.build.attestation, 'fresh-build-attested-unexecuted');
    assert.equal(artifact.buildAttestation.exitCode, 0);
    assert.deepEqual(artifact.buildAttestation.exitCodes, artifact.buildAttestation.commands.map(() => 0));
    assert.equal(artifact.buildAttestation.executionAllowed, false);
    assert.equal(artifact.buildAttestation.vmEvidence, null);
    assert.equal(validateSchema(artifact), true, ajv.errorsText(validateSchema.errors));
  }
});

test('build-attestation finalization rejects missing, stale, failed, forged, and VM-evidence records', () => {
  const value = currentSnapshot();
  const valid = archivedBuildAttestations(value);
  const missing = clone(valid); delete missing['engine:leanbch'];
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: missing }), /buildAttestations shape/);
  const staleInput = clone(valid); staleInput['engine:bchn'].inputs[0].rawSha256 = '0'.repeat(64);
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: staleInput }), /input bytes drift/);
  const changedOutput = clone(valid); changedOutput['engine:leanbch'].outputs = clone(changedOutput['engine:leanbch'].outputs); changedOutput['engine:leanbch'].outputs[0].rawSha256 = '0'.repeat(64);
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: changedOutput }), /output bytes drift/);
  const nonzero = clone(valid); nonzero['engine:bchn'].exitCodes[0] = 1;
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: nonzero }), /exit must be zero/);
  const omittedParallelism = clone(valid); delete omittedParallelism['engine:bchn'].commands[0].environment.NINJAFLAGS;
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: omittedParallelism }), /command or cwd drift/);
  const wrapperSubstitution = clone(valid); wrapperSubstitution['engine:leanbch'].commands[1].argv[0] = '/home/toorik/.elan/bin/lake';
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: wrapperSubstitution }), /command or cwd drift/);
  const environmentSubstitution = clone(valid); environmentSubstitution['engine:bchn'].commands[0].environment.PATH = '/usr/bin:/bin';
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: environmentSubstitution }), /command or cwd drift/);
  const staleToolchain = clone(valid); staleToolchain['engine:leanbch'].toolchain[0].stdoutSha256 = '0'.repeat(64);
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: staleToolchain }), /toolchain drift/);
  const logMutation = clone(valid); logMutation['engine:bchn'].logs[0].rawSha256 = '0'.repeat(64);
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: logMutation }), /log digest value drift/);
  const vmEvidence = clone(valid); vmEvidence['engine:bchn'].vmEvidence = { verdict: 'true' };
  assert.throws(() => buildEngineArtifactRecords({ snapshot: value, buildAttestations: vmEvidence }), /must not contain VM evidence/);
});
