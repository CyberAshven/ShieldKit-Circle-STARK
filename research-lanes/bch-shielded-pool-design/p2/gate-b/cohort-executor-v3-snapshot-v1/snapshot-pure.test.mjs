import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import * as Generate from './generate.mjs';
import * as Production from './production-api.mjs';
import * as Open from './snapshot-open.mjs';
import {
  deriveFixtureRowsFromSnapshot,
  encodeAllEndpointStdin,
  isAuthoritySnapshot,
  isRuntimeAttestation,
  openRetainedDataflowSnapshot,
  deriveRecoveryStableProjection,
  deriveSnapshotDigestBinding,
  validateAuthoritySnapshot,
  validateRuntimeAttestation,
} from './snapshot-open.mjs';
import * as Pure from './snapshot-pure.mjs';
import {
  ENDPOINT_ORDER,
  PURE_BOUNDARY,
  canonicalBytes,
  unsafeDeriveAuthoritySnapshotBindings as deriveAuthoritySnapshotBindings,
  unsafeDigestRecord as digestRecord,
  unsafeEncodeEndpointStdinFromRows as encodeEndpointStdinFromRows,
  unsafeMakeByteRecord as makeByteRecord,
  unsafeMakeIdempotentDescriptorReceipt as makeIdempotentDescriptorReceipt,
  omit,
  parseCanonicalJsonBytes,
  unsafeValidateCaptureRunStructure as validateCaptureRunStructure,
  unsafeValidateRuntimeMetadataStructure as validateRuntimeMetadataStructure,
  unsafeVerifyByteRecord as verifyByteRecord,
} from './snapshot-pure.mjs';

const packageDir = path.dirname(new URL(import.meta.url).pathname);

test('pure boundary contains no filesystem/process execution APIs and no writers', () => {
  const source = fs.readFileSync(new URL('./snapshot-pure.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:fs|node:path|child_process|readFile|statSync|realpathSync|spawn\(/u);
  assert.deepEqual(PURE_BOUNDARY, { filesystemCalls: false, childProcessCalls: false, vmCalls: false, postOpenPathReads: false, endpointTupleLength: 5, fixtureRows: 4732, eligibleRows: 4608 });
  assert.equal(Pure.makeAuthoritySnapshot, undefined);
  assert.equal(Pure.attestRuntime, undefined);
  assert.equal(Pure.attestAuthority, undefined);
  assert.equal(Pure.sealCaptureObservation, undefined);
  for (const name of ['digestRecord', 'deriveAuthoritySnapshotBindings', 'deriveFixtureRowsFromSnapshot', 'encodeAllEndpointStdin', 'deriveSnapshotDigestBinding', 'deriveRecoveryStableProjection', 'validateAuthoritySnapshotStructure', 'validateRuntimeMetadataStructure', 'validateCaptureRunStructure']) assert.equal(Pure[name], undefined, `unsafe structural export gate: ${name}`);
});

test('canonical parser rejects compact, duplicate-key, and mutated bytes', () => {
  assert.deepEqual(parseCanonicalJsonBytes(canonicalBytes({ b: 2, a: 1 })), { a: 1, b: 2 });
  assert.throws(() => parseCanonicalJsonBytes(Buffer.from('{"a":1}\n')), /canonical/);
  assert.throws(() => parseCanonicalJsonBytes(Buffer.from('{\n  "a": 1,\n  "a": 1\n}\n')), /canonical/);
});

test('manifest imports expose no attestation writers and reject forged production inputs', async () => {
  const manifestPath = path.join(packageDir, 'MANIFEST.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  // The test harness itself is manifest-covered but is intentionally excluded
  // from this import set. Every production .mjs is statically imported above,
  // so import-time side effects are exercised without a recursive child sweep.
  const moduleItems = manifest.files.filter(file => file.path.endsWith('.mjs') && !file.path.endsWith('.test.mjs'));
  const modules = Object.freeze({ 'generate.mjs': Generate, 'production-api.mjs': Production, 'snapshot-open.mjs': Open, 'snapshot-pure.mjs': Pure });
  assert.deepEqual(moduleItems.map(item => path.basename(item.path)).sort(), Object.keys(modules).sort());
  assert.deepEqual(Object.keys(Production).sort(), ['SNAPSHOT_OPEN_BOUNDARY', 'deriveFixtureRowsFromSnapshot', 'deriveRecoveryStableProjection', 'deriveSnapshotDigestBinding', 'encodeAllEndpointStdin', 'isAuthoritySnapshot', 'isRuntimeAttestation', 'openRetainedDataflowSnapshot', 'validateAuthoritySnapshot', 'validateRuntimeAttestation'].sort());
  for (const item of moduleItems) for (const name of Object.keys(modules[path.basename(item.path)])) assert.doesNotMatch(name, /^(?:attest|brand|sealCapture|makeAuthoritySnapshot)/iu, `${item.path} exports writer ${name}`);
  assert.equal(Production.sealCaptureObservation, undefined);
  assert.equal(Production.attestRuntime, undefined);
  assert.equal(Production.attestAuthority, undefined);
  assert.throws(() => Production.validateRuntimeAttestation({ fd: 9, uid: 0, readlinkTarget: '/forged/exe' }), /membership/);
  assert.throws(() => Production.validateAuthoritySnapshot({ runtime: { fd: 9, uid: 0, readlinkTarget: '/forged/exe' } }), /membership/);
});

test('opener reads each retained authority path once and derives plans from those records', { timeout: 600000 }, () => {
  const counts = new Map();
  const readCounts = new Map();
  const fdPaths = new Map();
  const originalOpenSync = fs.openSync;
  const originalReadSync = fs.readSync;
  fs.openSync = function countedOpenSync(file, ...args) {
    const key = typeof file === 'string' ? file : `fd:${String(file)}`;
    const fd = originalOpenSync.call(this, file, ...args);
    counts.set(key, (counts.get(key) ?? 0) + 1); fdPaths.set(fd, key); return fd;
  };
  fs.readSync = function countedReadSync(fd, ...args) {
    const key = fdPaths.get(fd) ?? `fd:${String(fd)}`;
    readCounts.set(key, (readCounts.get(key) ?? 0) + 1);
    return originalReadSync.call(this, fd, ...args);
  };
  let snapshot;
  try { snapshot = openRetainedDataflowSnapshot(); } finally { fs.openSync = originalOpenSync; fs.readSync = originalReadSync; }
  try {
    assert.equal(counts.get('/proc/self/exe'), 1);
    const workspace = path.resolve(packageDir, '../../../../..');
    const expectedPaths = [
      'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog.v1.json',
      'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/fixture-roster.v2.json',
      'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/work-item-roster.v2.json',
      'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.json',
      'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json',
      'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/campaign.v2.json',
      'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json',
    ].map(relative => path.resolve(workspace, relative));
    for (const plan of snapshot.sourcePlans) {
      const hexRecord = snapshot.records[`plan-hex:${plan.planId}`];
      const mapRecord = snapshot.records[`plan-map:${plan.planId}`];
      assert(hexRecord && mapRecord, `${plan.planId} retained records`);
      expectedPaths.push(path.resolve(workspace, hexRecord.path), path.resolve(workspace, mapRecord.path));
      const hexText = new TextDecoder('utf-8', { fatal: true }).decode(hexRecord.bytes);
      assert(Buffer.from(hexText.slice(0, -1), 'hex').equals(plan.redeemBytes), `${plan.planId} plan bytes retained binding`);
      assert.equal(mapRecord.contentDigest.value, plan.sourceMapDigest.value, `${plan.planId} map digest retained binding`);
    }
    assert.equal(expectedPaths.length, 91);
    assert.equal([...counts.values()].reduce((total, count) => total + count, 0), 92);
    for (const retainedPath of expectedPaths) assert.equal(counts.get(retainedPath), 1, `${retainedPath} opened once`);
    assert.equal(counts.size, 92); // 91 retained files plus /proc/self/exe.
    assert.equal(readCounts.get('/proc/self/exe'), 3, '/proc/self/exe initial read plus two live-brand rereads');
    for (const retainedPath of expectedPaths) assert.equal(readCounts.get(retainedPath), 1, `${retainedPath} read once`);
  } finally { snapshot.runtime.descriptor.close(); }
});

test('catalog rejects a changed but self-resealed frozen source file', { timeout: 600000 }, () => {
  const sourceWorkspace = path.resolve(packageDir, '../../../../..');
  const isolatedWorkspace = fs.mkdtempSync(path.join('/tmp', 'snapshot-v1-catalog-kat-'));
  const copyDirectory = relative => fs.cpSync(path.join(sourceWorkspace, relative), path.join(isolatedWorkspace, relative), { recursive: true });
  try {
    copyDirectory('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2');
    copyDirectory('research-lanes/bch-shielded-pool-design/p2/source-set-v1');
    const catalogRelative = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog.v1.json';
    const catalogTarget = path.join(isolatedWorkspace, catalogRelative); fs.mkdirSync(path.dirname(catalogTarget), { recursive: true }); fs.copyFileSync(path.join(sourceWorkspace, catalogRelative), catalogTarget);
    const fixtureRelative = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/fixture-roster.v2.json';
    const fixturePath = path.join(isolatedWorkspace, fixtureRelative); const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
    fixture.counts = { ...fixture.counts, total: fixture.counts.total + 1 }; fixture.contentDigest = digestRecord(omit(fixture), fixture.contentDigest.domain); fs.writeFileSync(fixturePath, canonicalBytes(fixture));
    assert.throws(() => openRetainedDataflowSnapshot({ workspace: isolatedWorkspace }), /catalog raw binding/);
  } finally { fs.rmSync(isolatedWorkspace, { recursive: true, force: true }); }
});

test('opener rejects a raw-reformatted pinned catalog', { timeout: 600000 }, () => {
  const sourceWorkspace = path.resolve(packageDir, '../../../../..');
  const isolatedWorkspace = fs.mkdtempSync(path.join('/tmp', 'snapshot-v1-catalog-format-kat-'));
  const copyDirectory = relative => fs.cpSync(path.join(sourceWorkspace, relative), path.join(isolatedWorkspace, relative), { recursive: true });
  try {
    copyDirectory('research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2');
    copyDirectory('research-lanes/bch-shielded-pool-design/p2/source-set-v1');
    const catalogRelative = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog.v1.json';
    const catalogTarget = path.join(isolatedWorkspace, catalogRelative); fs.mkdirSync(path.dirname(catalogTarget), { recursive: true });
    const catalog = JSON.parse(fs.readFileSync(path.join(sourceWorkspace, catalogRelative), 'utf8')); fs.writeFileSync(catalogTarget, `${JSON.stringify(catalog)}\n`);
    assert.throws(() => openRetainedDataflowSnapshot({ workspace: isolatedWorkspace }), /canonical JSON|pinned raw bytes/);
  } finally { fs.rmSync(isolatedWorkspace, { recursive: true, force: true }); }
});

test('opener rejects symlinked intermediate authority path components', { timeout: 600000 }, () => {
  const sourceWorkspace = path.resolve(packageDir, '../../../../..');
  const isolatedWorkspace = fs.mkdtempSync(path.join('/tmp', 'snapshot-v1-symlink-kat-'));
  try {
    const freezeRelative = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2'; const sourceSetRelative = 'research-lanes/bch-shielded-pool-design/p2/source-set-v1';
    fs.cpSync(path.join(sourceWorkspace, freezeRelative), path.join(isolatedWorkspace, freezeRelative), { recursive: true }); fs.cpSync(path.join(sourceWorkspace, sourceSetRelative), path.join(isolatedWorkspace, sourceSetRelative), { recursive: true });
    const catalogRelative = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog.v1.json'; const catalogTarget = path.join(isolatedWorkspace, catalogRelative); fs.mkdirSync(path.dirname(catalogTarget), { recursive: true }); fs.copyFileSync(path.join(sourceWorkspace, catalogRelative), catalogTarget);
    const gateB = path.join(isolatedWorkspace, 'research-lanes/bch-shielded-pool-design/p2/gate-b'); const movedGateB = path.join(isolatedWorkspace, 'gate-b-real');
    fs.renameSync(gateB, movedGateB); fs.symlinkSync(movedGateB, gateB, 'dir');
    assert.throws(() => openRetainedDataflowSnapshot({ workspace: isolatedWorkspace }), /symlink path component/);
  } finally { fs.rmSync(isolatedWorkspace, { recursive: true, force: true }); }
});

test('opener rejects a post-open descriptor target mismatch', { timeout: 600000 }, () => {
  const sourceWorkspace = path.resolve(packageDir, '../../../../..');
  const catalogPath = path.resolve(sourceWorkspace, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog.v1.json');
  const originalOpenSync = fs.openSync;
  fs.openSync = function outsideTarget(file, ...args) { return file === catalogPath ? originalOpenSync.call(this, '/etc/hosts', ...args) : originalOpenSync.call(this, file, ...args); };
  try { assert.throws(() => openRetainedDataflowSnapshot(), /descriptor target/); }
  finally { fs.openSync = originalOpenSync; }
});

test('retained authority derives exact fixture and codec cardinalities and rejects mutants', { timeout: 600000 }, () => {
  const snapshot = openRetainedDataflowSnapshot();
  try {
    assert.equal(validateAuthoritySnapshot(snapshot).fixtures, 4732);
    assert.equal(isAuthoritySnapshot(snapshot), true);
    assert.equal(isRuntimeAttestation(snapshot.runtime), true);
    assert.deepEqual(deriveSnapshotDigestBinding(snapshot), { kind: 'cohort-executor-v3-retained-byte-snapshot-digest-binding/v1', snapshotKind: snapshot.kind, snapshotDigest: snapshot.snapshotDigest, valuesRootDigest: snapshot.valuesRootDigest.value, authorityDigestDomain: 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority' });
    const recovery = deriveRecoveryStableProjection(snapshot);
    assert.equal(recovery.kind, 'cohort-executor-v3-retained-byte-recovery-projection/v1');
    assert.equal(Object.hasOwn(recovery.runtime, 'fd'), false);
    assert.equal(Object.hasOwn(recovery.runtime, 'descriptor'), false);
    assert.equal(recovery.snapshotDigest, snapshot.snapshotDigest);
    assert.match(snapshot.snapshotDigest, /^[0-9a-f]{64}$/u);
    assert.match(snapshot.valuesRootDigest.value, /^[0-9a-f]{64}$/u);
    assert.equal(snapshot.sourcePlans.length, 42);
    assert(snapshot.records.authorityCatalog, 'retained authority catalog record');
    assert.equal(snapshot.runtime.procSelfExe, '/proc/self/exe');
    const codecs = encodeAllEndpointStdin(snapshot);
    assert.deepEqual(codecs.map(codec => codec.byteLength), [0, 0, 29510638, 29192684, 29215724]);
    assert.deepEqual(codecs.map(codec => codec.readyRows), [4608, 4608, 4608, 4608, 4608]);
    const codecByte = codecs[2].bytes[0]; codecs[2].bytes[0] ^= 0xff;
    const freshCodecs = encodeAllEndpointStdin(snapshot);
    assert.equal(freshCodecs[2].bytes[0], codecByte);
    assert.notEqual(freshCodecs[2].bytes, codecs[2].bytes);

    const rows = deriveFixtureRowsFromSnapshot(snapshot);
    const rowByte = rows.fixtureRows[0].fixture.bytes.transaction[0]; rows.fixtureRows[0].fixture.bytes.transaction[0] ^= 0xff;
    const freshRows = deriveFixtureRowsFromSnapshot(snapshot);
    assert.equal(freshRows.fixtureRows[0].fixture.bytes.transaction[0], rowByte);
    assert.notEqual(freshRows.fixtureRows[0].fixture.bytes.transaction, rows.fixtureRows[0].fixture.bytes.transaction);
    assert.throws(() => encodeEndpointStdinFromRows('engine:native', 'secondary', rows.byEngine['engine:native'].filter(row => !row.preflightLimitViolation)), /matrix/);
    assert.throws(() => encodeEndpointStdinFromRows('engine:unknown', 'primary', rows.byEngine['engine:native'].filter(row => !row.preflightLimitViolation)), /matrix/);

    const mutatedCorpus = { ...snapshot.values.corpus, counts: { ...snapshot.values.corpus.counts, total: snapshot.values.corpus.counts.total + 1 } };
    assert.throws(() => deriveAuthoritySnapshotBindings({ values: { ...snapshot.values, corpus: mutatedCorpus }, records: snapshot.records, runtime: snapshot.runtime, sourcePlans: snapshot.sourcePlans }), /value binding/);
    const firstFixture = snapshot.values.fixtureRoster.records[0];
    const mutatedFixture = { ...snapshot.values.fixtureRoster, records: [{ ...firstFixture, status: firstFixture.status === 'ready' ? 'mutated' : 'ready' }, ...snapshot.values.fixtureRoster.records.slice(1)] };
    assert.throws(() => deriveAuthoritySnapshotBindings({ values: { ...snapshot.values, fixtureRoster: mutatedFixture }, records: snapshot.records, runtime: snapshot.runtime, sourcePlans: snapshot.sourcePlans }), /value binding/);

    const digest = snapshot.values.corpus.contentDigest;
    const tinyBytes = canonicalBytes({ contentDigest: digest, value: 1 });
    const tiny = makeByteRecord({ key: 'kat.json', path: 'kat.json', mediaType: 'application/json', bytes: tinyBytes, contentDigest: digest, stat: { dev: 1, ino: 2, mode: 33152, uid: 3, gid: 3, nlink: 1, size: tinyBytes.length } });
    assert.throws(() => verifyByteRecord({ ...tiny, contentDigest: { ...tiny.contentDigest, algorithm: 'md5' } }, { canonicalJson: true }), /algorithm/);
    assert.throws(() => validateRuntimeMetadataStructure({ ...snapshot.runtime, rawSha256: '0'.repeat(64) }), /runtime exact bytes/);
    assert.throws(() => validateRuntimeMetadataStructure({ ...snapshot.runtime, stat: { ...snapshot.runtime.stat, uid: snapshot.runtime.stat.uid + 1 } }), /descriptor stat binding/);
    assert.throws(() => validateRuntimeMetadataStructure({ ...snapshot.runtime, executable: '/forged/executable' }), /identity binding/);
    assert.throws(() => validateRuntimeMetadataStructure({ ...snapshot.runtime, descriptor: { ...snapshot.runtime.descriptor, state: 'closed', receipt: { state: 'closed' } } }), /live descriptor/);
    const forgedRuntime = { ...snapshot.runtime, stat: { ...snapshot.runtime.stat, uid: snapshot.runtime.stat.uid + 1 }, executable: '/forged/executable', executableIdentity: { ...snapshot.runtime.executableIdentity, readlinkTarget: '/forged/executable' } };
    assert.throws(() => validateRuntimeAttestation(forgedRuntime), /membership/);
    assert.throws(() => validateAuthoritySnapshot({ ...snapshot, runtime: forgedRuntime }), /membership/);

    const corpusByte = snapshot.records.corpus.bytes[0]; snapshot.records.corpus.bytes[0] ^= 0xff;
    assert.equal(isAuthoritySnapshot(snapshot), false);
    assert.throws(() => validateAuthoritySnapshot(snapshot), /raw bytes/);
    assert.throws(() => deriveFixtureRowsFromSnapshot(snapshot), /raw bytes/);
    assert.throws(() => encodeAllEndpointStdin(snapshot), /raw bytes/);
    snapshot.records.corpus.bytes[0] = corpusByte;
    assert.equal(isAuthoritySnapshot(snapshot), true);
    const redeemByte = snapshot.sourcePlans[0].redeemBytes[0]; snapshot.sourcePlans[0].redeemBytes[0] ^= 0xff;
    assert.equal(isAuthoritySnapshot(snapshot), false);
    assert.throws(() => deriveFixtureRowsFromSnapshot(snapshot), /redeem bytes/);
    snapshot.sourcePlans[0].redeemBytes[0] = redeemByte;
    const runtimeByte = snapshot.runtime.bytes[0]; snapshot.runtime.bytes[0] ^= 0xff;
    assert.equal(isRuntimeAttestation(snapshot.runtime), false);
    assert.throws(() => validateAuthoritySnapshot(snapshot), /membership/);
    snapshot.runtime.bytes[0] = runtimeByte;
    assert.equal(isAuthoritySnapshot(snapshot), true);

    const originalReadSync = fs.readSync; const runtimeFd = snapshot.runtime.descriptor.fd; let injectedSameFdMutation = false;
    try {
      fs.readSync = function sameFdMutation(fd, buffer, offset, length, position) {
        const count = originalReadSync.call(fs, fd, buffer, offset, length, position);
        if (fd === runtimeFd && !injectedSameFdMutation && count > 0) { buffer[offset] ^= 0xff; injectedSameFdMutation = true; }
        return count;
      };
      assert.equal(isAuthoritySnapshot(snapshot), false);
      assert.equal(injectedSameFdMutation, true);
    } finally { fs.readSync = originalReadSync; }
    assert.equal(isAuthoritySnapshot(snapshot), true);

    const stat = { dev: 1, ino: 100, mode: 33152, uid: 3, gid: 3, nlink: 1, size: 0 };
    const events = ['stdin-opened', 'stdin-fsynced', 'spawn-observed', 'stdout-fsynced', 'stderr-fsynced', 'close-observed', 'capture-sealed'];
    const endpoint = (key, ordinal) => { const [engineId, endpointRole] = key.split('/'); const stream = role => ({ role, bytes: Buffer.alloc(0), byteLength: 0, rawSha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', fsynced: true, stat: { ...stat, ino: stat.ino + ordinal } }); const streamForEvent = { 'stdin-opened': 'stdin', 'stdin-fsynced': 'stdin', 'spawn-observed': 'endpoint', 'stdout-fsynced': 'stdout', 'stderr-fsynced': 'stderr', 'close-observed': 'endpoint', 'capture-sealed': 'endpoint' }; const checkpoints = events.map((event, index) => ({ sequence: ordinal * events.length + index, event, monotonicNanoseconds: String(ordinal * events.length + index + 1), stream: streamForEvent[event], stat: streamForEvent[event] === 'endpoint' ? null : { ...stat, ino: stat.ino + ordinal } })); return { endpointOrdinal: ordinal, engineId, endpointRole, stdin: stream('stdin'), stdout: stream('stdout'), stderr: stream('stderr'), outcome: { captureClosed: true }, checkpoints }; };
    const endpoints = ENDPOINT_ORDER.map(endpoint);
    const run = { snapshotKind: snapshot.kind, snapshotDigest: snapshot.snapshotDigest, endpoints };
    assert.equal(validateCaptureRunStructure(run, snapshot.snapshotDigest), true);
    assert.throws(() => validateCaptureRunStructure({ ...run, checkpoints: [] }, snapshot.snapshotDigest), /capture run fields/);
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: endpoints.map(endpointValue => ({ ...endpointValue, checkpoints: endpointValue.checkpoints.map(checkpoint => checkpoint.event === 'spawn-observed' ? { ...checkpoint, stat: { ...stat } } : checkpoint) })) }, snapshot.snapshotDigest), /endpoint checkpoint stat/);
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: [...endpoints].reverse() }, snapshot.snapshotDigest), /matrix/);
    assert.throws(() => validateCaptureRunStructure({ ...run, snapshotDigest: 'a'.repeat(64) }, snapshot.snapshotDigest), /digest/);
    const repeatedMonotonic = endpoints.map(endpointValue => ({ ...endpointValue, checkpoints: endpointValue.checkpoints.map(checkpoint => ({ ...checkpoint, monotonicNanoseconds: '1' })) }));
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: repeatedMonotonic }, snapshot.snapshotDigest), /monotonic/);
    const wrongStream = endpoints.map(endpointValue => ({ ...endpointValue, stdin: { ...endpointValue.stdin, role: 'stderr' } }));
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: wrongStream }, snapshot.snapshotDigest), /stream role/);
    const reorderedEvents = endpoints.map(endpointValue => ({ ...endpointValue, checkpoints: [endpointValue.checkpoints[1], endpointValue.checkpoints[0], ...endpointValue.checkpoints.slice(2)] }));
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: reorderedEvents }, snapshot.snapshotDigest), /event order/);
    const mismatchedCheckpointStat = endpoints.map(endpointValue => ({ ...endpointValue, checkpoints: endpointValue.checkpoints.map(checkpoint => checkpoint.event === 'stdin-fsynced' ? { ...checkpoint, stat: { ...checkpoint.stat, ino: checkpoint.stat.ino + 1 } } : checkpoint) }));
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: mismatchedCheckpointStat }, snapshot.snapshotDigest), /terminal stream binding/);
    const openOutcome = endpoints.map(endpointValue => ({ ...endpointValue, outcome: { captureClosed: false } }));
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: openOutcome }, snapshot.snapshotDigest), /closed outcome/);
    const extraOutcome = endpoints.map(endpointValue => ({ ...endpointValue, outcome: { captureClosed: true, open: false } }));
    assert.throws(() => validateCaptureRunStructure({ ...run, endpoints: extraOutcome }, snapshot.snapshotDigest), /closed outcome/);

    snapshot.runtime.descriptor.close();
    assert.equal(snapshot.runtime.descriptor.close().idempotent, true);
    assert.equal(isRuntimeAttestation(snapshot.runtime), false);
    assert.equal(isAuthoritySnapshot(snapshot), false);
    assert.throws(() => validateRuntimeAttestation(snapshot.runtime), /membership/);
    assert.throws(() => validateAuthoritySnapshot(snapshot), /membership/);
    assert.throws(() => deriveSnapshotDigestBinding(snapshot), /membership/);
  } finally { snapshot.runtime.descriptor.close(); }
});

test('descriptor receipt is fstat-bound and idempotent', () => {
  let closeCalls = 0;
  const stat = { dev: 1, ino: 2, mode: 33152, uid: 3, gid: 3, nlink: 1, size: 7 };
  const descriptor = makeIdempotentDescriptorReceipt({ fd: 9, label: 'kat', before: stat, closeImpl: () => { closeCalls += 1; } });
  const first = descriptor.close(); const second = descriptor.close();
  assert.equal(first, second); assert.equal(closeCalls, 1); assert.equal(descriptor.state, 'closed');
});
