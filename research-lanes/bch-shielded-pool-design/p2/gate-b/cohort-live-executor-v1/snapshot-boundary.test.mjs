import assert from 'node:assert/strict';
import test from 'node:test';
import { ENDPOINTS, assertSnapshotBinding, domainDigest } from './model.mjs';
import {
  assertRehashedStdinBytes,
  bindStdinBytes,
  prepareSnapshotBinding,
  projectRuntimeExecutable,
  rehashCallerBytes,
} from './snapshot-boundary.mjs';

const digest = (label) => domainDigest('snapshot-boundary-test', label);
const stat = (n) => ({ dev: n, ino: n, mode: '0600', uid: '1', gid: '1', nlink: '1', size: n });
const stdinInputs = () => ENDPOINTS.map(({ ordinal, id, role }) => ({ ordinal, id, role, codec: 'rows-v1', readyRows: 4608, bytes: Uint8Array.of(ordinal, 1, 2, 3) }));
const runtimeExecutable = (byteLength = 2) => ({
  id: '/proc/self/exe',
  role: 'runtime-executable',
  rawSha256: digest(`runtime-raw-${byteLength}`),
  byteLength,
  stat: stat(String(byteLength)),
});

test('rehash caller bytes returns scalar metadata only, never a mutable byte view', () => {
  const source = Uint8Array.of(1, 2, 3);
  const rehashed = rehashCallerBytes(source);
  assert.deepEqual(Object.keys(rehashed).sort(), ['byteLength', 'sha256']);
  assert.equal('bytes' in rehashed, false);
  const originalDigest = rehashed.sha256;
  source[0] = 99;
  assert.notEqual(rehashCallerBytes(source).sha256, originalDigest);
  const binding = bindStdinBytes({ ordinal: 0, id: 'native-primary', role: 'primary', codec: 'rows-v1', readyRows: 4608, bytes: Uint8Array.of(1, 2, 3) });
  assert.doesNotThrow(() => assertRehashedStdinBytes(binding, Uint8Array.of(1, 2, 3)));
  assert.throws(() => assertRehashedStdinBytes(binding, Uint8Array.of(1, 2, 4)), /do not match/);
});

test('only /proc/self/exe has a strict structural recovery projection; B remains pending and non-authorizing', () => {
  const projection = projectRuntimeExecutable(runtimeExecutable());
  assert.deepEqual(Object.keys(projection).sort(), ['byteLength', 'executableIdentityDigest', 'id', 'rawSha256', 'role', 'stat']);
  assert.equal(projection.id, '/proc/self/exe');
  assert.equal(projection.role, 'runtime-executable');
  assert.equal(Object.isFrozen(projection), true);
  const common = {
    a0Digest: digest('a0'),
    a1Digest: digest('a1'),
    snapshotDigest: digest('snapshot'),
    valuesRootDigest: digest('root'),
    catalogBindingDigest: digest('catalog'),
    runtimeExecutable: runtimeExecutable(),
    stdinInputs: stdinInputs(),
  };
  const binding = prepareSnapshotBinding(common);
  assert.doesNotThrow(() => assertSnapshotBinding(binding));
  assert.equal(binding.snapshotAdapterBranded, false);
  assert.equal(binding.externalBJoinStatus, 'PENDING_NONAUTHORIZING');
  const stdinMutant = JSON.parse(JSON.stringify(binding));
  stdinMutant.stdinBindings[0].sha256 = digest('substituted-stdin');
  assert.throws(() => assertSnapshotBinding(stdinMutant), /stdin-binding root/);
  const statusMutant = JSON.parse(JSON.stringify(binding));
  statusMutant.externalBJoinStatus = 'AUTHORIZED';
  assert.throws(() => assertSnapshotBinding(statusMutant), /pending and non-authorizing/);
  const brandedMutant = JSON.parse(JSON.stringify(binding));
  brandedMutant.snapshotAdapterBranded = true;
  assert.throws(() => assertSnapshotBinding(brandedMutant), /no branded snapshot adapter/);
  const identityMutant = JSON.parse(JSON.stringify(binding));
  identityMutant.runtimeExecutableProjection.rawSha256 = digest('self-resealed-runtime-raw');
  assert.throws(() => assertSnapshotBinding(identityMutant), /executableIdentityDigest mismatch/);
  assert.throws(() => projectRuntimeExecutable({ ...runtimeExecutable(), id: 'input-catalog', role: 'catalog' }), /exact retained runtime executable/);
  assert.throws(() => projectRuntimeExecutable({ ...runtimeExecutable(), fd: 3 }), /unexpected keys/);
  assert.throws(() => prepareSnapshotBinding({ ...common, descriptorRecords: [] }), /unexpected keys/);
  assert.throws(() => prepareSnapshotBinding({ ...common, runtimeExecutable: { ...runtimeExecutable(), stat: stat('3') } }), /size/);
});
