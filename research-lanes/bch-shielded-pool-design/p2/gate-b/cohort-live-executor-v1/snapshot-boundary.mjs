import {
  ENDPOINTS,
  EXTERNAL_B_JOIN_STATUS,
  RUNTIME_EXECUTABLE,
  SCHEMA_VERSION,
  assertDigest,
  assertExactKeys,
  assertSnapshotStat,
  assertSnapshotBinding,
  assertRuntimeExecutableProjection,
  deriveRetainedDescriptorInventory,
  domainDigest,
  invariant,
  recoveryStableProjection,
  stdinBindingRootDigest,
} from './model.mjs';
import { createHash } from 'node:crypto';

function copyBytes(bytes, label) {
  invariant(bytes instanceof Uint8Array, `${label} must be a Uint8Array supplied by the caller`);
  return new Uint8Array(bytes);
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function rehashCallerBytes(bytes) {
  const copied = copyBytes(bytes, 'bytes');
  // Returning bytes would pair a mutable view with a stale digest. The copy is
  // intentionally private; callers receive only immutable scalar metadata.
  return Object.freeze({ sha256: sha256Bytes(copied), byteLength: copied.byteLength });
}

export function bindStdinBytes(input) {
  assertExactKeys(input, ['ordinal', 'id', 'role', 'codec', 'readyRows', 'bytes'], 'stdin byte input');
  const endpoint = ENDPOINTS[input.ordinal];
  invariant(endpoint && input.id === endpoint.id && input.role === endpoint.role, 'stdin byte input endpoint mismatch');
  invariant(typeof input.codec === 'string' && input.codec.length > 0, 'stdin byte input codec is required');
  invariant(input.readyRows === 4608, 'stdin byte input readyRows must be 4608');
  const copied = copyBytes(input.bytes, 'stdin byte input bytes');
  return Object.freeze({
    ordinal: input.ordinal,
    id: input.id,
    role: input.role,
    codec: input.codec,
    readyRows: input.readyRows,
    sha256: sha256Bytes(copied),
    byteLength: copied.byteLength,
  });
}

export function assertRehashedStdinBytes(binding, bytes) {
  const computed = bindStdinBytes({
    ordinal: binding.ordinal,
    id: binding.id,
    role: binding.role,
    codec: binding.codec,
    readyRows: binding.readyRows,
    bytes,
  });
  invariant(computed.sha256 === binding.sha256 && computed.byteLength === binding.byteLength, 'caller bytes do not match durable stdin binding');
  return computed;
}

export function projectRuntimeExecutable(record) {
  assertExactKeys(record, ['id', 'role', 'rawSha256', 'byteLength', 'stat'], 'runtime executable structural input');
  invariant(record.id === RUNTIME_EXECUTABLE.id && record.role === RUNTIME_EXECUTABLE.role, 'runtime executable structural input must be the exact retained runtime executable');
  assertDigest(record.rawSha256, 'runtime executable structural input.rawSha256');
  invariant(Number.isSafeInteger(record.byteLength) && record.byteLength >= 0, 'runtime executable structural input.byteLength must be a non-negative safe integer');
  assertSnapshotStat(record.stat, 'runtime executable structural input.stat');
  invariant(record.stat.size === String(record.byteLength), 'runtime executable structural input.stat.size must exactly equal byteLength');
  const projection = {
    id: record.id,
    role: record.role,
    rawSha256: record.rawSha256,
    byteLength: record.byteLength,
    stat: Object.freeze({ ...record.stat }),
  };
  const complete = Object.freeze({
    ...projection,
    executableIdentityDigest: domainDigest('runtime-executable-identity', projection),
  });
  assertRuntimeExecutableProjection(complete);
  return complete;
}

export function retainedDescriptorInventory(binding) {
  return Object.freeze(deriveRetainedDescriptorInventory(binding).map((entry) => Object.freeze({ ...entry })));
}

export function prepareSnapshotBinding(input) {
  assertExactKeys(input, [
    'a0Digest', 'a1Digest', 'snapshotDigest', 'valuesRootDigest', 'catalogBindingDigest',
    'runtimeExecutable', 'stdinInputs',
  ], 'snapshot preparation input');
  for (const key of ['a0Digest', 'a1Digest', 'snapshotDigest', 'valuesRootDigest', 'catalogBindingDigest']) assertDigest(input[key], `snapshot input.${key}`);
  const runtimeExecutableProjection = projectRuntimeExecutable(input.runtimeExecutable);
  invariant(Array.isArray(input.stdinInputs) && input.stdinInputs.length === ENDPOINTS.length, 'snapshot preparation requires five stdin inputs');
  const stdinBindings = input.stdinInputs.map((entry, ordinal) => {
    invariant(entry.ordinal === ordinal, 'stdin inputs must be in exact endpoint order');
    return bindStdinBytes(entry);
  });
  const incomplete = {
    schemaVersion: SCHEMA_VERSION,
    a0Digest: input.a0Digest,
    a1Digest: input.a1Digest,
    snapshotDigest: input.snapshotDigest,
    valuesRootDigest: input.valuesRootDigest,
    catalogBindingDigest: input.catalogBindingDigest,
    runtimeExecutableProjection,
    // This package cannot possess the future private snapshot brand. It can
    // therefore project recovery structure only, never an external B join.
    snapshotAdapterBranded: false,
    externalBJoinStatus: EXTERNAL_B_JOIN_STATUS,
    stdinBindings,
    stdinBindingRootDigest: stdinBindingRootDigest(stdinBindings),
  };
  const binding = Object.freeze({
    ...incomplete,
    recoveryStableDigest: domainDigest('snapshot-stable-projection', recoveryStableProjection(incomplete)),
  });
  assertSnapshotBinding(binding);
  return binding;
}
