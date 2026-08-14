/*
 * Production trust boundary for snapshot-v1.
 *
 * The runtime/authority WeakSets and their writers are intentionally
 * module-local. Public exports below are only the filesystem opener,
 * membership predicates, and live-membership validation/transform wrappers.
 * snapshot-pure.mjs contains structural transforms and never brands a value.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  canonicalBytes, deepFreeze, unsafeDeriveAuthoritySnapshotBindings as deriveAuthoritySnapshotBindings,
  unsafeDeriveRecoveryStableProjection as deriveRecoveryStableProjectionStructure,
  unsafeDeriveSnapshotDigestBinding as deriveSnapshotDigestBindingStructure,
  unsafeEncodeAllEndpointStdin as encodeAllEndpointStdinStructure,
  unsafeMakeByteRecord as makeByteRecord, unsafeMakeIdempotentDescriptorReceipt as makeIdempotentDescriptorReceipt, parseCanonicalJsonBytes,
  AUTHORITY_CATALOG_DIGEST_DOMAIN, SNAPSHOT_KIND, unsafeValidateAuthorityCatalogStructure as validateAuthorityCatalogStructure, unsafeValidateAuthoritySnapshotStructure as validateAuthoritySnapshotStructure,
  unsafeValidateRuntimeMetadataStructure as validateRuntimeMetadataStructure, unsafeVerifyByteRecord as verifyByteRecord, VALUE_DIGEST_DOMAINS,
} from './snapshot-pure.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspaceDefault = path.resolve(here, '../../../../..');
const AUTHORITY_CATALOG_RELATIVE = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog.v1.json';
const PINNED_AUTHORITY_CATALOG_DIGEST = '0b1b796f31a8f7ef94ff3223c224c52ae89a677675df10929973c5c9012d28ef';
const PINNED_AUTHORITY_CATALOG_RAW_SHA256 = '0e60c0c215e2231a27c2677bf57930e6afd0f111b60313f07935ca7b15e0975f';
const PINNED_AUTHORITY_CATALOG_BYTE_LENGTH = 63967;
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const fail = message => { throw new Error(`cohort-executor-v3-snapshot-v1 production-api: ${message}`); };
const assert = (condition, message) => { if (!condition) fail(message); };
const noFollow = fs.constants.O_NOFOLLOW ?? 0;
const readOnly = fs.constants.O_RDONLY;

const runtimeBrand = new WeakSet();
const runtimeState = new WeakMap();
const authorityBrand = new WeakSet();
const authorityState = new WeakMap();
const authorityValidationCache = new WeakMap();
const STAT_FIELDS = Object.freeze(['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size']);
const sameStat = (left, right) => STAT_FIELDS.every(field => left?.[field] === right?.[field]);

function cloneValue(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, cloneValue(child)]));
  return value;
}

function cloneRuntime(runtime) {
  return deepFreeze({ ...runtime, bytes: Buffer.from(runtime.bytes), stat: { ...runtime.stat }, executableIdentity: { ...runtime.executableIdentity }, descriptor: runtime.descriptor });
}

function cloneRecord(record) {
  return { ...record, bytes: Buffer.from(record.bytes), stat: { ...record.stat }, contentDigest: cloneValue(record.contentDigest) };
}

function cloneAuthoritySnapshot(snapshot, runtime = null) {
  return deepFreeze({
    ...snapshot,
    values: cloneValue(snapshot.values),
    records: Object.fromEntries(Object.entries(snapshot.records).map(([key, record]) => [key, cloneRecord(record)])),
    sourcePlans: snapshot.sourcePlans.map(plan => cloneValue(plan)),
    runtime: runtime ?? cloneRuntime(snapshot.runtime),
  });
}

function abs(workspace, relative) {
  assert(typeof relative === 'string' && relative.length > 0 && !path.isAbsolute(relative) && !relative.split('/').includes('..'), `unsafe relative path ${relative}`);
  const root = fs.realpathSync(workspace); const candidate = path.resolve(root, relative); const relativeCandidate = path.relative(root, candidate);
  assert(relativeCandidate && !relativeCandidate.startsWith(`..${path.sep}`) && !path.isAbsolute(relativeCandidate), `workspace containment ${relative}`);
  let current = root; const components = relativeCandidate.split(path.sep);
  for (const [index, component] of components.entries()) { current = path.join(current, component); const info = fs.lstatSync(current); assert(!info.isSymbolicLink(), `${relative} symlink path component`); if (index < components.length - 1) assert(info.isDirectory(), `${relative} intermediate directory`); }
  assert(fs.realpathSync(candidate) === candidate, `${relative} realpath containment`);
  return Object.freeze({ root, candidate });
}
function assertDescriptorTarget(fd, expectedPath, root, label) {
  const actual = fs.realpathSync(`/proc/self/fd/${fd}`);
  assert(actual === expectedPath, `${label} descriptor target`);
  if (root !== null) {
    const relative = path.relative(root, actual);
    assert(relative && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative), `${label} descriptor containment`);
  }
}
function statShape(stat) { const output = { dev: Number(stat.dev), ino: Number(stat.ino), mode: Number(stat.mode), uid: Number(stat.uid), gid: Number(stat.gid), nlink: Number(stat.nlink), size: Number(stat.size) }; assert(Object.values(output).every(value => Number.isSafeInteger(value)), 'seven-field fstat'); assert(output.dev >= 0 && output.ino >= 0 && output.mode >= 0 && output.uid >= 0 && output.gid >= 0 && output.nlink === 1 && output.size >= 0, 'fstat ranges'); return Object.freeze(output); }
function sameRetainedStat(before, after, label) { for (const key of STAT_FIELDS) assert(before[key] === after[key], `${label} changed while retained`); }
function readFd(fd, length) { const output = Buffer.alloc(length); let offset = 0; while (offset < length) { const count = fs.readSync(fd, output, offset, length - offset, offset); assert(count > 0, 'short retained descriptor read'); offset += count; } return output; }
function rereadLiveExecutable(expected) {
  const before = statShape(fs.fstatSync(expected.fd));
  if (!sameStat(before, expected.stat)) return false;
  const bytes = readFd(expected.fd, expected.byteLength);
  const after = statShape(fs.fstatSync(expected.fd));
  if (!sameStat(after, expected.stat)) return false;
  return bytes.length === expected.byteLength && sha(bytes) === expected.rawSha256 && Buffer.isBuffer(expected.backing.bytes) && bytes.equals(expected.backing.bytes);
}

function retainedFile(workspace, relative, { mediaType = 'application/octet-stream', canonical = false, requireRawCanonical = false, digestDomain = null } = {}) {
  const { root, candidate: file } = abs(workspace, relative); const fd = fs.openSync(file, readOnly | noFollow); let before; let bytes;
  try {
    assertDescriptorTarget(fd, file, root, relative);
    before = fs.fstatSync(fd); assert(before.isFile() && Number.isSafeInteger(before.size) && before.size >= 0 && (!Number.isInteger(before.nlink) || before.nlink === 1), `${relative} regular single-link file`);
    bytes = readFd(fd, before.size); const after = fs.fstatSync(fd); sameRetainedStat(statShape(before), statShape(after), relative);
  } finally { fs.closeSync(fd); }
  let contentDigest = null; let canonicalBody = bytes;
  if (canonical) {
    let value;
    try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch (error) { fail(`${relative} invalid UTF-8/JSON: ${error.message}`); }
    canonicalBody = canonicalBytes(value); if (requireRawCanonical) assert(bytes.equals(canonicalBody), `${relative} retained canonical JSON bytes`);
    const domain = digestDomain ?? value.contentDigest?.domain; assert(domain && value.contentDigest?.domain === domain, `${relative} content digest domain`); contentDigest = value.contentDigest;
  }
  const record = makeByteRecord({ key: relative, path: relative, bytes: canonicalBody, mediaType, stat: statShape(before), contentDigest, sourceRawSha256: sha(bytes), sourceByteLength: bytes.length });
  if (canonical) verifyByteRecord(record, { canonicalJson: true, digestDomain, label: relative });
  return record;
}

function attestRuntime(runtime) {
  validateRuntimeMetadataStructure(runtime);
  const backing = cloneRuntime(runtime);
  const publicRuntime = cloneRuntime(runtime);
  runtimeBrand.add(publicRuntime);
  runtimeState.set(publicRuntime, Object.freeze({
    backing,
    descriptor: publicRuntime.descriptor, fd: publicRuntime.descriptor.fd, stat: Object.freeze({ ...backing.stat }),
    descriptorBefore: Object.freeze({ ...backing.descriptor.before }), descriptorAfter: Object.freeze({ ...backing.descriptor.after }),
    procSelfExe: backing.procSelfExe, executable: backing.executable, executableRealpath: backing.executableRealpath,
    processExecPath: backing.processExecPath, executableIdentity: Object.freeze({ ...backing.executableIdentity }),
    rawSha256: backing.rawSha256, byteLength: backing.byteLength,
  }));
  return publicRuntime;
}

function isLiveRuntime(runtime) {
  const expected = runtimeState.get(runtime);
  if (!runtimeBrand.has(runtime) || !expected || runtime?.descriptor !== expected.descriptor || runtime.descriptor.state !== 'open' || runtime.descriptor.fd !== expected.fd) return false;
  if (runtime.byteLength !== expected.byteLength || runtime.rawSha256 !== expected.rawSha256 || !Buffer.isBuffer(runtime.bytes) || sha(runtime.bytes) !== expected.rawSha256) return false;
  if (!sameStat(runtime.stat, expected.stat) || !sameStat(runtime.descriptor.before, expected.descriptorBefore) || !sameStat(runtime.descriptor.after, expected.descriptorAfter)) return false;
  try { if (!rereadLiveExecutable(expected)) return false; } catch { return false; }
  return runtime.procSelfExe === expected.procSelfExe && runtime.executable === expected.executable && runtime.executableRealpath === expected.executableRealpath && runtime.processExecPath === expected.processExecPath && runtime.executableIdentity?.procSelfExe === expected.executableIdentity.procSelfExe && runtime.executableIdentity?.readlinkTarget === expected.executableIdentity.readlinkTarget && runtime.executableIdentity?.realpath === expected.executableIdentity.realpath && runtime.executableIdentity?.processExecPath === expected.executableIdentity.processExecPath;
}

function attestAuthority(snapshot, runtime = snapshot.runtime) {
  assert(isLiveRuntime(runtime), 'authority requires live runtime attestation');
  const publicSnapshot = cloneAuthoritySnapshot(snapshot, runtime);
  authorityBrand.add(publicSnapshot); authorityState.set(publicSnapshot, Object.freeze({ backing: snapshot, runtime, descriptor: runtime.descriptor, snapshotDigest: snapshot.snapshotDigest }));
  return publicSnapshot;
}

function hasLiveAuthorityBrand(snapshot) {
  const expected = authorityState.get(snapshot);
  return authorityBrand.has(snapshot) && Boolean(expected) && snapshot?.runtime === expected.runtime && snapshot.runtime?.descriptor === expected.descriptor && snapshot.runtime.descriptor?.state === 'open' && snapshot.snapshotDigest === expected.snapshotDigest && isLiveRuntime(snapshot.runtime);
}

function retainedRuntime() {
  const procSelfExe = '/proc/self/exe';
  const executable = fs.readlinkSync(procSelfExe); const executableRealpath = fs.realpathSync(procSelfExe); const processExecPath = fs.realpathSync(process.execPath);
  assert(executableRealpath === processExecPath, '/proc/self/exe executable identity');
  const fd = fs.openSync(procSelfExe, readOnly); let before; let bytes;
  try { assertDescriptorTarget(fd, executableRealpath, null, procSelfExe); before = fs.fstatSync(fd); assert(before.isFile() && Number.isSafeInteger(before.size) && before.size > 0, '/proc/self/exe regular executable'); bytes = readFd(fd, before.size); const after = fs.fstatSync(fd); sameRetainedStat(statShape(before), statShape(after), procSelfExe); }
  catch (error) { try { fs.closeSync(fd); } catch {} throw error; }
  const stat = statShape(before); const descriptor = makeIdempotentDescriptorReceipt({ fd, label: procSelfExe, before: stat, closeImpl: descriptorFd => { const after = statShape(fs.fstatSync(descriptorFd)); sameRetainedStat(stat, after, procSelfExe); fs.closeSync(descriptorFd); return { after }; } });
  const runtime = Object.freeze({ procSelfExe, executable, executableRealpath, processExecPath, executableIdentity: { procSelfExe, readlinkTarget: executable, realpath: executableRealpath, processExecPath }, rawSha256: sha(bytes), byteLength: bytes.length, bytes: Buffer.from(bytes), stat, descriptor, version: process.version, platform: process.platform, arch: process.arch });
  return attestRuntime(runtime);
}

function sourcePlanRecords(workspace, sourceSetValue, sourceSetRawSha256) {
  assert(Array.isArray(sourceSetValue.planIndex) && sourceSetValue.planIndex.length === 42, 'source-set plan cardinality');
  const records = {};
  const plans = sourceSetValue.planIndex.map(entry => {
    const hexRecord = retainedFile(workspace, `research-lanes/bch-shielded-pool-design/p2/source-set-v1/${entry.hexPath}`, { mediaType: 'text/plain' }); const mapRelative = `research-lanes/bch-shielded-pool-design/p2/source-set-v1/${entry.mapPath}`; const mapRecord = retainedFile(workspace, mapRelative, { mediaType: 'application/json', canonical: true, digestDomain: entry.sourceMapDigest.domain });
    records[`plan-hex:${entry.planId}`] = hexRecord; records[`plan-map:${entry.planId}`] = mapRecord;
    const text = new TextDecoder('utf-8', { fatal: true }).decode(hexRecord.bytes); assert(/^[0-9a-f]+\n$/u.test(text), `${entry.planId} hex artifact grammar`); const redeemBytes = Buffer.from(text.slice(0, -1), 'hex'); assert(redeemBytes.length === entry.bytecodeBytes && sha(redeemBytes) === entry.bytecodeSha256, `${entry.planId} bytecode binding`);
    const map = parseCanonicalJsonBytes(mapRecord.bytes, mapRelative); return Object.freeze({ planId: entry.planId, planOrder: entry.orderIndex, redeemBytes, expectedOperandCount: Number(map.instructions?.[0]?.irTypedContract?.transientStackContract?.typedTransientItems?.[1]?.value), sourceMapDigest: entry.sourceMapDigest, sourceSetBinding: Object.freeze({ rootPath: 'source-set.v1.json', rootRawSha256: sourceSetRawSha256, contentDigest: sourceSetValue.contentDigest?.value ?? null, planIndexEntrySha256: sha(Buffer.from(JSON.stringify(entry), 'utf8')) }), hexKey: hexRecord.key, mapKey: mapRecord.key });
  });
  return Object.freeze({ plans: Object.freeze(plans), records: Object.freeze(records) });
}

function createAuthoritySnapshot(input) {
  assert(input.records.authorityCatalog.sourceRawSha256 === PINNED_AUTHORITY_CATALOG_RAW_SHA256 && input.records.authorityCatalog.sourceByteLength === PINNED_AUTHORITY_CATALOG_BYTE_LENGTH, 'authority catalog pinned raw bytes');
  const catalog = verifyByteRecord(input.records.authorityCatalog, { canonicalJson: true, digestDomain: AUTHORITY_CATALOG_DIGEST_DOMAIN, label: 'authority catalog' });
  validateAuthorityCatalogStructure(catalog, input.records, input.sourcePlans, PINNED_AUTHORITY_CATALOG_DIGEST);
  const runtimeBacking = runtimeState.get(input.runtime)?.backing;
  assert(runtimeBacking && runtimeBrand.has(input.runtime), 'authority runtime backing');
  const internalInput = { ...input, runtime: runtimeBacking };
  const bindings = deriveAuthoritySnapshotBindings(internalInput); const snapshot = deepFreeze({ kind: SNAPSHOT_KIND, values: bindings.values, valuesRootDigest: bindings.valuesRootDigest, records: internalInput.records, runtime: internalInput.runtime, sourcePlans: internalInput.sourcePlans, snapshotDigest: bindings.snapshotDigest });
  const publicSnapshot = attestAuthority(snapshot, input.runtime); validateAuthoritySnapshot(publicSnapshot); return publicSnapshot;
}

export function openRetainedDataflowSnapshot({ workspace = workspaceDefault } = {}) {
  const freeze = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2'; const values = {}; const records = {}; const catalogRecord = retainedFile(workspace, AUTHORITY_CATALOG_RELATIVE, { mediaType: 'application/json', canonical: true, requireRawCanonical: true, digestDomain: AUTHORITY_CATALOG_DIGEST_DOMAIN }); const catalog = parseCanonicalJsonBytes(catalogRecord.bytes, AUTHORITY_CATALOG_RELATIVE); records.authorityCatalog = catalogRecord;
  assert(catalogRecord.sourceRawSha256 === PINNED_AUTHORITY_CATALOG_RAW_SHA256 && catalogRecord.sourceByteLength === PINNED_AUTHORITY_CATALOG_BYTE_LENGTH, 'authority catalog pinned raw bytes');
  const jsons = { fixtureRoster: `${freeze}/fixture-roster.v2.json`, workItemRoster: `${freeze}/work-item-roster.v2.json`, corpus: `${freeze}/canonical-corpus.v2.json`, epoch: `${freeze}/execution-epoch.v2.json`, campaign: `${freeze}/campaign.v2.json`, sourceSet: 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json' };
  for (const [key, relative] of Object.entries(jsons)) { const record = retainedFile(workspace, relative, { mediaType: 'application/json', canonical: true, digestDomain: VALUE_DIGEST_DOMAINS[key] }); records[key] = record; values[key] = parseCanonicalJsonBytes(record.bytes, relative); }
  const source = sourcePlanRecords(workspace, values.sourceSet, records.sourceSet.sourceRawSha256); const sourcePlans = source.plans; Object.assign(records, source.records); validateAuthorityCatalogStructure(catalog, records, sourcePlans, PINNED_AUTHORITY_CATALOG_DIGEST);
  return createAuthoritySnapshot({ values, records, runtime: retainedRuntime(), sourcePlans });
}

function requireLiveRuntime(runtime) { assert(isLiveRuntime(runtime), 'runtime attestation membership/live descriptor'); return runtime; }
function requireLiveAuthority(snapshot) {
  assert(hasLiveAuthorityBrand(snapshot), 'authority snapshot membership/live descriptor');
  const cached = authorityValidationCache.get(snapshot);
  const result = validateAuthoritySnapshotStructure(snapshot, { includeFixtureRows: !cached, skipFixtureDerivation: Boolean(cached) });
  if (!cached) authorityValidationCache.set(snapshot, Object.freeze({ snapshotDigest: snapshot.snapshotDigest, fixtureRows: result.fixtureRows }));
  return { result, fixtureRows: cached?.fixtureRows ?? result.fixtureRows };
}

export const isRuntimeAttestation = value => isLiveRuntime(value);
export const isAuthoritySnapshot = value => { if (!hasLiveAuthorityBrand(value)) return false; try { requireLiveAuthority(value); return true; } catch { return false; } };
export function validateRuntimeAttestation(runtime) { requireLiveRuntime(runtime); validateRuntimeMetadataStructure(runtime); return true; }
export function validateAuthoritySnapshot(snapshot) { const { result } = requireLiveAuthority(snapshot); const { fixtureRows: _ignored, ...publicResult } = result; return Object.freeze(publicResult); }
export function deriveSnapshotDigestBinding(snapshot) { requireLiveAuthority(snapshot); return deriveSnapshotDigestBindingStructure(snapshot); }
export function deriveRecoveryStableProjection(snapshot) { requireLiveAuthority(snapshot); return deriveRecoveryStableProjectionStructure(snapshot); }
export function deriveFixtureRowsFromSnapshot(snapshot) { const { fixtureRows } = requireLiveAuthority(snapshot); return deepFreeze(cloneValue(fixtureRows)); }
export function encodeAllEndpointStdin(snapshot) { const { fixtureRows } = requireLiveAuthority(snapshot); return deepFreeze(cloneValue(encodeAllEndpointStdinStructure(snapshot, fixtureRows))); }

export const SNAPSHOT_OPEN_BOUNDARY = Object.freeze({ postOpenPathReads: false, runtimeProvenance: '/proc/self/exe', retainedPlans: 42, retainedFixtureRows: 4732, retainedEligibleRowsPerEngine: 4608, writersExported: false, captureProvenance: 'none-in-snapshot-v1-structural-only' });
