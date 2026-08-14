/*
 * Snapshot-only dataflow for cohort-executor-v3.
 *
 * This module deliberately has no filesystem, process, child-process, path, or
 * VM imports. Every authority byte used below is supplied by the production
 * opener as a retained byte record. This module contains only structural
 * transforms and validators; production branding and observation provenance
 * live in production-api.mjs.
 */
import crypto from 'node:crypto';

// Unsafe-prefixed constructors/validators below are structural-only; the
// production opener is the sole live authority brand owner.

export const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
export const FRAME = 'utf8(domain)||0x00||canonical-json-utf8';
export const ENGINE_ORDER = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
export const ENDPOINT_ORDER = Object.freeze([
  'engine:native/primary', 'engine:libauth/primary', 'engine:bchn/primary',
  'engine:leanbch/primary', 'engine:leanbch/secondary',
]);
export const ENDPOINT_MATRIX = Object.freeze([
  Object.freeze({ endpointOrdinal: 0, engineId: 'engine:native', endpointRole: 'primary' }),
  Object.freeze({ endpointOrdinal: 1, engineId: 'engine:libauth', endpointRole: 'primary' }),
  Object.freeze({ endpointOrdinal: 2, engineId: 'engine:bchn', endpointRole: 'primary' }),
  Object.freeze({ endpointOrdinal: 3, engineId: 'engine:leanbch', endpointRole: 'primary' }),
  Object.freeze({ endpointOrdinal: 4, engineId: 'engine:leanbch', endpointRole: 'secondary' }),
]);
export const STREAM_ORDER = Object.freeze(['stdin', 'stdout', 'stderr']);
export const CHECKPOINT_STREAM_BY_EVENT = Object.freeze({
  'stdin-opened': 'stdin',
  'stdin-fsynced': 'stdin',
  'spawn-observed': 'endpoint',
  'stdout-fsynced': 'stdout',
  'stderr-fsynced': 'stderr',
  'close-observed': 'endpoint',
  'capture-sealed': 'endpoint',
});
export const METRICS = Object.freeze(['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom']);
export const FIXTURE_COUNT = 4732;
export const READY_COUNT = 4608;
export const PREFLIGHT_COUNT = 124;
export const OBLIGATION_COUNT = 18928;
export const CAPTURE_CHECKPOINT_EVENTS = Object.freeze(['stdin-opened', 'stdin-fsynced', 'spawn-observed', 'stdout-fsynced', 'stderr-fsynced', 'close-observed', 'capture-sealed']);
export const SNAPSHOT_KIND = 'cohort-executor-v3-retained-byte-snapshot/v1';
export const AUTHORITY_DIGEST_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority';
export const VALUES_ROOT_DIGEST_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/values-root';
export const AUTHORITY_CATALOG_DIGEST_DOMAIN = 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog/root';
export const VALUE_DIGEST_DOMAINS = Object.freeze({
  fixtureRoster: 'shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-roster',
  workItemRoster: 'shieldkit-labs/p2/gate-b/execution-epoch/v2/work-item-roster',
  corpus: 'shieldkit-labs/p2/gate-b/canonical-corpus/v2/root',
  epoch: 'shieldkit-labs/p2/gate-b/execution-epoch/v2/root',
  campaign: 'shieldkit-labs/p2/gate-b/campaign/v2/root',
  sourceSet: 'shieldkit-labs/p2/source-set/v1/root',
});
const VALUE_KEYS = Object.freeze(['fixtureRoster', 'workItemRoster', 'corpus', 'epoch', 'campaign', 'sourceSet']);

const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const fail = message => { throw new Error(`cohort-executor-v3-snapshot-v1: ${message}`); };
const assert = (condition, message) => { if (!condition) fail(message); };
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const HEX64 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/u;

export const canonicalize = value => Array.isArray(value)
  ? value.map(canonicalize)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(byteSort).map(key => [key, canonicalize(value[key])]))
    : value;
export const canonicalBytes = value => Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
export const omit = (value, field = 'contentDigest') => { const { [field]: _ignored, ...rest } = value; return rest; };
export const unsafeDigestRecord = (value, domain) => ({ algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value: sha(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.of(0), canonicalBytes(value)])) });

function verifyDigestMetadata(digest, label, expectedDomain = null) {
  assert(digest && typeof digest === 'object', `${label} digest metadata`);
  assert(digest.algorithm === 'sha256', `${label} digest algorithm`);
  assert(digest.canonicalization === CANONICALIZATION, `${label} digest canonicalization`);
  assert(digest.frame === FRAME, `${label} digest frame`);
  assert(typeof digest.domain === 'string' && digest.domain.length > 0, `${label} digest domain`);
  assert(HEX64.test(digest.value), `${label} digest value`);
  if (expectedDomain !== null) assert(digest.domain === expectedDomain, `${label} digest domain binding`);
  return digest;
}

function exactCanonical(left, right, label) {
  assert(JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right)), label);
}

function statShape(stat, label) {
  const fields = ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size'];
  assert(stat && fields.every(field => Number.isSafeInteger(stat[field])), `${label} seven-field fstat`);
  assert(stat.dev >= 0 && stat.ino >= 0 && stat.mode >= 0 && stat.uid >= 0 && stat.gid >= 0 && stat.nlink >= 1 && stat.size >= 0, `${label} fstat ranges`);
  return Object.freeze(Object.fromEntries(fields.map(field => [field, stat[field]])));
}
const sameStat = (left, right) => ['dev', 'ino', 'mode', 'uid', 'gid', 'nlink', 'size'].every(field => left?.[field] === right?.[field]);

function decimalNanoseconds(value, label) {
  assert(typeof value === 'string' && DECIMAL.test(value), `${label} monotonic decimal`);
  return BigInt(value);
}

function expectedRecordDigestDomain(key, sourcePlans = []) {
  if (own(VALUE_DIGEST_DOMAINS, key)) return VALUE_DIGEST_DOMAINS[key];
  if (key === 'authorityCatalog') return AUTHORITY_CATALOG_DIGEST_DOMAIN;
  if (key.startsWith('plan-map:')) return sourcePlans.find(plan => `plan-map:${plan.planId}` === key)?.sourceMapDigest?.domain ?? null;
  return null;
}

export function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) if (child && typeof child === 'object' && !Buffer.isBuffer(child)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

export function parseCanonicalJsonBytes(bytes, label = 'canonical JSON') {
  assert(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array, `${label} bytes`);
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch (error) { fail(`${label} invalid UTF-8/JSON: ${error.message}`); }
  assert(Buffer.from(bytes).equals(canonicalBytes(value)), `${label} is not canonical JSON`);
  return value;
}

export function unsafeMakeByteRecord({ key, path = null, bytes, mediaType = 'application/octet-stream', contentDigest = null, stat = null, sourceRawSha256 = null, sourceByteLength = null }) {
  assert(typeof key === 'string' && key.length > 0, 'byte record key');
  assert(path === null || typeof path === 'string', `${key} provenance path`);
  assert(Buffer.isBuffer(bytes) || bytes instanceof Uint8Array, `${key} bytes`);
  const retainedStat = statShape(stat, key);
  const body = Buffer.from(bytes);
  assert(sourceRawSha256 === null || HEX64.test(sourceRawSha256), `${key} source raw SHA-256`);
  assert(sourceByteLength === null || (Number.isSafeInteger(sourceByteLength) && sourceByteLength >= 0), `${key} source byte length`);
  const retainedSourceLength = sourceByteLength ?? body.length;
  assert(retainedStat.size === retainedSourceLength, `${key} fstat byte length`);
  if (contentDigest !== null) verifyDigestMetadata(contentDigest, `${key} content`);
  const record = { key, path, mediaType, rawSha256: sha(body), byteLength: body.length, bytes: body, sourceRawSha256: sourceRawSha256 ?? sha(body), sourceByteLength: retainedSourceLength, contentDigest, stat: retainedStat };
  return deepFreeze(record);
}

export function unsafeVerifyByteRecord(record, { canonicalJson = false, digestDomain = null, label = record?.key ?? 'byte record' } = {}) {
  assert(record && typeof record === 'object' && (Buffer.isBuffer(record.bytes) || record.bytes instanceof Uint8Array), `${label} shape`);
  statShape(record.stat, label);
  assert(record.byteLength === record.bytes.length && record.rawSha256 === sha(record.bytes), `${label} raw bytes`);
  assert(HEX64.test(record.sourceRawSha256) && Number.isSafeInteger(record.sourceByteLength) && record.sourceByteLength >= 0, `${label} source byte binding`);
  assert(record.stat.size === record.sourceByteLength, `${label} fstat byte length`);
  if (canonicalJson) {
    const value = parseCanonicalJsonBytes(record.bytes, label);
    assert(record.mediaType === 'application/json', `${label} JSON media type`);
    const digest = verifyDigestMetadata(value.contentDigest, `${label} content`, digestDomain);
    verifyDigestMetadata(record.contentDigest, `${label} retained content`, digest.domain);
    exactCanonical(record.contentDigest, digest, `${label} retained content digest binding`);
    exactCanonical(digest, unsafeDigestRecord(omit(value), digest.domain), `${label} content digest value`);
    return value;
  }
  return null;
}

const bytesEqual = (left, right) => Buffer.from(left).equals(Buffer.from(right));
const byteBinding = value => ({ byteLength: value.length, sha256: sha(value) });
const u32le = value => Buffer.from([value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff]);
const u64le = value => Buffer.from(Array.from({ length: 8 }, (_, index) => Number((BigInt(value) >> BigInt(index * 8)) & 0xffn)));
const hash256 = value => Buffer.from(crypto.createHash('sha256').update(crypto.createHash('sha256').update(value).digest()).digest());
const join = (...parts) => Buffer.concat(parts.map(part => Buffer.from(part)));
const outputLockingBytecode = Buffer.of(0x51);
const dummyOutpointHash = Buffer.alloc(32, 0x11);

function compactSize(value) {
  assert(Number.isSafeInteger(value) && value >= 0, 'CompactSize value');
  if (value < 0xfd) return Buffer.of(value);
  if (value <= 0xffff) return Buffer.of(0xfd, value & 0xff, value >>> 8);
  if (value <= 0xffffffff) return Buffer.of(0xfe, value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
  const wide = BigInt(value); return Buffer.from([0xff, ...Array.from({ length: 8 }, (_, index) => Number((wide >> BigInt(index * 8)) & 0xffn))]);
}
function minimalPush(value) {
  assert(Buffer.isBuffer(value), 'minimal push payload');
  if (value.length === 0) return Buffer.of(0);
  if (value.length === 1 && value[0] >= 1 && value[0] <= 16) return Buffer.of(0x50 + value[0]);
  if (value.length === 1 && value[0] === 0x81) return Buffer.of(0x4f);
  if (value.length <= 75) return join(Buffer.of(value.length), value);
  if (value.length <= 0xff) return join(Buffer.of(0x4c, value.length), value);
  assert(value.length <= 0xffff, 'push payload maximum'); return join(Buffer.of(0x4d, value.length & 0xff, value.length >>> 8), value);
}
function p2sh32(redeem) { return join(Buffer.of(0xaa, 0x20), hash256(redeem), Buffer.of(0x87)); }
function tx({ unlocking, sourceLocking }) {
  return join(u32le(2), Buffer.of(1), dummyOutpointHash, u32le(0), compactSize(unlocking.length), unlocking, u32le(0xffffffff), Buffer.of(1), u64le(1000), compactSize(1), outputLockingBytecode, u32le(0));
}
function sourceOutputs(sourceLocking) { return join(Buffer.of(1), u64le(1000), compactSize(sourceLocking.length), sourceLocking); }
function parseHex(text, label) { assert(typeof text === 'string' && /^[0-9a-f]*$/u.test(text) && text.length % 2 === 0, `${label} lowercase even hex`); return Buffer.from(text, 'hex'); }
function expectedOperandCount(map, label) { const value = map?.instructions?.[0]?.irTypedContract?.transientStackContract?.typedTransientItems?.[1]?.value; assert(typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value), `${label} operand count`); const count = Number(value); assert(Number.isSafeInteger(count), `${label} operand count range`); return count; }

function fixtureFromPlan(plan, entry) {
  const operands = entry.stackArgsBottomToTop.map((hex, ordinal) => parseHex(hex, `${entry.caseKey} operand ${ordinal}`));
  assert(operands.length === plan.expectedOperandCount, `${entry.caseKey} operand ABI`);
  const operandUnlocking = Buffer.concat(operands.map(minimalPush));
  const redeemPush = minimalPush(plan.redeemBytes);
  const unlocking = join(operandUnlocking, redeemPush);
  const sourceLocking = p2sh32(plan.redeemBytes);
  const transaction = tx({ unlocking, sourceLocking });
  const outputs = sourceOutputs(sourceLocking);
  const bytes = { operandsBottomToTop: operands, redeemBytecode: Buffer.from(plan.redeemBytes), operandUnlockingBytecode: operandUnlocking, redeemPush, unlockingBytecode: unlocking, sourceLockingBytecode: sourceLocking, transaction, sourceOutputs: outputs, outputLockingBytecode };
  return { artifactId: 'artifact:gate-b:cohort-freeze-v2:execution-fixture', kind: 'synthetic-one-input-one-output-p2sh32-component-fixture-v2', planId: plan.planId, planOrder: plan.planOrder, operandOrder: 'bottom-to-top-exact-raw-bytes-no-normalization', sourceSetBinding: plan.sourceSetBinding, sourceBinding: { sourceSet: plan.sourceSetBinding, executionCeiling: { bytes: 10000, sourcePath: 'src/script/vm_limits.h', sourceSymbol: 'MAX_SCRIPT_SIZE' } }, bytes, bindings: Object.fromEntries(Object.entries(bytes).map(([key, body]) => [key, Array.isArray(body) ? body.map(byteBinding) : byteBinding(body)])) };
}

function fixtureKey(identity) {
  const projection = { constructionIndex: identity.constructionIndex, constructionId: identity.constructionId, planId: identity.planId, caseKey: identity.caseKey, caseDigest: identity.caseDigest, vectorAttempt: identity.vectorAttempt };
  return `fixture:${unsafeDigestRecord(projection, 'shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture-key').value}`;
}

function fixtureRecordDigest(record) {
  const indexFields = new Set(['armId', 'trackId', 'relationId', 'categoryId', 'caseIndex', 'engineWorkItemCount']);
  const projection = Object.fromEntries(Object.entries(record).filter(([key]) => key !== 'contentDigest' && !indexFields.has(key)));
  projection.contentDigest = null;
  return unsafeDigestRecord(projection, `shieldkit-labs/p2/gate-b/execution-epoch/v2/fixture/${record.fixtureKey}`);
}

function exact(left, right, label) { assert(JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right)), label); }
function assertRecordBindings(record, fixture, label) {
  exact(record.byteBindings, fixture.bindings, `${label} byte bindings`);
  exact(record.sourceBinding, fixture.sourceBinding, `${label} source binding`);
  assert(record.fixtureKey === fixtureKey(record.epochIdentity), `${label} fixture key`);
  assert(record.contentDigest?.value === fixtureRecordDigest(record).value, `${label} record digest`);
}

export function unsafeDeriveFixtureRowsFromSnapshot(snapshot) {
  const roster = snapshot.values.fixtureRoster; const workRoster = snapshot.values.workItemRoster; const corpus = snapshot.values.corpus; const source = snapshot.values.sourceSet;
  assert(roster.records?.length === FIXTURE_COUNT && workRoster.workItems?.length === OBLIGATION_COUNT, 'fixture/work cardinality');
  const cases = new Map(corpus.constructions.flatMap(construction => construction.cases).map(entry => [entry.caseKey, entry]));
  const plans = new Map(snapshot.sourcePlans.map(plan => [plan.planId, plan])); const bases = new Map();
  for (const record of roster.records) {
    const entry = cases.get(record.epochIdentity.caseKey); assert(entry && entry.caseDigest?.value === record.epochIdentity.caseDigest, `case binding ${record.fixtureKey}`);
    const plan = plans.get(record.planId); assert(plan, `missing source plan ${record.planId}`);
    const fixture = fixtureFromPlan(plan, entry); assertRecordBindings(record, fixture, `fixture ${record.fixtureKey}`);
    const base = Object.freeze({ fixtureRecord: record, fixture, expected: entry.expected, caseEntry: entry, preflightLimitViolation: Boolean(record.preflightLimitViolation?.scriptSig || record.preflightLimitViolation?.redeem) });
    bases.set(record.fixtureKey, base);
  }
  assert(bases.size === FIXTURE_COUNT && plans.size === 42 && source.planIndex?.length === 42, 'source plan/fixture cardinality');
  const perEngine = new Map(ENGINE_ORDER.map(engineId => [engineId, []]));
  for (const work of workRoster.workItems) { const base = bases.get(work.fixtureKey); assert(base && base.fixtureRecord.planId === work.planId, `work fixture binding ${work.workItemId}`); perEngine.get(work.engineId).push(Object.freeze({ ...base, workItem: work })); }
  for (const engineId of ENGINE_ORDER) { const rows = perEngine.get(engineId); assert(rows.length === FIXTURE_COUNT, `${engineId} row cardinality`); for (let ordinal = 0; ordinal < rows.length; ordinal += 1) { assert(rows[ordinal].fixtureRecord.fixtureKey === roster.records[ordinal].fixtureKey, `${engineId} order ${ordinal}`); } }
  const preflight = roster.records.filter(record => Boolean(record.preflightLimitViolation?.scriptSig || record.preflightLimitViolation?.redeem));
  assert(preflight.length === PREFLIGHT_COUNT, 'preflight cardinality');
  return deepFreeze({ fixtureRows: Object.freeze([...bases.values()]), byEngine: Object.freeze(Object.fromEntries(ENGINE_ORDER.map(engineId => [engineId, Object.freeze(perEngine.get(engineId))]))), counts: Object.freeze({ fixtures: FIXTURE_COUNT, engines: 4, obligations: OBLIGATION_COUNT, preflightFixtures: PREFLIGHT_COUNT, executablePerEngine: READY_COUNT }) });
}

function readyRows(rows, engineId) { const ready = rows.byEngine[engineId].filter(row => !row.preflightLimitViolation); assert(ready.length === READY_COUNT, `${engineId} ready rows`); return ready; }
const hex = bytes => Buffer.from(bytes).toString('hex');
function exactRows(rows, engineId) { assert(Array.isArray(rows) && rows.length === READY_COUNT, `${engineId} codec rows`); for (const row of rows) assert(row.workItem.engineId === engineId && row.fixture && row.expected && !row.preflightLimitViolation, `${engineId} codec authority`); }
function leanLine(row, expected) { return `${expected} ${row.workItem.workItemId} ${hex(row.fixture.bytes.transaction)} ${hex(row.fixture.bytes.sourceOutputs)} 0`; }
export function unsafeEncodeEndpointStdinFromRows(engineId, endpointRole, rows) {
  const matrix = ENDPOINT_MATRIX.find(endpoint => endpoint.engineId === engineId && endpoint.endpointRole === endpointRole);
  assert(matrix, `endpoint engine/role matrix ${engineId}/${endpointRole}`);
  exactRows(rows, engineId);
  if (engineId === 'engine:native' || engineId === 'engine:libauth') return Buffer.alloc(0);
  if (engineId === 'engine:bchn') return Buffer.from(`${JSON.stringify(rows.map(row => [row.workItem.workItemId, 'cohort-freeze-v2 exact synthetic P2SH32 component fixture', '', '', hex(row.fixture.bytes.transaction), hex(row.fixture.bytes.sourceOutputs), 0]))}\n`, 'utf8');
  const expected = endpointRole === 'primary' ? row => row.expected.verdict === 'accept' ? '1' : '0' : () => 'KERNEL';
  return Buffer.from(`${rows.map(row => leanLine(row, expected(row))).join('\n')}\n`, 'utf8');
}
export function unsafeEncodeAllEndpointStdin(snapshot, prederivedRows = null) {
  const rows = prederivedRows ?? unsafeDeriveFixtureRowsFromSnapshot(snapshot); const tuple = ENDPOINT_ORDER.map(key => { const [engineId, role] = key.split('/'); const body = unsafeEncodeEndpointStdinFromRows(engineId, role, readyRows(rows, engineId)); return deepFreeze({ endpointOrdinal: ENDPOINT_ORDER.indexOf(key), engineId, endpointRole: role, codec: engineId === 'engine:native' || engineId === 'engine:libauth' ? 'module-empty-v1' : engineId === 'engine:bchn' ? 'bchn-effects-json-v1' : role === 'primary' ? 'lean-vmbconf-lines-v1' : 'lean-costprobe-kernel-lines-v1', readyRows: READY_COUNT, bytes: body, rawSha256: sha(body), byteLength: body.length }); }); return Object.freeze(tuple);
}

const descriptorStates = new WeakMap();
export function unsafeMakeIdempotentDescriptorReceipt({ fd, label, before, after = before, closeImpl = () => {} }) {
  assert(Number.isInteger(fd) && fd >= 0 && typeof label === 'string' && typeof closeImpl === 'function', 'descriptor receipt shape');
  const beforeStat = statShape(before, label); const afterStat = statShape(after, label);
  const state = { state: 'open', receipt: null }; descriptorStates.set(state, true);
  const close = () => {
    if (state.state === 'closed') return state.receipt;
    assert(descriptorStates.has(state), `${label} descriptor state`);
    const result = closeImpl(fd);
    const closedAfter = result?.after ?? afterStat;
    statShape(closedAfter, `${label} close receipt`);
    state.state = 'closed';
    state.receipt = deepFreeze({ label, fd, state: 'closed', before: { ...beforeStat }, after: { ...closedAfter }, idempotent: true });
    return state.receipt;
  };
  return deepFreeze({ label, fd, before: { ...beforeStat }, after: { ...afterStat }, get state() { return state.state; }, get receipt() { return state.receipt; }, close });
}

function captureCheckpoint(value, label) {
  assert(value && Object.keys(value).sort().join('\0') === ['event', 'monotonicNanoseconds', 'sequence', 'stat', 'stream'].join('\0'), `${label} checkpoint fields`);
  assert(value && Number.isSafeInteger(value.sequence) && value.sequence >= 0 && CAPTURE_CHECKPOINT_EVENTS.includes(value.event), `${label} checkpoint`);
  decimalNanoseconds(value.monotonicNanoseconds, label);
  assert(value.stream === CHECKPOINT_STREAM_BY_EVENT[value.event], `${label} checkpoint stream binding`);
  if (value.stream === 'endpoint') assert(value.stat === null, `${label} endpoint checkpoint stat`);
  else statShape(value.stat, `${label} checkpoint`);
  return value;
}
function validateStream(stream, expectedRole, label) {
  assert(stream && Object.keys(stream).sort().join('\0') === ['byteLength', 'bytes', 'fsynced', 'rawSha256', 'role', 'stat'].join('\0'), `${label} stream fields`);
  assert(stream && STREAM_ORDER.includes(stream.role) && stream.role === expectedRole, `${label} stream role binding`);
  assert(Buffer.isBuffer(stream.bytes) || stream.bytes instanceof Uint8Array, `${label} stream bytes`);
  assert(stream.byteLength === stream.bytes.length && stream.rawSha256 === sha(stream.bytes) && stream.fsynced === true, `${label} stream binding`);
  statShape(stream.stat, `${label} stream`);
  assert(stream.stat.size === stream.byteLength, `${label} stream fstat byte length`);
  return stream;
}
export function unsafeValidateCaptureRunStructure(captured, authoritySnapshotDigest = null) {
  assert(captured && typeof captured === 'object', 'capture structure is not an observation provenance token');
  if (authoritySnapshotDigest !== null) assert(HEX64.test(authoritySnapshotDigest) && captured.snapshotDigest === authoritySnapshotDigest, 'capture snapshot digest authority binding');
  const captureFields = Object.keys(captured).sort().join('\0');
  assert(captureFields === 'endpoints\0snapshotDigest\0snapshotKind', 'capture run fields');
  assert(captured.snapshotKind === SNAPSHOT_KIND && Array.isArray(captured.endpoints) && captured.endpoints.length === ENDPOINT_MATRIX.length, 'capture run shape');
  let previousSequence = -1; let previousMonotonic = -1n;
  for (const [ordinal, endpoint] of captured.endpoints.entries()) {
    const expected = ENDPOINT_MATRIX[ordinal];
    assert(Object.keys(endpoint).sort().join('\0') === ['checkpoints', 'endpointOrdinal', 'endpointRole', 'engineId', 'outcome', 'stderr', 'stdin', 'stdout'].join('\0'), `capture endpoint fields ${ordinal}`);
    assert(endpoint.endpointOrdinal === expected.endpointOrdinal && endpoint.engineId === expected.engineId && endpoint.endpointRole === expected.endpointRole, `capture endpoint matrix ${ordinal}`);
    assert(endpoint.outcome && Object.keys(endpoint.outcome).sort().join('\0') === 'captureClosed' && endpoint.outcome.captureClosed === true, `capture endpoint closed outcome ${ordinal}`);
    validateStream(endpoint.stdin, 'stdin', `${ENDPOINT_ORDER[ordinal]} stdin`); validateStream(endpoint.stdout, 'stdout', `${ENDPOINT_ORDER[ordinal]} stdout`); validateStream(endpoint.stderr, 'stderr', `${ENDPOINT_ORDER[ordinal]} stderr`);
    assert(Array.isArray(endpoint.checkpoints) && endpoint.checkpoints.length === CAPTURE_CHECKPOINT_EVENTS.length, `capture checkpoint count ${ordinal}`);
    const events = new Set();
    for (const [checkpointOrdinal, checkpoint] of endpoint.checkpoints.entries()) {
      captureCheckpoint(checkpoint, ENDPOINT_ORDER[ordinal]);
      assert(checkpoint.event === CAPTURE_CHECKPOINT_EVENTS[checkpointOrdinal], `capture checkpoint event order ${ENDPOINT_ORDER[ordinal]}`);
      const monotonic = decimalNanoseconds(checkpoint.monotonicNanoseconds, ENDPOINT_ORDER[ordinal]);
      events.add(checkpoint.event); assert(checkpoint.sequence > previousSequence, `capture checkpoint sequence ${ordinal}`); assert(monotonic > previousMonotonic, `capture checkpoint monotonic order ${ordinal}`);
      if (checkpoint.stream !== 'endpoint') {
        const stream = endpoint[checkpoint.stream];
        assert(sameStat(checkpoint.stat, stream.stat) && checkpoint.stat.size === stream.byteLength && stream.rawSha256 === sha(stream.bytes), `capture checkpoint terminal stream binding ${ENDPOINT_ORDER[ordinal]}/${checkpoint.event}`);
      }
      previousSequence = checkpoint.sequence; previousMonotonic = monotonic;
    }
    for (const event of CAPTURE_CHECKPOINT_EVENTS) assert(events.has(event), `capture checkpoint event ${ENDPOINT_ORDER[ordinal]}/${event}`);
    assert(endpoint.checkpoints.at(-1)?.event === 'capture-sealed', `capture seal checkpoint ${ordinal}`);
  }
  return true;
}

function deriveValuesFromRecords(records) {
  const values = {};
  for (const key of VALUE_KEYS) values[key] = unsafeVerifyByteRecord(records[key], { canonicalJson: true, digestDomain: VALUE_DIGEST_DOMAINS[key], label: `values/${key}` });
  return deepFreeze(values);
}

function valuesRootDigest(records) {
  const bindings = Object.fromEntries(VALUE_KEYS.map(key => {
    const record = records[key];
    return [key, { rawSha256: record.rawSha256, byteLength: record.byteLength, sourceRawSha256: record.sourceRawSha256, sourceByteLength: record.sourceByteLength, contentDigest: record.contentDigest }];
  }));
  return unsafeDigestRecord(bindings, VALUES_ROOT_DIGEST_DOMAIN);
}

function runtimeBinding(runtime) {
  return {
    procSelfExe: runtime.procSelfExe,
    executable: runtime.executable,
    executableRealpath: runtime.executableRealpath,
    processExecPath: runtime.processExecPath,
    executableIdentity: runtime.executableIdentity,
    rawSha256: runtime.rawSha256,
    byteLength: runtime.byteLength,
    bytesSha256: sha(runtime.bytes),
    stat: runtime.stat,
    descriptor: { label: runtime.descriptor?.label, identity: 'retained-live-descriptor-v1' },
    version: runtime.version,
    platform: runtime.platform,
    arch: runtime.arch,
  };
}

function recordBindings(records) {
  return Object.fromEntries(Object.keys(records).sort(byteSort).map(key => {
    const record = records[key];
    return [key, { key: record.key, path: record.path, mediaType: record.mediaType, rawSha256: record.rawSha256, byteLength: record.byteLength, sourceRawSha256: record.sourceRawSha256, sourceByteLength: record.sourceByteLength, contentDigest: record.contentDigest, stat: record.stat }];
  }));
}

function sourcePlanBindings(sourcePlans) {
  return sourcePlans.map(plan => ({ planId: plan.planId, planOrder: plan.planOrder, redeemSha256: sha(plan.redeemBytes), redeemByteLength: plan.redeemBytes.length, expectedOperandCount: plan.expectedOperandCount, sourceSetBinding: plan.sourceSetBinding }));
}

function verifySourcePlans(sourcePlans, records, sourceSetValue = null) {
  assert(Array.isArray(sourcePlans) && sourcePlans.length === 42, 'source plan cardinality');
  const orders = new Set();
  for (const plan of sourcePlans) {
    assert(Object.keys(plan).sort().join('\0') === ['expectedOperandCount', 'hexKey', 'mapKey', 'planId', 'planOrder', 'redeemBytes', 'sourceMapDigest', 'sourceSetBinding'].sort().join('\0'), `source plan closed shape ${plan.planId ?? 'unknown'}`);
    assert(Object.keys(plan.sourceSetBinding ?? {}).sort().join('\0') === ['contentDigest', 'planIndexEntrySha256', 'rootPath', 'rootRawSha256'].sort().join('\0'), `source plan source-set binding shape ${plan.planId ?? 'unknown'}`);
    assert(typeof plan.planId === 'string' && Number.isSafeInteger(plan.planOrder) && plan.planOrder >= 0 && !orders.has(plan.planOrder), `source plan order ${plan.planId}`); orders.add(plan.planOrder);
    assert(Buffer.isBuffer(plan.redeemBytes) && plan.redeemBytes.length > 0 && Number.isSafeInteger(plan.expectedOperandCount) && plan.expectedOperandCount >= 0, `source plan shape ${plan.planId}`);
    const hexRecord = records[`plan-hex:${plan.planId}`]; const mapRecord = records[`plan-map:${plan.planId}`];
    assert(plan.hexKey === hexRecord?.key && plan.mapKey === mapRecord?.key, `source plan record key binding ${plan.planId}`);
    if (sourceSetValue !== null) {
      const sourceEntry = sourceSetValue.planIndex?.find(entry => entry.planId === plan.planId);
      assert(sourceEntry && sourceEntry.orderIndex === plan.planOrder && plan.sourceSetBinding.planIndexEntrySha256 === sha(Buffer.from(JSON.stringify(sourceEntry), 'utf8')), `source plan source-set entry binding ${plan.planId}`);
    }
    unsafeVerifyByteRecord(hexRecord, { label: `source plan hex ${plan.planId}` }); unsafeVerifyByteRecord(mapRecord, { canonicalJson: true, digestDomain: plan.sourceMapDigest?.domain, label: `source plan map ${plan.planId}` });
    const hexText = new TextDecoder('utf-8', { fatal: true }).decode(hexRecord.bytes); assert(/^[0-9a-f]+\n$/u.test(hexText), `source plan hex grammar ${plan.planId}`); assert(Buffer.from(hexText.slice(0, -1), 'hex').equals(plan.redeemBytes), `source plan redeem bytes ${plan.planId}`);
    const map = parseCanonicalJsonBytes(mapRecord.bytes, `source plan map ${plan.planId}`); assert(expectedOperandCount(map, plan.planId) === plan.expectedOperandCount, `source plan operand count ${plan.planId}`);
    verifyDigestMetadata(plan.sourceMapDigest, `source plan map digest ${plan.planId}`, mapRecord.contentDigest?.domain); exactCanonical(plan.sourceMapDigest, mapRecord.contentDigest, `source plan map digest binding ${plan.planId}`);
    assert(plan.sourceSetBinding?.rootRawSha256 === records.sourceSet.sourceRawSha256 && plan.sourceSetBinding?.contentDigest === records.sourceSet.contentDigest.value, `source plan root binding ${plan.planId}`);
  }
  assert(orders.size === 42 && [...Array(42).keys()].every(order => orders.has(order)), 'source plan order closure');
}

function catalogRecordBinding(record, binding, label) {
  assert(record && binding && record.path === binding.path && record.sourceRawSha256 === binding.rawSha256 && record.sourceByteLength === binding.byteLength, `${label} catalog raw binding`);
  if (Object.prototype.hasOwnProperty.call(binding, 'contentDigest')) exactCanonical(record.contentDigest, binding.contentDigest, `${label} catalog content binding`);
  else assert(record.contentDigest === null, `${label} catalog absent content binding`);
}

export function unsafeValidateAuthorityCatalogStructure(catalog, records, sourcePlans, expectedDigest = null) {
  assert(catalog && catalog.schema === 'shieldkit-labs/p2/gate-b/cohort-executor-v3-snapshot-v1/authority-catalog/v1' && catalog.status === 'retained-byte-input-catalog' && catalog.executionAllowed === false && catalog.metricsAllowed === false, 'authority catalog identity');
  assert(catalog.counts?.fixtures === FIXTURE_COUNT && catalog.counts?.corpusCases === 1288 && catalog.counts?.workItems === OBLIGATION_COUNT && catalog.counts?.sourcePlans === 42 && catalog.counts?.preflightFixtures === PREFLIGHT_COUNT && catalog.counts?.eligiblePerEngine === READY_COUNT, 'authority catalog cardinality');
  verifyDigestMetadata(catalog.contentDigest, 'authority catalog content', AUTHORITY_CATALOG_DIGEST_DOMAIN);
  exactCanonical(catalog.contentDigest, unsafeDigestRecord(omit(catalog), AUTHORITY_CATALOG_DIGEST_DOMAIN), 'authority catalog content digest');
  if (expectedDigest !== null) assert(catalog.contentDigest.value === expectedDigest, 'authority catalog pinned digest');
  assert(Array.isArray(catalog.frozen) && catalog.frozen.length === 5 && Array.isArray(catalog.source) && catalog.source.length === 1 && Array.isArray(catalog.plans) && catalog.plans.length === 42, 'authority catalog graph shape');
  const valueBindings = [...catalog.frozen, ...catalog.source]; const paths = new Set(valueBindings.map(binding => binding.path));
  assert(paths.size === valueBindings.length, 'authority catalog value path uniqueness');
  for (const key of VALUE_KEYS) catalogRecordBinding(records[key], valueBindings.find(binding => binding.path === records[key]?.path), `authority ${key}`);
  const expectedValuePaths = new Set(VALUE_KEYS.map(key => records[key]?.path));
  assert(paths.size === expectedValuePaths.size && [...paths].every(value => expectedValuePaths.has(value)), 'authority catalog value path closure');
  const planIds = new Set(); const planOrders = new Set();
  for (const plan of sourcePlans) {
    const catalogPlan = catalog.plans.find(entry => entry.planId === plan.planId);
    assert(catalogPlan && catalogPlan.orderIndex === plan.planOrder && !planIds.has(plan.planId) && !planOrders.has(plan.planOrder), `authority catalog plan ${plan.planId}`);
    planIds.add(plan.planId); planOrders.add(plan.planOrder);
    const hexRecord = records[`plan-hex:${plan.planId}`]; const mapRecord = records[`plan-map:${plan.planId}`];
    catalogRecordBinding(hexRecord, catalogPlan.hex, `authority ${plan.planId} hex`);
    catalogRecordBinding(mapRecord, catalogPlan.map, `authority ${plan.planId} map`);
    assert(sha(Buffer.from(new TextDecoder('utf-8', { fatal: true }).decode(hexRecord.bytes).slice(0, -1), 'hex')) === catalogPlan.hex.bytecodeSha256 && plan.redeemBytes.length === catalogPlan.hex.bytecodeBytes, `authority ${plan.planId} bytecode catalog binding`);
    exactCanonical(mapRecord.contentDigest, catalogPlan.map.contentDigest, `authority ${plan.planId} map catalog binding`);
  }
  assert(planIds.size === 42 && planOrders.size === 42 && [...Array(42).keys()].every(order => planOrders.has(order)), 'authority catalog plan closure');
  return true;
}

function authorityDigestProjection({ valuesRoot, records, runtime, sourcePlans }) {
  return { valuesRoot, recordBindings: recordBindings(records), runtimeBinding: runtimeBinding(runtime), sourcePlans: sourcePlanBindings(sourcePlans) };
}

export function unsafeValidateRuntimeMetadataStructure(runtime) {
  assert(runtime && typeof runtime === 'object' && Buffer.isBuffer(runtime.bytes), 'runtime bytes shape');
  assert(Object.keys(runtime).sort().join('\0') === ['arch', 'byteLength', 'bytes', 'descriptor', 'executable', 'executableIdentity', 'executableRealpath', 'platform', 'processExecPath', 'procSelfExe', 'rawSha256', 'stat', 'version'].sort().join('\0'), 'runtime closed shape');
  statShape(runtime.stat, 'runtime');
  assert(runtime.procSelfExe === '/proc/self/exe', 'runtime /proc/self/exe provenance');
  assert(runtime.byteLength === runtime.bytes.length && runtime.rawSha256 === sha(runtime.bytes), 'runtime exact bytes/length/SHA');
  assert(typeof runtime.executable === 'string' && runtime.executable.length > 0, 'runtime executable identity');
  assert(typeof runtime.executableRealpath === 'string' && runtime.executableRealpath.length > 0, 'runtime executable realpath');
  assert(typeof runtime.processExecPath === 'string' && runtime.processExecPath.length > 0 && runtime.executableRealpath === runtime.processExecPath, 'runtime process executable identity');
  const identity = runtime.executableIdentity;
  assert(identity && identity.procSelfExe === '/proc/self/exe' && identity.readlinkTarget === runtime.executable && identity.realpath === runtime.executableRealpath && identity.processExecPath === runtime.processExecPath, 'runtime executable identity binding');
  assert(runtime.executable.startsWith('/') && runtime.executableRealpath.startsWith('/') && runtime.processExecPath.startsWith('/'), 'runtime executable path identity');
  assert(typeof runtime.version === 'string' && runtime.version.length > 0 && typeof runtime.platform === 'string' && runtime.platform.length > 0 && typeof runtime.arch === 'string' && runtime.arch.length > 0, 'runtime platform identity');
  assert(runtime.descriptor && runtime.descriptor.label === '/proc/self/exe' && Number.isInteger(runtime.descriptor.fd) && runtime.descriptor.fd >= 0 && runtime.descriptor.state === 'open', 'runtime live descriptor receipt');
  statShape(runtime.descriptor.before, 'runtime descriptor before'); statShape(runtime.descriptor.after, 'runtime descriptor after');
  assert(sameStat(runtime.stat, runtime.descriptor.before) && sameStat(runtime.stat, runtime.descriptor.after), 'runtime descriptor stat binding');
  assert(runtime.descriptor.receipt === null, 'runtime descriptor open receipt');
  return true;
}

function verifyRuntime(runtime) {
  unsafeValidateRuntimeMetadataStructure(runtime);
}

export function unsafeDeriveAuthoritySnapshotBindings({ values, records, runtime, sourcePlans }) {
  assert(values && records && runtime && Array.isArray(sourcePlans), 'authority snapshot inputs');
  assert(VALUE_KEYS.every(key => own(records, key)), 'authority value records');
  const expectedRecordKeys = [...VALUE_KEYS, 'authorityCatalog', ...sourcePlans.flatMap(plan => [`plan-hex:${plan.planId}`, `plan-map:${plan.planId}`])].sort();
  assert(Object.keys(records).sort().join('\0') === expectedRecordKeys.join('\0'), 'authority retained record closure');
  for (const [key, record] of Object.entries(records)) unsafeVerifyByteRecord(record, { canonicalJson: record.mediaType === 'application/json', digestDomain: expectedRecordDigestDomain(key, sourcePlans), label: record.key });
  verifySourcePlans(sourcePlans, records, values.sourceSet);
  const catalog = unsafeVerifyByteRecord(records.authorityCatalog, { canonicalJson: true, digestDomain: AUTHORITY_CATALOG_DIGEST_DOMAIN, label: 'authority catalog' });
  unsafeValidateAuthorityCatalogStructure(catalog, records, sourcePlans);
  const derivedValues = deriveValuesFromRecords(records);
  for (const key of VALUE_KEYS) { assert(own(values, key), `authority supplied value ${key}`); exactCanonical(values[key], derivedValues[key], `authority value binding ${key}`); }
  assert(Object.keys(values).sort().join('\0') === VALUE_KEYS.slice().sort().join('\0'), 'authority value key closure');
  verifyRuntime(runtime);
  const root = valuesRootDigest(records); const projection = authorityDigestProjection({ valuesRoot: root, records, runtime, sourcePlans });
  const computedSnapshotDigest = unsafeDigestRecord(projection, AUTHORITY_DIGEST_DOMAIN).value;
  return Object.freeze({ values: derivedValues, valuesRootDigest: root, snapshotDigest: computedSnapshotDigest });
}

export function unsafeValidateAuthoritySnapshotStructure(snapshot, { includeFixtureRows = false, skipFixtureDerivation = false } = {}) {
  assert(snapshot.kind === SNAPSHOT_KIND && snapshot.values.fixtureRoster.records.length === FIXTURE_COUNT && snapshot.values.workItemRoster.workItems.length === OBLIGATION_COUNT, 'authority snapshot cardinality');
  const bindings = unsafeDeriveAuthoritySnapshotBindings({ values: snapshot.values, records: snapshot.records, runtime: snapshot.runtime, sourcePlans: snapshot.sourcePlans });
  for (const key of VALUE_KEYS) exactCanonical(snapshot.values[key], bindings.values[key], `authority retained value ${key}`);
  exactCanonical(snapshot.valuesRootDigest, bindings.valuesRootDigest, 'authority values-root digest');
  assert(HEX64.test(snapshot.snapshotDigest) && snapshot.snapshotDigest === bindings.snapshotDigest, 'authority snapshot digest');
  const fixtureRows = skipFixtureDerivation ? null : unsafeDeriveFixtureRowsFromSnapshot(snapshot); const result = { status: 'PASS', snapshotDigest: snapshot.snapshotDigest, valuesRootDigest: bindings.valuesRootDigest.value, fixtures: FIXTURE_COUNT, eligiblePerEngine: READY_COUNT };
  if (includeFixtureRows) result.fixtureRows = fixtureRows;
  return Object.freeze(result);
}

export const SNAPSHOT_DIGEST_BINDING_KIND = 'cohort-executor-v3-retained-byte-snapshot-digest-binding/v1';
export function unsafeDeriveSnapshotDigestBinding(snapshot) {
  assert(snapshot && snapshot.kind === SNAPSHOT_KIND, 'snapshot digest binding kind');
  assert(HEX64.test(snapshot.snapshotDigest), 'snapshot digest binding value');
  verifyDigestMetadata(snapshot.valuesRootDigest, 'snapshot values-root', VALUES_ROOT_DIGEST_DOMAIN);
  return Object.freeze({ kind: SNAPSHOT_DIGEST_BINDING_KIND, snapshotKind: SNAPSHOT_KIND, snapshotDigest: snapshot.snapshotDigest, valuesRootDigest: snapshot.valuesRootDigest.value, authorityDigestDomain: AUTHORITY_DIGEST_DOMAIN });
}

export const RECOVERY_STABLE_PROJECTION_KIND = 'cohort-executor-v3-retained-byte-recovery-projection/v1';
export function unsafeDeriveRecoveryStableProjection(snapshot) {
  assert(snapshot && snapshot.kind === SNAPSHOT_KIND, 'recovery projection kind');
  assert(HEX64.test(snapshot.snapshotDigest) && HEX64.test(snapshot.valuesRootDigest?.value), 'recovery projection digest');
  const runtime = snapshot.runtime;
  assert(runtime && Buffer.isBuffer(runtime.bytes) && runtime.byteLength === runtime.bytes.length && runtime.rawSha256 === sha(runtime.bytes), 'recovery projection runtime bytes');
  return Object.freeze({
    kind: RECOVERY_STABLE_PROJECTION_KIND,
    snapshotKind: SNAPSHOT_KIND,
    snapshotDigest: snapshot.snapshotDigest,
    valuesRootDigest: snapshot.valuesRootDigest.value,
    runtime: Object.freeze({
      procSelfExe: runtime.procSelfExe,
      executable: runtime.executable,
      executableRealpath: runtime.executableRealpath,
      processExecPath: runtime.processExecPath,
      executableIdentity: Object.freeze({ ...runtime.executableIdentity }),
      rawSha256: runtime.rawSha256,
      byteLength: runtime.byteLength,
      bytesSha256: sha(runtime.bytes),
      stat: Object.freeze({ ...runtime.stat }),
    }),
  });
}

export const PURE_BOUNDARY = Object.freeze({ filesystemCalls: false, childProcessCalls: false, vmCalls: false, postOpenPathReads: false, endpointTupleLength: 5, fixtureRows: FIXTURE_COUNT, eligibleRows: READY_COUNT });
