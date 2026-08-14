import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';

export const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
export const FRAME = 'utf8(domain)||0x00||canonical-json-utf8';
export const ENDPOINTS = Object.freeze([
  Object.freeze({ id: 'engine:native/primary', kind: 'module-ndjson' }),
  Object.freeze({ id: 'engine:libauth/primary', kind: 'module-ndjson' }),
  Object.freeze({ id: 'engine:bchn/primary', kind: 'external-process' }),
  Object.freeze({ id: 'engine:leanbch/primary', kind: 'external-process' }),
  Object.freeze({ id: 'engine:leanbch/secondary', kind: 'external-process' }),
]);
export const PACKAGE_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-live-accounting-v2';
const here = path.dirname(new URL(import.meta.url).pathname);
const repo = path.resolve(here, '../../../../../');
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const byteSort = (left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right));
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-live-accounting-v2: ${message}`); };
export const canonicalize = value => Array.isArray(value) ? value.map(canonicalize) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonicalize(value[key])])) : value;
export const canonicalBytes = value => Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
export const omit = value => Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'contentDigest'));
export const digestRecord = (domain, value) => Object.freeze({ algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value: sha(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), canonicalBytes(value)])) });
const rootDomain = 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/failure-root/attempt-001';
const manifestDomain = 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/checkpoint-manifest/attempt-001';
const packageDomain = 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/package-manifest/root';
const authorizationSchema = 'shieldkit-labs/p2/gate-b/cohort-executor-v3/authorization/v3';
const authorizationDomain = 'shieldkit-labs/p2/gate-b/cohort-executor-v3/authorization/v3/root';
const claimSchema = 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3';
const claimDomain = 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root';
const authoritySchemaRoot = path.resolve(here, '../cohort-executor-v3');
const authorizationSchemaRawSha256 = '2ba82797b4e81257857e99344bfac51fd70ffbb27bb3e05973e225ff3a6f7b68';
const claimSchemaRawSha256 = 'cdaedc5e2fe87d23ecb928f229ace6422539db657d4976b626df2f7774720a05';

function exact(left, right, label) { assert(JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right)), label); }
function safeRelative(relative) { assert(typeof relative === 'string' && relative.length > 0 && !path.isAbsolute(relative) && !relative.includes('\\') && !relative.split('/').includes('..'), `unsafe relative path ${relative}`); return relative; }
function readFileContained(root, relative, { requirePrivateMode = false } = {}) {
  safeRelative(relative); const rootReal = fs.realpathSync(root); let current = rootReal;
  for (const component of relative.split('/')) { current = path.join(current, component); const stat = fs.lstatSync(current); assert(!stat.isSymbolicLink(), `symlink ${relative}`); }
  const stat = fs.statSync(current); assert(stat.isFile() && (!Number.isInteger(stat.nlink) || stat.nlink === 1), `non-regular/hardlinked ${relative}`); if (requirePrivateMode) assert((stat.mode & 0o777) === 0o600, `durable private mode ${relative}`);
  const real = fs.realpathSync(current); assert(real.startsWith(`${rootReal}${path.sep}`), `path escape ${relative}`); return fs.readFileSync(real);
}
function parseCanonical(bytes, label) { const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); assert(canonicalBytes(value).equals(bytes), `${label} noncanonical or duplicate-key JSON`); return value; }
function schema(file, value) { const ajv = new Ajv2020({ allErrors: true, strict: true }); const validate = ajv.compile(JSON.parse(fs.readFileSync(path.join(here, file), 'utf8'))); assert(validate(value), `${file}: ${ajv.errorsText(validate.errors)}`); }
/** This structural grammar consumes only the frozen v3 schema bytes, never a
 * current authorization/claim transport or any external authority state. */
function authoritySchema(file, expectedId, expectedRawSha256, value, label) {
  const bytes = readFileContained(authoritySchemaRoot, file); const source = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert(sha(bytes) === expectedRawSha256 && source.$id === expectedId && source.additionalProperties === false, `${label} authoritative schema identity`);
  const ajv = new Ajv2020({ allErrors: true, strict: true }); const validate = ajv.compile(source); assert(validate(value), `${label} strict v3 schema: ${ajv.errorsText(validate.errors)}`);
}
function content(value, domain, label) { const digest = value?.contentDigest; assert(digest?.algorithm === 'sha256' && digest.canonicalization === CANONICALIZATION && digest.frame === FRAME && digest.domain === domain && digest.value === digestRecord(domain, omit(value)).value, `${label} content digest`); }
function digestShape(digest, label) { assert(digest?.algorithm === 'sha256' && digest.canonicalization === CANONICALIZATION && digest.frame === FRAME && typeof digest.domain === 'string' && /^[0-9a-f]{64}$/u.test(digest.value), `${label} digest shape`); }
function binding(root, item, label, { requirePrivateMode = false } = {}) {
  const bytes = readFileContained(root, item.path, { requirePrivateMode }); const value = parseCanonical(bytes, label); assert(sha(bytes) === item.rawSha256 && bytes.length === item.byteLength, `${label} raw binding`); digestShape(value.contentDigest, `${label} embedded`); assert(JSON.stringify(value.contentDigest) === JSON.stringify(item.contentDigest), `${label} content binding`); return Object.freeze({ bytes, value });
}
function walk(root) {
  const files = []; const dirs = [];
  const visit = (folder, prefix = '') => { for (const name of fs.readdirSync(folder).sort(byteSort)) { const full = path.join(folder, name); const relative = prefix ? `${prefix}/${name}` : name; const stat = fs.lstatSync(full); assert(!stat.isSymbolicLink(), `symlink namespace ${relative}`); if (stat.isDirectory()) { dirs.push(relative); visit(full, relative); } else { assert(stat.isFile() && (!Number.isInteger(stat.nlink) || stat.nlink === 1), `non-regular/hardlinked namespace ${relative}`); files.push(relative); } } };
  visit(root); return { files: files.sort(byteSort), dirs: dirs.sort(byteSort) };
}
function expectedDirectories(files) { const dirs = new Set(); for (const file of files) { const parts = file.split('/'); for (let index = 1; index < parts.length; index += 1) dirs.add(parts.slice(0, index).join('/')); } return [...dirs].sort(byteSort); }
function endpointFor(ordinal) { const value = ENDPOINTS[ordinal]; assert(value !== undefined, `unknown endpoint ordinal ${ordinal}`); return value; }
function checkpointDomain(ordinal) { return `shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/checkpoint/attempt-001/${ordinal}`; }
function containedDirectory(root, label, { requirePrivateMode = false } = {}) {
  assert(path.isAbsolute(root), `${label} absolute root`);
  const stat = fs.lstatSync(root);
  assert(stat.isDirectory() && !stat.isSymbolicLink(), `${label} root directory`); if (requirePrivateMode) assert((stat.mode & 0o777) === 0o700, `${label} root private mode`);
  return root;
}
function validateSlot(root, slot, expectedRole, label, { requirePrivateMode = false } = {}) {
  assert(slot.streamRole === expectedRole, `${label} stream role`);
  if (slot.captureStatus === 'unavailable') { exact([slot.path, slot.rawSha256, slot.byteLength, slot.fsynced], [null, null, null, false], `${label} unavailable union`); return null; }
  assert(typeof slot.path === 'string' && slot.path.startsWith('streams/') && /^[0-9a-f]{64}$/u.test(slot.rawSha256) && Number.isSafeInteger(slot.byteLength) && slot.byteLength >= 0 && slot.fsynced === true, `${label} durable stream union`);
  const bytes = readFileContained(root, slot.path, { requirePrivateMode }); assert(bytes.length === slot.byteLength && sha(bytes) === slot.rawSha256, `${label} stream bytes`); return { streamRole: expectedRole, path: slot.path, rawSha256: slot.rawSha256, byteLength: slot.byteLength, captureStatus: slot.captureStatus, fsynced: true };
}
function validateCapture(root, capture, endpoint, label, { requirePrivateMode = false } = {}) {
  assert(capture.endpointKind === endpoint.kind, `${label} endpoint kind`); const roles = ['stdin', 'stdout', 'stderr']; const slots = capture.slots.map((slot, index) => validateSlot(root, slot, roles[index], `${label}/${roles[index]}`, { requirePrivateMode }));
  if (endpoint.kind === 'module-ndjson') {
    assert(capture.modulePrefix !== null, `${label} module prefix required`); const stdout = capture.slots[1]; assert(stdout.path !== null, `${label} module stdout unavailable`); const bytes = readFileContained(root, stdout.path, { requirePrivateMode }); const finalLf = bytes.lastIndexOf(0x0a); const prefix = finalLf < 0 ? Buffer.alloc(0) : bytes.subarray(0, finalLf + 1); const trailing = finalLf < 0 ? bytes : bytes.subarray(finalLf + 1); const rows = prefix.length === 0 ? 0 : new TextDecoder('utf-8', { fatal: true }).decode(prefix).slice(0, -1).split('\n').length;
    exact(capture.modulePrefix, { completedRowCount: rows, completedLfByteLength: prefix.length, completedLfRawSha256: sha(prefix), trailingFragmentByteLength: trailing.length, trailingFragmentRawSha256: sha(trailing) }, `${label} module durable prefix`);
    if (stdout.captureStatus === 'complete') assert(trailing.length === 0, `${label} complete module trailing fragment`);
    if (trailing.length !== 0) assert(stdout.captureStatus === 'partial', `${label} module fragment requires partial capture`);
  } else assert(capture.modulePrefix === null, `${label} external module prefix`);
  return slots.filter(Boolean);
}
function terminalRules(rootTerminal, event, ordinal) {
  const isController = rootTerminal.phase.startsWith('controller-');
  const controllerKinds = new Set(['controller-before-endpoint', 'controller-between-endpoints', 'controller-after-endpoint']);
  if (isController) {
    assert(controllerKinds.has(event.kind) && event.kind === rootTerminal.phase && event.phase === 'controller' && event.controllerFailureKind === rootTerminal.failureKind && event.capture === null, 'controller terminal event');
    assert(['builder', 'materializer', 'validator', 'commit', 'recovery'].includes(rootTerminal.failureKind), 'controller failure kind');
    exact([event.endpointId, event.endpointKind], [null, null], 'controller endpoint identity absent');
    if (rootTerminal.phase === 'controller-before-endpoint') exact([rootTerminal.endpointOrdinal, event.endpointOrdinal], [null, null], 'before endpoint ordinal');
    if (rootTerminal.phase === 'controller-after-endpoint') exact([rootTerminal.endpointOrdinal, event.endpointOrdinal], [null, null], 'after endpoint ordinal');
    if (rootTerminal.phase === 'controller-between-endpoints') assert(rootTerminal.endpointOrdinal === event.endpointOrdinal && Number.isInteger(rootTerminal.endpointOrdinal) && rootTerminal.endpointOrdinal >= 1 && rootTerminal.endpointOrdinal <= 4, 'between endpoint ordinal');
    return;
  }
  assert(event.phase === 'endpoint' && event.endpointOrdinal === rootTerminal.endpointOrdinal && event.endpointId === endpointFor(event.endpointOrdinal).id && event.endpointKind === endpointFor(event.endpointOrdinal).kind && event.controllerFailureKind === null, 'endpoint terminal identity');
  if (rootTerminal.phase === 'abrupt-before-start') assert(event.kind === 'abrupt-before-start' && event.capture === null && rootTerminal.failureKind === 'abrupt-before-start', 'abrupt-before-start event');
  else if (rootTerminal.phase === 'abrupt-module-death') assert(event.kind === 'abrupt-module-death' && event.capture !== null && endpointFor(event.endpointOrdinal).kind === 'module-ndjson' && rootTerminal.failureKind === 'abrupt-module-death', 'abrupt module event');
  else {
    assert(rootTerminal.phase === 'endpoint-failure' && event.capture !== null, 'endpoint terminal event');
    const endpoint = endpointFor(rootTerminal.endpointOrdinal);
    if (endpoint.kind === 'module-ndjson') exact([event.kind, rootTerminal.failureKind], ['module-terminal', 'module-error'], 'module endpoint terminal coupling');
    else exact([event.kind, rootTerminal.failureKind], ['external-terminal', 'external-process'], 'external endpoint terminal coupling');
  }
  assert(ordinal >= 0, 'terminal ordinal');
}
function selectedSuffix(terminal) {
  if (terminal.phase === 'controller-before-endpoint') return [0, 1, 2, 3, 4];
  if (terminal.phase === 'controller-after-endpoint') return [];
  if (terminal.phase === 'controller-between-endpoints') return Array.from({ length: 5 - terminal.endpointOrdinal }, (_, index) => terminal.endpointOrdinal + index);
  if (terminal.phase === 'abrupt-before-start') return Array.from({ length: 5 - terminal.endpointOrdinal }, (_, index) => terminal.endpointOrdinal + index);
  return Array.from({ length: 4 - terminal.endpointOrdinal }, (_, index) => terminal.endpointOrdinal + index + 1);
}
function completedPrefix(terminal) {
  if (terminal.phase === 'controller-before-endpoint') return [];
  if (terminal.phase === 'controller-between-endpoints') return Array.from({ length: terminal.endpointOrdinal }, (_, index) => index);
  if (terminal.phase === 'controller-after-endpoint') return [0, 1, 2, 3, 4];
  return Array.from({ length: terminal.endpointOrdinal }, (_, index) => index);
}

/** Validates only a local, already-authenticated live failure container. It
 * never discovers or authenticates authority outside `root`. */
export function validateLiveFailureContainer(root) {
  containedDirectory(root, 'contained');
  const rootBytes = readFileContained(root, 'live-failure.v2.json'); const value = parseCanonical(rootBytes, 'failure root'); schema('live-failure.v2.schema.json', value); content(value, rootDomain, 'failure root'); exact(value.endpointOrder, ENDPOINTS.map(endpoint => endpoint.id), 'exact endpoint order');
  assert(value.executionAllowed === false && value.metricsAllowed === false && value.ranking === null && value.selection === null && value.resultReuse === null && value.recovery.endpointReinvoked === false && value.recovery.reusable === false && value.recovery.resultReuse === null, 'nonreuse boundary');
  const auth = binding(root, value.authorizationCopy.copyBinding, 'authorization copy'); const claim = binding(root, value.claimCopy.copyBinding, 'claim copy'); exact(value.authorizationCopy.authorityBinding, value.authorizationCopy.copyBinding, 'authorization copy/authority exact binding'); exact(value.claimCopy.authorityBinding, value.claimCopy.copyBinding, 'claim copy/authority exact binding');
  assert(auth.value.schema === authorizationSchema, 'authorization copy schema'); content(auth.value, authorizationDomain, 'authorization copy'); authoritySchema('authorization.v3.schema.json', 'https://shieldkit-labs.local/p2/gate-b/cohort-executor-v3/authorization.v3.schema.json', authorizationSchemaRawSha256, auth.value, 'authorization copy');
  assert(claim.value.schema === claimSchema, 'claim copy schema'); content(claim.value, claimDomain, 'claim copy'); authoritySchema('execution-claim.v3.schema.json', 'https://shieldkit-labs.local/p2/gate-b/cohort-executor-v3/execution-claim.v3.schema.json', claimSchemaRawSha256, claim.value, 'claim copy');
  exact(claim.value.authorizationBinding, value.authorizationCopy.copyBinding, 'claim/auth copy exact binding');
  const manifestRead = binding(root, value.checkpointManifestBinding, 'checkpoint manifest'); const manifest = manifestRead.value; schema('checkpoint-manifest.v2.schema.json', manifest); content(manifest, manifestDomain, 'checkpoint manifest');
  assert(manifest.checkpointBindings.length >= 2, 'checkpoint chain requires terminal and recovery checkpoints'); const checkpoints = []; let previous = null; const streams = [];
  for (const [index, item] of manifest.checkpointBindings.entries()) {
    assert(item.path === `checkpoints/${String(index).padStart(3, '0')}.checkpoint.v2.json`, `checkpoint path/order ${index}`); const checkpointRead = binding(root, item, `checkpoint ${index}`); const checkpoint = checkpointRead.value; schema('checkpoint.v2.schema.json', checkpoint); assert(checkpoint.ordinal === index && checkpoint.checkpointId === `checkpoint:attempt-001:${index}`, `checkpoint identity ${index}`); content(checkpoint, checkpointDomain(index), `checkpoint ${index}`); exact(checkpoint.previousCheckpointDigest, previous, `checkpoint chain ${index}`); previous = checkpoint.contentDigest; checkpoints.push(checkpoint);
    if (checkpoint.event.capture !== null) streams.push(...validateCapture(root, checkpoint.event.capture, endpointFor(checkpoint.event.endpointOrdinal), `checkpoint ${index}`).map(stream => ({ endpointOrdinal: checkpoint.event.endpointOrdinal, ...stream })));
  }
  assert(checkpoints.length === 2, 'sealed chain exact cardinality'); const terminalIndex = 0; const terminal = checkpoints[terminalIndex]; assert(terminal.event.kind !== 'recovery-sealed' && terminal.event.phase !== 'recovery', 'sealed terminal checkpoint index 0'); terminalRules(value.terminal, terminal.event, terminalIndex);
  exact(checkpoints[1].event, { phase: 'recovery', kind: 'recovery-sealed', endpointOrdinal: null, endpointId: null, endpointKind: null, controllerFailureKind: null, capture: null }, 'recovery sealed exact shape');
  exact(value.completedEndpointPrefix, completedPrefix(value.terminal), 'completed endpoint exact prefix'); exact(value.selectedNotStarted, selectedSuffix(value.terminal), 'selected-not-started exact suffix');
  const expectedDisposition = value.terminal.phase === 'controller-before-endpoint' ? 'sealed-no-endpoint' : value.terminal.phase === 'abrupt-before-start' ? 'sealed-before-start' : value.terminal.phase === 'controller-after-endpoint' ? 'sealed-after-terminal' : 'sealed-partial-prefix'; assert(value.recovery.disposition === expectedDisposition, 'recovery disposition');
  const expectedStreams = streams; assert(manifest.streamBindings.length === streams.length, 'stream manifest cardinality');
  for (const [index, stream] of manifest.streamBindings.entries()) { exact(stream, expectedStreams[index], `stream manifest ${index}`); }
  const files = ['authorization.copy.json', 'checkpoint-manifest.v2.json', 'execution-claim.copy.json', 'live-failure.v2.json', ...manifest.checkpointBindings.map(item => item.path), ...manifest.streamBindings.map(item => item.path)].sort(byteSort); const actual = walk(root); exact(actual.files, files, 'container exact file closure'); exact(actual.dirs, expectedDirectories(files), 'container exact directory closure');
  return Object.freeze({ status: 'PASS', checkpointCount: checkpoints.length, terminalPhase: value.terminal.phase, streamCount: streams.length, authorityNeutral: true, executionAllowed: false });
}

/** A crash-recovery preflight validates an append-only checkpoint prefix but
 * deliberately cannot treat it as a sealed failure until the root exists. */
export function validateRecoverableCheckpointPrefix(root) {
  containedDirectory(root, 'prefix', { requirePrivateMode: true }); const manifest = parseCanonical(readFileContained(root, 'checkpoint-manifest.v2.json', { requirePrivateMode: true }), 'prefix manifest'); schema('checkpoint-manifest.v2.schema.json', manifest); content(manifest, manifestDomain, 'prefix manifest'); assert(manifest.checkpointBindings.length >= 1, 'prefix checkpoint count'); let previous = null; const streams = [];
  for (const [index, item] of manifest.checkpointBindings.entries()) { assert(item.path === `checkpoints/${String(index).padStart(3, '0')}.checkpoint.v2.json`, `prefix checkpoint path/order ${index}`); const checkpoint = binding(root, item, `prefix checkpoint ${index}`, { requirePrivateMode: true }).value; schema('checkpoint.v2.schema.json', checkpoint); assert(checkpoint.ordinal === index && checkpoint.checkpointId === `checkpoint:attempt-001:${index}`, 'prefix checkpoint identity'); content(checkpoint, checkpointDomain(index), 'prefix content'); exact(checkpoint.previousCheckpointDigest, previous, 'prefix chain'); previous = checkpoint.contentDigest; if (checkpoint.event.capture !== null) streams.push(...validateCapture(root, checkpoint.event.capture, endpointFor(checkpoint.event.endpointOrdinal), `prefix checkpoint ${index}`, { requirePrivateMode: true }).map(stream => ({ endpointOrdinal: checkpoint.event.endpointOrdinal, ...stream }))); }
  assert(manifest.streamBindings.length === streams.length, 'prefix stream manifest cardinality'); for (const [index, stream] of manifest.streamBindings.entries()) exact(stream, streams[index], `prefix stream manifest ${index}`);
  const files = ['checkpoint-manifest.v2.json', ...manifest.checkpointBindings.map(item => item.path), ...manifest.streamBindings.map(item => item.path)].sort(byteSort); const namespace = walk(root); exact(namespace.files, files, 'prefix exact file closure'); exact(namespace.dirs, expectedDirectories(files), 'prefix exact directory closure'); for (const directory of namespace.dirs) { const stat = fs.lstatSync(path.join(root, directory)); assert((stat.mode & 0o777) === 0o700, `prefix durable directory mode ${directory}`); }
  return Object.freeze({ status: 'RECOVERABLE-PREFIX-ONLY', checkpointCount: manifest.checkpointBindings.length, sealed: false });
}

export function validatePackageEnvelope() {
  const manifestPath = path.join(here, 'MANIFEST.json'); const manifestBytes = fs.readFileSync(manifestPath); const manifest = parseCanonical(manifestBytes, 'package manifest'); schema('manifest.v1.schema.json', manifest); content(manifest, packageDomain, 'package manifest'); assert(manifest.coverage.listedPayloadCount === manifest.files.length, 'package listed count'); const listed = manifest.files.map(item => item.path); const namespace = walk(here); const expectedFiles = ['MANIFEST.json', 'SHA256SUMS', ...manifest.files.map(item => item.path.slice(`${PACKAGE_REL}/`.length))].sort(byteSort); exact(namespace.files, expectedFiles, 'package exact file closure'); exact(namespace.dirs, expectedDirectories(expectedFiles), 'package exact directory closure'); const actual = namespace.files.filter(file => !['MANIFEST.json', 'SHA256SUMS'].includes(file)).map(file => `${PACKAGE_REL}/${file}`); exact(listed, actual, 'package listed closure');
  for (const item of manifest.files) { const bytes = fs.readFileSync(path.join(repo, item.path)); assert(bytes.length === item.byteLength && sha(bytes) === item.rawSha256, `package payload ${item.path}`); }
  const checksum = Buffer.from(`${[[sha(manifestBytes), `${PACKAGE_REL}/MANIFEST.json`], ...manifest.files.map(item => [item.rawSha256, item.path])].map(row => row.join('  ')).join('\n')}\n`, 'utf8'); assert(fs.readFileSync(path.join(here, 'SHA256SUMS')).equals(checksum), 'package checksum envelope'); return true;
}

if (import.meta.url === `file://${process.argv[1]}`) { validatePackageEnvelope(); console.log('PASS cohort-live-accounting-v2 static package'); }
