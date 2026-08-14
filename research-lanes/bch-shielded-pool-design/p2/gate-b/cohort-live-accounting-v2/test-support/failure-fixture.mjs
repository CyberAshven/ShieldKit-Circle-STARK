import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ENDPOINTS, canonicalBytes, digestRecord, omit } from '../validator.mjs';
import { buildAuthorizationTemplate } from '../../cohort-executor-v3/authority.mjs';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const empty = Buffer.alloc(0);
const rootDomain = 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/failure-root/attempt-001';
const manifestDomain = 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/checkpoint-manifest/attempt-001';
const checkpointDomain = ordinal => `shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/checkpoint/attempt-001/${ordinal}`;
export const read = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export const write = (file, value) => { fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 }); fs.writeFileSync(file, Buffer.isBuffer(value) ? value : canonicalBytes(value), { mode: 0o600 }); };
const digest = (value, domain) => { value.contentDigest = digestRecord(domain, omit(value)); return value; };
const binding = (root, relative) => { const bytes = fs.readFileSync(path.join(root, relative)); const value = read(path.join(root, relative)); return { path: relative, rawSha256: sha(bytes), byteLength: bytes.length, contentDigest: value.contentDigest }; };
const streamSlot = (root, endpointOrdinal, role, bytes, captureStatus) => {
  if (captureStatus === 'unavailable') return { streamRole: role, captureStatus, path: null, rawSha256: null, byteLength: null, fsynced: false };
  const relative = `streams/${String(endpointOrdinal).padStart(2, '0')}.${role}.bin`; write(path.join(root, relative), bytes); return { streamRole: role, captureStatus, path: relative, rawSha256: sha(bytes), byteLength: bytes.length, fsynced: true };
};
const modulePrefix = bytes => { const finalLf = bytes.lastIndexOf(0x0a); const prefix = finalLf < 0 ? empty : bytes.subarray(0, finalLf + 1); const trailing = finalLf < 0 ? bytes : bytes.subarray(finalLf + 1); return { completedRowCount: prefix.length === 0 ? 0 : prefix.toString('utf8').slice(0, -1).split('\n').length, completedLfByteLength: prefix.length, completedLfRawSha256: sha(prefix), trailingFragmentByteLength: trailing.length, trailingFragmentRawSha256: sha(trailing) }; };
function capture(root, ordinal, { moduleComplete = false } = {}) {
  const endpoint = ENDPOINTS[ordinal]; const complete = endpoint.kind === 'module-ndjson' && moduleComplete; const output = endpoint.kind === 'module-ndjson' ? Buffer.from(complete ? '{"row":0}\n' : '{"row":0}\n{"truncated"', 'utf8') : Buffer.from([0xff, 0x00, 0x0a]);
  return { endpointKind: endpoint.kind, slots: [streamSlot(root, ordinal, 'stdin', Buffer.from('input\n'), 'complete'), streamSlot(root, ordinal, 'stdout', output, complete ? 'complete' : 'partial'), streamSlot(root, ordinal, 'stderr', empty, 'complete')], modulePrefix: endpoint.kind === 'module-ndjson' ? modulePrefix(output) : null };
}
function terminalShape(phase, failureKind, endpointOrdinal) {
  const selected = phase === 'controller-before-endpoint' ? [0, 1, 2, 3, 4] : phase === 'controller-after-endpoint' ? [] : phase === 'controller-between-endpoints' || phase === 'abrupt-before-start' ? Array.from({ length: 5 - endpointOrdinal }, (_, index) => endpointOrdinal + index) : Array.from({ length: 4 - endpointOrdinal }, (_, index) => endpointOrdinal + index + 1);
  const completed = phase === 'controller-before-endpoint' ? [] : phase === 'controller-between-endpoints' ? Array.from({ length: endpointOrdinal }, (_, index) => index) : phase === 'controller-after-endpoint' ? [0, 1, 2, 3, 4] : Array.from({ length: endpointOrdinal }, (_, index) => index);
  const disposition = phase === 'controller-before-endpoint' ? 'sealed-no-endpoint' : phase === 'abrupt-before-start' ? 'sealed-before-start' : phase === 'controller-after-endpoint' ? 'sealed-after-terminal' : 'sealed-partial-prefix';
  return { terminal: { phase, failureKind, endpointOrdinal }, selected, completed, disposition };
}
function terminalEvent(root, terminal, options) {
  const { phase, failureKind, endpointOrdinal } = terminal;
  if (phase.startsWith('controller-')) return { phase: 'controller', kind: phase, endpointOrdinal, endpointId: null, endpointKind: null, controllerFailureKind: failureKind, capture: null };
  const endpoint = ENDPOINTS[endpointOrdinal];
  if (phase === 'abrupt-before-start') return { phase: 'endpoint', kind: 'abrupt-before-start', endpointOrdinal, endpointId: endpoint.id, endpointKind: endpoint.kind, controllerFailureKind: null, capture: null };
  if (phase === 'abrupt-module-death') return { phase: 'endpoint', kind: 'abrupt-module-death', endpointOrdinal, endpointId: endpoint.id, endpointKind: endpoint.kind, controllerFailureKind: null, capture: capture(root, endpointOrdinal, options) };
  return { phase: 'endpoint', kind: endpoint.kind === 'module-ndjson' ? 'module-terminal' : 'external-terminal', endpointOrdinal, endpointId: endpoint.id, endpointKind: endpoint.kind, controllerFailureKind: null, capture: capture(root, endpointOrdinal, options) };
}
function checkpoint(ordinal, event, previousCheckpointDigest) { const value = { schema: 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/checkpoint/v2', checkpointId: `checkpoint:attempt-001:${ordinal}`, attemptIndex: 1, ordinal, event, previousCheckpointDigest, contentDigest: null }; return digest(value, checkpointDomain(ordinal)); }
const frozenAuthorizationShape = Object.freeze(buildAuthorizationTemplate());
function copies(root) {
  const authorization = structuredClone(frozenAuthorizationShape); write(path.join(root, 'authorization.copy.json'), authorization); const authorizationBinding = binding(root, 'authorization.copy.json');
  const { artifactId: _artifactId, realpath: _realpath, ...contractBinding } = authorization.contractBinding;
  const claim = digest({ schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3', claimId: 'execution-claim:cohort-executor-v3:attempt-001', status: 'claimed-unexecuted', attemptIndex: 1, authorizationBinding, contractBinding, outputRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-runs-v3/attempt-001', runtime: authorization.runtime, nonreusePolicy: 'exclusive-one-use-claim-consumes-attempt-001-even-if-output-absent', contentDigest: null }, 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root'); write(path.join(root, 'execution-claim.copy.json'), claim);
  return { authorizationBinding, claimBinding: binding(root, 'execution-claim.copy.json') };
}
function streamBindings(checkpoints) { return checkpoints.flatMap(checkpoint => checkpoint.event.capture === null ? [] : checkpoint.event.capture.slots.filter(slot => slot.path !== null).map(slot => ({ endpointOrdinal: checkpoint.event.endpointOrdinal, streamRole: slot.streamRole, path: slot.path, rawSha256: slot.rawSha256, byteLength: slot.byteLength, captureStatus: slot.captureStatus, fsynced: slot.fsynced }))); }
export function buildFailureFixture({ phase = 'endpoint-failure', failureKind = 'external-process', endpointOrdinal = 2, crashPrefix = false, moduleComplete = false } = {}) {
  if (phase === 'abrupt-module-death' || phase === 'abrupt-before-start') endpointOrdinal = 0;
  if (phase === 'controller-before-endpoint' || phase === 'controller-after-endpoint') endpointOrdinal = null;
  if (phase === 'controller-between-endpoints' && endpointOrdinal === null) endpointOrdinal = 2;
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'cohort-live-accounting-v2-')); const root = path.join(parent, 'failure'); fs.mkdirSync(root, { mode: 0o700 }); const { terminal, selected, completed, disposition } = terminalShape(phase, failureKind, endpointOrdinal); const copy = crashPrefix ? null : copies(root);
  const first = checkpoint(0, terminalEvent(root, terminal, { moduleComplete }), null); write(path.join(root, 'checkpoints/000.checkpoint.v2.json'), first); const checkpoints = [first];
  if (!crashPrefix) { const second = checkpoint(1, { phase: 'recovery', kind: 'recovery-sealed', endpointOrdinal: null, endpointId: null, endpointKind: null, controllerFailureKind: null, capture: null }, first.contentDigest); write(path.join(root, 'checkpoints/001.checkpoint.v2.json'), second); checkpoints.push(second); }
  const checkpointBindings = checkpoints.map((_, ordinal) => binding(root, `checkpoints/${String(ordinal).padStart(3, '0')}.checkpoint.v2.json`)); const manifest = digest({ schema: 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/checkpoint-manifest/v2', manifestId: 'checkpoint-manifest:execution-epoch-gate-b-v2:attempt-001:v2', attemptIndex: 1, checkpointBindings, streamBindings: streamBindings(checkpoints), contentDigest: null }, manifestDomain); write(path.join(root, 'checkpoint-manifest.v2.json'), manifest);
  if (!crashPrefix) { const failure = digest({ schema: 'shieldkit-labs/p2/gate-b/cohort-live-accounting-v2/live-failure/v2', failureId: 'live-failure:execution-epoch-gate-b-v2:attempt-001:v2', attemptIndex: 1, status: 'sealed-live-failure-recovery-only', executionAllowed: false, metricsAllowed: false, ranking: null, selection: null, resultReuse: null, endpointOrder: ENDPOINTS.map(endpoint => endpoint.id), completedEndpointPrefix: completed, terminal, selectedNotStarted: selected, authorizationCopy: { copyBinding: copy.authorizationBinding, authorityBinding: copy.authorizationBinding }, claimCopy: { copyBinding: copy.claimBinding, authorityBinding: copy.claimBinding }, checkpointManifestBinding: binding(root, 'checkpoint-manifest.v2.json'), recovery: { disposition, endpointReinvoked: false, reusable: false, resultReuse: null, recoverySealed: true }, contentDigest: null }, rootDomain); write(path.join(root, 'live-failure.v2.json'), failure); }
  return { parent, root, terminal, remove: () => fs.rmSync(parent, { recursive: true, force: true }) };
}
