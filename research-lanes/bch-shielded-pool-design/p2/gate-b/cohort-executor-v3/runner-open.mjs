/*
 * Execute-only runner opening. This module is dynamically imported by CLI
 * after --execute is selected; it is deliberately absent from the static
 * validator closure. Importing it does not launch an endpoint.
 */
import crypto from 'node:crypto';
import path from 'node:path';
import { spawn as nodeSpawn } from 'node:child_process';
import { AUTHORIZATION_DOMAIN, AUTHORIZATION_REL, CLAIM_REL, OUTPUT_REL, buildAuthorizationTemplate, currentRuntime, validateAuthorizationObject } from './authority.mjs';
import { canonicalBytes, canonicalize, digestRecord, omit } from '../cohort-execution-v3/contract.mjs';
import { encodeBchnBatchStdin, encodeLeanCostprobeStdin, encodeLeanVmbconfStdin, encodeLibauthModuleStdin, encodeNativeModuleStdin } from '../cohort-execution-v3/adapters.mjs';
import { createExactAttemptScratch, commitValidatedAttemptNoReplace, materializeExactSuccessScratch, revalidateCommittedSuccess, validateScratchBeforeAtomicCommit } from './materializer.mjs';
import { closeDescriptor, createScratchSubdirectory, ensureExactOwnedDirectory, fsyncDescriptor, fsyncDirectory, openCaptureSlot, openDirectoryDescriptorNoFollow, openRegularFileDescriptorNoFollow, readRegularFileNoFollow, removeScratchLeavesNoFollow, writeExclusiveFileNoFollow } from './durable-io.mjs';
import { deriveCompleteSuccessPayloadBytes } from './evidence-builder.mjs';
import { currentCommitHelperBinding } from './commit-helper.mjs';

const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 runner-open: ${message}`); };
const workspace = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../../../../..');
const abs = relative => path.resolve(workspace, relative);
const asDecimalNs = value => BigInt(value).toString(10);
const nowNs = () => process.hrtime.bigint();
const endpointOrder = Object.freeze(['engine:native/primary', 'engine:libauth/primary', 'engine:bchn/primary', 'engine:leanbch/primary', 'engine:leanbch/secondary']);
const emptySha = sha(Buffer.alloc(0));
const structuredError = error => Object.freeze({ name: error?.name || 'Error', code: error?.code ?? null, messageRawSha256: sha(Buffer.from(String(error?.message ?? ''), 'utf8')) });
const unavailableStreams = () => Object.freeze({
  stdin: Object.freeze({ path: null, byteLength: null, rawSha256: null, fsynced: false, captureStatus: 'unavailable' }),
  stdout: Object.freeze({ path: null, byteLength: null, rawSha256: null, fsynced: false, captureStatus: 'unavailable' }),
  stderr: Object.freeze({ path: null, byteLength: null, rawSha256: null, fsynced: false, captureStatus: 'unavailable' }),
});
const zeroStream = file => Object.freeze({ path: file, byteLength: 0, rawSha256: emptySha, fsynced: true, captureStatus: 'complete' });

function strictCanonicalJson(bytes, label) {
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  assert(canonicalBytes(value).equals(bytes), `${label} noncanonical JSON`); return value;
}

/** Descriptor-bound external authorization read: parsed value and raw hash use one opened inode. */
export function readAuthorizationByDescriptor() {
  const read = readRegularFileNoFollow(workspace, AUTHORIZATION_REL); const authorization = strictCanonicalJson(read.bytes, 'authorization');
  validateAuthorizationObject(authorization);
  assert(read.rawSha256 === sha(read.bytes) && read.byteLength === read.bytes.length, 'authorization descriptor byte identity');
  return Object.freeze({ authorization, bytes: read.bytes, binding: Object.freeze({ path: AUTHORIZATION_REL, rawSha256: read.rawSha256, byteLength: read.byteLength, contentDigest: authorization.contentDigest }), descriptor: read });
}

function retainedPath(binding) {
  assert(binding && typeof binding === 'object' && typeof binding.path === 'string', 'retained binding path');
  return binding.realpath ?? (path.isAbsolute(binding.path) ? binding.path : abs(binding.path));
}
function retainExactFile(retained, label, binding, { requireContentDigest = false } = {}) {
  const opened = openRegularFileDescriptorNoFollow(retainedPath(binding));
  try {
    /* Some frozen narrow bindings deliberately pin a raw byte digest without
     * duplicating a byte length. In that form the hash is still mandatory;
     * when a length is present it is an additional exact check. */
    assert(opened.rawSha256 === binding.rawSha256 &&
      (!Number.isSafeInteger(binding.byteLength) || opened.byteLength === binding.byteLength),
    `retained ${label} bytes`);
    if (binding.realpath !== undefined) assert(opened.realpath === binding.realpath, `retained ${label} realpath`);
    if (requireContentDigest) {
      const value = strictCanonicalJson(opened.bytes, `retained ${label}`);
      assert(value.contentDigest && typeof value.contentDigest.domain === 'string' && /^[0-9a-f]{64}$/u.test(value.contentDigest.value), `retained ${label} content digest shape`);
      assert(value.contentDigest.value === digestRecord(omit(value), value.contentDigest.domain).value, `retained ${label} recomputed content digest`);
      assert(canonicalBytes(value.contentDigest).equals(canonicalBytes(binding.contentDigest)), `retained ${label} content digest`);
    }
    const entry = Object.freeze({ label, path: binding.path, realpath: opened.realpath, rawSha256: opened.rawSha256, byteLength: opened.byteLength, fd: opened.fd, bytes: opened.bytes, ...(requireContentDigest ? { contentDigest: binding.contentDigest } : {}) });
    retained.push(entry); return entry;
  } catch (error) { closeDescriptor(opened.fd); throw error; }
}

/**
 * Build the retained authority snapshot used by a future live runner. All
 * pathname reads happen before claim creation; subsequent codecs, evaluators,
 * builders, validators, and the commit helper receive only these bytes/fds.
 * This opening does not create a claim or invoke an endpoint, and production
 * execution remains fail-closed until durable checkpoints/failure publishing
 * consume this object.
 */
export function openRetainedAuthoritySnapshot() {
  const retained = [];
  try {
    const authorizationFile = openRegularFileDescriptorNoFollow(abs(AUTHORIZATION_REL));
    let authorization;
    try {
      authorization = strictCanonicalJson(authorizationFile.bytes, 'retained authorization');
      validateAuthorizationObject(authorization);
      assert(authorizationFile.rawSha256 === sha(authorizationFile.bytes) && authorizationFile.byteLength === authorizationFile.bytes.length, 'retained authorization bytes');
      retained.push(Object.freeze({ label: 'authorization', path: AUTHORIZATION_REL, realpath: authorizationFile.realpath, rawSha256: authorizationFile.rawSha256, byteLength: authorizationFile.byteLength, fd: authorizationFile.fd, bytes: authorizationFile.bytes, contentDigest: authorization.contentDigest }));
    } catch (error) { closeDescriptor(authorizationFile.fd); throw error; }
    const add = (label, binding, options) => retainExactFile(retained, label, binding, options);
    add('contract', authorization.contractBinding, { requireContentDigest: true });
    add('epoch', authorization.epochBinding, { requireContentDigest: true });
    add('retry', authorization.retryBinding, { requireContentDigest: true });
    add('accounting', authorization.accountingBinding, { requireContentDigest: true });
    for (const [index, binding] of authorization.packageRootBindings.entries()) {
      add(`package-${index}-manifest`, { path: binding.manifestPath, rawSha256: binding.manifestRawSha256, byteLength: binding.manifestByteLength, contentDigest: binding.manifestContentDigest }, { requireContentDigest: true });
      add(`package-${index}-schema`, { path: binding.manifestSchemaPath, rawSha256: binding.manifestSchemaRawSha256, byteLength: null });
      add(`package-${index}-checksums`, { path: binding.checksumsPath, rawSha256: binding.checksumsRawSha256, byteLength: binding.checksumsByteLength });
    }
    for (const [index, binding] of authorization.engineBindings.entries()) add(`engine-${index}`, { ...binding, byteLength: null }, { requireContentDigest: true });
    for (const [index, binding] of authorization.sourceBindings.entries()) add(`source-${index}`, binding);
    for (const [index, binding] of authorization.schemaBindings.entries()) add(`schema-${index}`, binding);
    const runtime = add('node-runtime', { path: authorization.runtime.executable, realpath: authorization.runtime.executable, rawSha256: authorization.runtime.rawSha256, byteLength: authorization.runtime.byteLength });
    for (const tree of authorization.runtimeDependencyTrees) for (const [index, binding] of tree.files.entries()) add(`runtime-${tree.packageName}-${index}`, binding);
    const entrypoints = authorization.endpoints.map((endpoint, index) => add(`entrypoint-${index}`, { ...endpoint.invocation.entrypointBinding, byteLength: null }));
    const helper = authorization.commitHelper;
    add('helper-descriptor', helper.descriptor, { requireContentDigest: true }); const helperBinary = add('helper-binary', helper.binary); add('helper-source', helper.source); add('helper-receipt', helper.buildReceipt, { requireContentDigest: true }); add('helper-manifest', helper.manifest, { requireContentDigest: true }); add('helper-checksums', helper.checksums);
    const moduleSpecifiers = authorization.endpoints.flatMap((endpoint, index) => endpoint.invocation.entrypointKind === 'module'
      ? [{ endpoint: `${endpoint.engineId}/${endpoint.endpointRole}`, specifier: `file:///proc/self/fd/${entrypoints[index].fd}` }]
      : []);
    return Object.freeze({ authorization, authorizationBytes: authorizationFile.bytes, authorizationBinding: Object.freeze({ path: AUTHORIZATION_REL, rawSha256: authorizationFile.rawSha256, byteLength: authorizationFile.byteLength, contentDigest: authorization.contentDigest }), retained: Object.freeze(retained), runtime, entrypoints: Object.freeze(entrypoints), moduleSpecifiers: Object.freeze(moduleSpecifiers), helperBinary, close: () => closeRetainedAuthoritySnapshot({ retained }) });
  } catch (error) { closeRetainedAuthoritySnapshot({ retained }); throw error; }
}

export function closeRetainedAuthoritySnapshot(snapshot) {
  const seen = new Set();
  for (const entry of snapshot?.retained ?? []) if (Number.isInteger(entry.fd) && !seen.has(entry.fd)) { seen.add(entry.fd); closeDescriptor(entry.fd); }
}

export function buildExecutionClaim({ authorization, authorizationBytes }) {
  assert(Buffer.isBuffer(authorizationBytes) && authorization?.contentDigest?.domain === AUTHORIZATION_DOMAIN, 'authorized descriptor bytes');
  const expected = buildAuthorizationTemplate();
  assert(authorization.contentDigest.value === expected.contentDigest.value, 'current authorization digest');
  const claim = {
    schema: 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3',
    claimId: 'execution-claim:cohort-executor-v3:attempt-001', status: 'claimed-unexecuted', attemptIndex: 1,
    authorizationBinding: { path: AUTHORIZATION_REL, rawSha256: sha(authorizationBytes), byteLength: authorizationBytes.length, contentDigest: authorization.contentDigest },
    contractBinding: expected.contractBinding, outputRoot: OUTPUT_REL, runtime: currentRuntime(),
    nonreusePolicy: 'exclusive-one-use-claim-consumes-attempt-001-even-if-output-absent',
  };
  claim.contentDigest = digestRecord(omit(claim), 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root');
  return Object.freeze(claim);
}

/** Exclusive, no-follow claim creation. Claim persistence happens before any endpoint callback. */
export function createExecutionClaim({ authorization, authorizationBytes }) {
  const claim = buildExecutionClaim({ authorization, authorizationBytes }); const bytes = canonicalBytes(claim);
  /* The authorization transport is already descriptor-read and must be the
   * sole pre-claim entry. A stale claim, extra file, wrong mode, or symlinked
   * namespace fails before the O_EXCL create. */
  ensureExactOwnedDirectory(path.dirname(abs(CLAIM_REL)), { expectedEntries: [path.basename(AUTHORIZATION_REL)] });
  const result = writeExclusiveFileNoFollow(abs(CLAIM_REL), bytes, { mode: 0o600 });
  return Object.freeze({ claim, bytes, binding: Object.freeze({ path: CLAIM_REL, rawSha256: result.rawSha256, byteLength: result.byteLength, contentDigest: claim.contentDigest }) });
}

export function encodeEndpointStdin(endpoint, readyRows) {
  assert(Array.isArray(readyRows) && readyRows.length === 4608, 'exact ready row set');
  const key = `${endpoint.engineId}/${endpoint.endpointRole}`;
  if (key === 'engine:native/primary') return encodeNativeModuleStdin(readyRows);
  if (key === 'engine:libauth/primary') return encodeLibauthModuleStdin(readyRows);
  if (key === 'engine:bchn/primary') return encodeBchnBatchStdin(readyRows);
  if (key === 'engine:leanbch/primary') return encodeLeanVmbconfStdin(readyRows);
  if (key === 'engine:leanbch/secondary') return encodeLeanCostprobeStdin(readyRows);
  throw new Error(`cohort-executor-v3 runner-open: unknown endpoint ${key}`);
}

function dispatchProcessGroup(child, signal) {
  try {
    assert(Number.isInteger(child.pid) && child.pid > 0, 'child pid unavailable'); process.kill(-child.pid, signal);
    return { kind: 'returned', value: true, error: null };
  } catch (error) { return { kind: 'threw', value: null, error: { name: error.name || 'Error', code: error.code ?? null, messageRawSha256: sha(Buffer.from(String(error.message ?? ''), 'utf8')) } }; }
}
function controllerAttempt(ordinal, reason, signal, graceMilliseconds, dispatchResult) {
  return Object.freeze({ ordinal, reason, signal, graceMilliseconds, requestedAtMonotonicNanoseconds: asDecimalNs(nowNs()), closeObservedBeforeRequest: false, dispatchResult });
}
async function writeBackpressured(writable, bytes) {
  /* Keep the error listener through the writable close, rather than removing
   * it as soon as write() accepts bytes. A child can reject the final end
   * after an apparently successful buffered write. */
  return await new Promise(resolve => {
    let firstError = null; let closed = false;
    const cleanup = () => { writable.removeListener('error', onError); writable.removeListener('close', onClose); writable.removeListener('drain', onDrain); };
    const complete = () => { if (closed) return; closed = true; cleanup(); resolve(firstError); };
    const onError = error => { if (firstError === null) firstError = error; try { if (!writable.destroyed) writable.destroy(); } catch {} };
    const onClose = () => complete();
    const onDrain = () => { try { writable.end(); } catch (error) { onError(error); } };
    writable.on('error', onError); writable.once('close', onClose);
    try { if (writable.write(bytes)) writable.end(); else writable.once('drain', onDrain); }
    catch (error) { onError(error); }
  });
}

/**
 * Capture one external endpoint using pre-opened durable stream files. It is
 * intentionally injectable for host-only synthetic child KATs. A cap applies
 * to stdout+stderr together, while stdin is bound independently.
 */
export async function captureExternalEndpoint({ endpoint, stdinBytes, streamDirectory, deadlineNs, spawnImpl = nodeSpawn, monotonicNow = nowNs, executableDescriptor = null, testOnlyAllowPathExecutable = false, dispatchImpl = dispatchProcessGroup, setTimer = setTimeout, clearTimer = clearTimeout, captureSlotFactory = openCaptureSlot }) {
  assert(endpoint?.endpointKind === 'external-process' && Buffer.isBuffer(stdinBytes), 'external endpoint/bytes');
  assert(typeof deadlineNs === 'bigint', 'absolute monotonic deadline');
  let stdinPath; let stdoutPath; let stderrPath; let stdout; let stderr;
  try {
    createScratchSubdirectory(streamDirectory);
    stdinPath = path.join(streamDirectory, 'stdin.bin'); stdoutPath = path.join(streamDirectory, 'stdout.bin'); stderrPath = path.join(streamDirectory, 'stderr.bin');
    writeExclusiveFileNoFollow(stdinPath, stdinBytes, { mode: 0o600 });
    const cap = 134217728; stdout = captureSlotFactory(stdoutPath, { capBytes: cap }); stderr = captureSlotFactory(stderrPath, { capBytes: cap });
  } catch (error) {
    /* No child has been spawned. Preserve any descriptor-created prefix in
     * the private scratch directory for a later failure publisher; callers
     * receive a deterministic, lossless controller error rather than a
     * cleanup race or an invented endpoint outcome. */
    const setup = Object.assign(new Error('external capture setup failed'), { code: 'RUNNER_SETUP_FAILURE', controllerError: structuredError(error), streamDirectory });
    throw setup;
  }
  const cap = 134217728;
  const argv = endpoint.invocation.argv;
  assert(Array.isArray(argv) && argv.length > 0 && path.isAbsolute(argv[0]), 'exact absolute external argv');
  if (executableDescriptor !== null) assert(Number.isInteger(executableDescriptor.fd) && executableDescriptor.fd >= 3 && executableDescriptor.rawSha256 === endpoint.invocation.entrypointBinding?.rawSha256, 'descriptor-bound external executable');
  else assert(testOnlyAllowPathExecutable === true, 'path-based external executable is test-only');
  const executable = executableDescriptor === null ? argv[0] : `/proc/self/fd/${executableDescriptor.fd}`;
  const startedAt = monotonicNow(); let child; let close = null; let transportError = null; let stdoutEnded = false; let stderrEnded = false; let capExceeded = false; let timedOut = false; let killAttempts = []; let capTimer = null; let graceTimer = null; let abortTimer = null; let captureError = null; let captureDisabled = false;
  const clearTimers = () => { if (capTimer !== null) clearTimer(capTimer); if (graceTimer !== null) clearTimer(graceTimer); if (abortTimer !== null) clearTimer(abortTimer); };
  const discardBeforeSpawnCapture = () => {
    captureDisabled = true; try { stdout.abort(); } catch {} try { stderr.abort(); } catch {}
    try { removeScratchLeavesNoFollow(streamDirectory, ['stdin.bin', 'stdout.bin', 'stderr.bin']); } catch {}
  };
  const finishSlots = () => Object.freeze({
    stdin: Object.freeze({ path: stdinPath, byteLength: stdinBytes.length, rawSha256: sha(stdinBytes), fsynced: true, captureStatus: 'complete' }),
    stdout: Object.freeze({ ...stdout.finish(), captureStatus: 'complete' }),
    stderr: Object.freeze({ ...stderr.finish(), captureStatus: 'complete' }),
  });
  const partialSlots = () => {
    captureDisabled = true;
    const seal = slot => { try { return Object.freeze({ ...slot.sealPartial(), captureStatus: 'partial' }); } catch { return null; } };
    const sealedStdout = seal(stdout); const sealedStderr = seal(stderr);
    if (sealedStdout === null || sealedStderr === null) return unavailableStreams();
    return Object.freeze({ stdin: Object.freeze({ path: stdinPath, byteLength: stdinBytes.length, rawSha256: sha(stdinBytes), fsynced: true, captureStatus: 'complete' }), stdout: sealedStdout, stderr: sealedStderr });
  };
  const abandoned = (terminalClosure, failureStage, error, { attribution = null, attempts = killAttempts, spawned = false, preserve = false, transport = null, controller = null } = {}) => {
    clearTimers();
    if (!spawned) discardBeforeSpawnCapture();
    const streams = preserve ? partialSlots() : unavailableStreams(); const durable = Object.values(streams).every(slot => slot.fsynced);
    const transportError = transport === null ? null : structuredError(transport); const controllerError = controller === null ? null : structuredError(controller);
    return Object.freeze({ status: 'failed', startedAtMonotonicNanoseconds: asDecimalNs(startedAt), exitCode: null, signal: null, parserStatus: 'incomplete', captureClosed: false, observedExitCode: null, observedSignal: null, timedOut, capExceeded, terminalClosure, failureStage, observedOutcomeAttribution: attribution, runnerError: transportError ?? controllerError, transportError, controllerError, killAttempts: Object.freeze(attempts), streams, lifecycle: Object.freeze({ spawnAttempted: true, spawnSucceeded: terminalClosure !== 'spawn-error', startObserved: terminalClosure !== 'spawn-error', exitEventObserved: false, closeEventObserved: false, stdoutEndObserved: false, stderrEndObserved: false, streamsFsynced: durable, captureClosed: false, stdinWriteError: null, spawnError: terminalClosure === 'spawn-error' ? structuredError(error) : null, transportError, controllerError }) });
  };
  const abandonBeforeSpawn = error => abandoned('spawn-error', 'spawn-error', error);
  let settleAbort; const abortWait = new Promise(resolve => { settleAbort = resolve; });
  const requestTermination = reason => {
    if (killAttempts.length > 0 || close !== null || child === undefined) return;
    if (reason === 'timeout') timedOut = true; if (reason === 'capture-limit') capExceeded = true;
    const term = controllerAttempt(0, reason, 'SIGTERM', 5000, dispatchImpl(child, 'SIGTERM')); killAttempts = [term];
    graceTimer = setTimer(() => {
      if (close !== null) return;
      if (term.dispatchResult.kind === 'returned' && term.dispatchResult.value === true) {
        const kill = controllerAttempt(1, reason, 'SIGKILL', 0, dispatchImpl(child, 'SIGKILL')); killAttempts = [term, kill];
        abortTimer = setTimer(() => { if (close === null) settleAbort({ kind: 'executor-abort', trigger: reason }); }, 5000);
      } else settleAbort({ kind: 'executor-abort', trigger: reason });
    }, 5000);
  };
  try { child = spawnImpl(executable, argv.slice(1), { cwd: endpoint.invocation.cwd, env: endpoint.invocation.environment, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'] }); } catch (error) { return abandonBeforeSpawn(error); }
  let spawnObserved = false; let resolveSpawn; const spawnedWait = new Promise(resolve => { resolveSpawn = resolve; }); let resolveTerminal; const terminalWait = new Promise(resolve => { resolveTerminal = resolve; });
  child.once('spawn', () => { spawnObserved = true; resolveSpawn({ ok: true, error: null }); });
  child.once('close', (code, signal) => { close = { code, signal, at: monotonicNow() }; resolveTerminal({ kind: 'close', ...close }); });
  child.on('error', error => {
    if (!spawnObserved) resolveSpawn({ ok: false, error });
    else if (transportError === null) { transportError = error; requestTermination('executor-abort'); }
  });
  const spawned = await spawnedWait; if (!spawned.ok) return abandonBeforeSpawn(spawned.error);
  const safeAppend = (slot, chunk) => {
    if (captureDisabled) return;
    try { const body = Buffer.from(chunk); const remaining = cap - stdout.byteLength - stderr.byteLength; if (remaining > 0) slot.append(body.subarray(0, remaining)); if (body.length > remaining) requestTermination('capture-limit'); }
    catch (error) { if (captureError === null) captureError = error; requestTermination('executor-abort'); }
  };
  const remainingMs = Number((deadlineNs - monotonicNow()) / 1000000n); if (remainingMs <= 0) requestTermination('timeout'); else capTimer = setTimer(() => requestTermination('timeout'), remainingMs);
  child.stdout.on('data', chunk => safeAppend(stdout, chunk)); child.stderr.on('data', chunk => safeAppend(stderr, chunk));
  child.stdout.once('end', () => { stdoutEnded = true; }); child.stderr.once('end', () => { stderrEnded = true; });
  let stdinError = null; const stdinCompletion = writeBackpressured(child.stdin, stdinBytes).then(error => { stdinError = error; });
  const terminal = await Promise.race([terminalWait, abortWait]); clearTimers();
  if (terminal.kind === 'executor-abort') {
    /* The child either closed through the terminal wait or exhausted the
     * bounded controller sequence. Never remove bytes produced after spawn. */
    return abandoned('executor-abort', 'executor-abort', captureError ?? transportError, { attribution: 'not-attributed-to-requested-signal', spawned: true, preserve: true, transport: transportError, controller: captureError });
  }
  await stdinCompletion;
  /* A normal early close can reject stdin after the kernel exit is already
   * observed. Preserve that exit (including exit 0) and classify only the
   * write failure; never fabricate a process failure. */
  if (!stdoutEnded || !stderrEnded) { if (captureError === null) captureError = new Error('close before stdout/stderr end'); return abandoned('executor-abort', 'executor-abort', captureError, { attribution: 'not-attributed-to-requested-signal', spawned: true, preserve: true, transport: transportError, controller: captureError }); }
  let streams; try { streams = finishSlots(); } catch (error) { return abandoned('executor-abort', 'executor-abort', error, { attribution: 'not-attributed-to-requested-signal', spawned: true, preserve: true, transport: transportError, controller: error }); }
  const observedExitCode = terminal.code === null ? null : terminal.code; const observedSignal = terminal.signal ?? null;
  /* A durable-stream append/fsync fault is controller-owned, even if the
   * child subsequently reports a normal kernel close. The observed kernel
   * outcome remains bound separately; it is never relabelled as process-exit. */
  const terminalClosure = transportError !== null || captureError !== null ? 'executor-abort' : capExceeded ? 'capture-limit' : timedOut ? 'timeout' : observedSignal !== null ? 'signal' : 'exit';
  const failureStage = transportError !== null || captureError !== null ? 'executor-abort' : capExceeded ? 'capture-limit' : timedOut ? 'timeout' : observedSignal !== null ? 'process-signal' : observedExitCode !== 0 ? 'process-exit' : stdinError !== null ? 'capture-write' : null;
  const completed = terminalClosure === 'exit' && observedExitCode === 0 && stdinError === null && captureError === null && transportError === null;
  const transport = transportError === null ? null : structuredError(transportError); const controller = captureError === null ? null : structuredError(captureError);
  return Object.freeze({ status: completed ? 'complete' : 'failed', startedAtMonotonicNanoseconds: asDecimalNs(startedAt), observedCloseAtMonotonicNanoseconds: asDecimalNs(terminal.at), exitCode: observedExitCode, signal: observedSignal, parserStatus: 'complete', captureClosed: true, observedExitCode, observedSignal, timedOut, capExceeded, terminalClosure, failureStage, observedOutcomeAttribution: killAttempts.length > 0 ? 'not-attributed-to-requested-signal' : null, runnerError: transport ?? controller, transportError: transport, controllerError: controller, killAttempts: Object.freeze(killAttempts), streams, lifecycle: Object.freeze({ spawnAttempted: true, spawnSucceeded: true, startObserved: true, exitEventObserved: true, closeEventObserved: true, stdoutEndObserved: true, stderrEndObserved: true, streamsFsynced: true, captureClosed: true, stdinWriteError: stdinError === null ? null : structuredError(stdinError), spawnError: null, transportError: transport, controllerError: controller }) });
}

/** Capture an in-process Native/Libauth transcript without inventing verdicts.
 * The supplied evaluator must return one observed canonical row at a time;
 * stdout is appended and fsynced per completed LF row, stdin/stderr are exact
 * intentional zero-byte files. This helper never imports or invokes a VM. */
export async function captureModuleEndpoint({ endpoint, readyRows, streamDirectory, evaluateRow }) {
  assert(endpoint?.endpointKind === 'module-ndjson' && Array.isArray(readyRows) && readyRows.length === 4608 && typeof evaluateRow === 'function', 'module endpoint/rows/evaluator');
  createScratchSubdirectory(streamDirectory);
  const stdinPath = path.join(streamDirectory, 'stdin.bin'); const stdoutPath = path.join(streamDirectory, 'stdout.bin'); const stderrPath = path.join(streamDirectory, 'stderr.bin');
  writeExclusiveFileNoFollow(stdinPath, Buffer.alloc(0)); writeExclusiveFileNoFollow(stderrPath, Buffer.alloc(0));
  const stdout = openCaptureSlot(stdoutPath, { capBytes: 134217728, fsyncEachAppend: true }); let count = 0; let thrown = null;
  try {
    for (const row of readyRows) {
      const observed = await evaluateRow(row);
      assert(observed && typeof observed === 'object' && observed.workItemId === row.workItem.workItemId, `module observed row identity ${count}`);
      const body = Buffer.from(`${JSON.stringify(canonicalize(observed))}\n`, 'utf8'); stdout.append(body); count += 1;
    }
  } catch (error) { thrown = error; }
  /* finish after both the success and throw paths: any LF-complete prefix is
     independently durable before a later failure publisher observes it. */
  const finished = Object.freeze({ ...stdout.finish(), captureStatus: 'complete' });
  const streams = Object.freeze({ stdin: zeroStream(stdinPath), stdout: finished, stderr: zeroStream(stderrPath) });
  if (thrown !== null) {
    return Object.freeze({
      status: 'failed', exitCode: null, signal: null, parserStatus: 'incomplete', captureClosed: true,
      observedExitCode: null, observedSignal: null, timedOut: false, capExceeded: false,
      terminalClosure: 'module-error', failureStage: 'module-error', rowPrefixCardinality: count,
      error: structuredError(thrown), streams,
      lifecycle: Object.freeze({ invocationStarted: true, returned: false, threw: true, moduleErrorClass: thrown?.name || 'Error', moduleErrorMessageDigest: sha(Buffer.from(String(thrown?.message ?? ''), 'utf8')), captureClosed: true, streamsFsynced: true, fsyncPerCompletedRow: true }),
    });
  }
  return Object.freeze({ status: 'complete', exitCode: null, signal: null, parserStatus: 'complete', captureClosed: true, observedExitCode: null, observedSignal: null, timedOut: false, capExceeded: false, terminalClosure: 'module-complete', failureStage: null, rowPrefixCardinality: count, streams, lifecycle: Object.freeze({ invocationStarted: true, returned: true, threw: false, moduleErrorClass: null, moduleErrorMessageDigest: null, captureClosed: true, streamsFsynced: true, fsyncPerCompletedRow: true }) });
}

/** Lean is one logical batch: the secondary receives the exact remaining time
 * from the primary's shared 600-second monotonic deadline, never a fresh one. */
export async function captureLeanPair({ primary, secondary, primaryStdin, secondaryStdin, streamRoot, deadlineMilliseconds = 600000, spawnImpl = nodeSpawn, monotonicNow = nowNs, executableDescriptors = null, testOnlyAllowPathExecutable = false }) {
  assert(primary?.engineId === 'engine:leanbch' && primary.endpointRole === 'primary' && secondary?.engineId === 'engine:leanbch' && secondary.endpointRole === 'secondary', 'exact Lean endpoint order');
  assert(Number.isSafeInteger(deadlineMilliseconds) && deadlineMilliseconds === 600000, 'exact shared Lean deadline');
  const deadlineNs = monotonicNow() + BigInt(deadlineMilliseconds) * 1000000n;
  const first = await captureExternalEndpoint({ endpoint: primary, stdinBytes: primaryStdin, streamDirectory: path.join(streamRoot, 'primary'), deadlineNs, spawnImpl, monotonicNow, executableDescriptor: executableDescriptors?.primary ?? null, testOnlyAllowPathExecutable });
  if (first.status !== 'complete') return Object.freeze({ deadlineMilliseconds, primary: first, secondary: null, sharedDeadline: true });
  const second = await captureExternalEndpoint({ endpoint: secondary, stdinBytes: secondaryStdin, streamDirectory: path.join(streamRoot, 'secondary'), deadlineNs, spawnImpl, monotonicNow, executableDescriptor: executableDescriptors?.secondary ?? null, testOnlyAllowPathExecutable });
  return Object.freeze({ deadlineMilliseconds, primary: first, secondary: second, sharedDeadline: true });
}

/**
 * Commit a fully validated scratch directory via the independently sealed
 * Linux renameat2 helper. All three file/directory authorities are opened,
 * fstat-checked, and hashed before the child receives inherited fd 3/4/5;
 * neither the binary nor either parent is reopened by pathname afterwards.
 */
function assertAuthorizedCommitHelper(authorizedHelper, currentHelper) {
  assert(authorizedHelper && typeof authorizedHelper === 'object', 'authorized commit helper is required');
  for (const key of ['descriptor', 'binary', 'source', 'buildReceipt', 'manifest', 'checksums']) {
    /* Artifact identifiers are authorization-envelope labels. The helper's
     * own current binding deliberately omits them, so compare the complete
     * byte authority after removing only that envelope-only label. */
    const { artifactId = undefined, ...binding } = authorizedHelper[key] ?? {};
    if (['descriptor', 'buildReceipt', 'manifest'].includes(key)) assert(typeof artifactId === 'string' && artifactId.length > 0, `authorized commit helper ${key} artifact id`);
    else assert(artifactId === undefined, `authorized commit helper ${key} artifact id`);
    assert(canonicalBytes(binding).equals(canonicalBytes(currentHelper[key])), `authorized commit helper ${key}`);
  }
  assert(canonicalBytes(authorizedHelper.interface).equals(canonicalBytes(currentHelper.interface)) && canonicalBytes(authorizedHelper.syscall).equals(canonicalBytes(currentHelper.syscall)), 'authorized commit helper interface');
}

export async function commitNoReplaceWithPinnedHelper({ scratchRoot, destinationRoot, authorizedHelper, retainedHelperBinary = null, spawnImpl = nodeSpawn }) {
  assert(path.isAbsolute(scratchRoot) && path.isAbsolute(destinationRoot), 'absolute commit roots');
  assert(path.dirname(scratchRoot) === path.dirname(destinationRoot), 'same parent commit roots');
  assert(!path.basename(scratchRoot).includes('.') || path.basename(scratchRoot).endsWith('.scratch'), 'scratch basename');
  assert(!path.basename(destinationRoot).includes('.') && !path.basename(destinationRoot).includes('/'), 'destination basename');
  const helper = currentCommitHelperBinding(); assertAuthorizedCommitHelper(authorizedHelper, helper);
  const binary = retainedHelperBinary ?? openRegularFileDescriptorNoFollow(helper.binary.realpath);
  let sourceParent = null; let destinationParent = null; let sourceDirectory = null;
  try {
    assert(binary.realpath === helper.binary.realpath && binary.rawSha256 === helper.binary.rawSha256 && binary.byteLength === helper.binary.byteLength, 'helper binary descriptor snapshot');
    sourceParent = openDirectoryDescriptorNoFollow(path.dirname(scratchRoot), { requireOwned: true }); destinationParent = openDirectoryDescriptorNoFollow(path.dirname(destinationRoot), { requireOwned: true }); sourceDirectory = openDirectoryDescriptorNoFollow(scratchRoot, { requireOwned: true });
    const stdout = []; const stderr = []; let overflow = false;
    const child = spawnImpl('/proc/self/fd/6', [path.basename(scratchRoot), path.basename(destinationRoot)], { cwd: '/', env: {}, shell: false, detached: false, stdio: ['ignore', 'pipe', 'pipe', sourceParent, destinationParent, sourceDirectory, binary.fd] });
    child.stdout.on('data', chunk => { const body = Buffer.from(chunk); if (Buffer.concat(stdout).length + body.length > 65536) overflow = true; else stdout.push(body); });
    child.stderr.on('data', chunk => { const body = Buffer.from(chunk); if (Buffer.concat(stderr).length + body.length > 65536) overflow = true; else stderr.push(body); });
    const outcome = await new Promise((resolve, reject) => { child.once('error', reject); child.once('close', (exitCode, signal) => resolve({ exitCode, signal })); });
    assert(!overflow && Buffer.concat(stdout).length === 0 && Buffer.concat(stderr).length === 0, 'helper output protocol');
    assert(outcome.exitCode === 0 && outcome.signal === null, `renameat2 helper failed ${outcome.exitCode ?? outcome.signal}`);
    fsyncDescriptor(destinationParent);
    return Object.freeze({ helper, exitCode: outcome.exitCode, signal: outcome.signal, noReplace: true });
  } finally { if (retainedHelperBinary === null) closeDescriptor(binary.fd); closeDescriptor(sourceDirectory); closeDescriptor(sourceParent); closeDescriptor(destinationParent); }
}

/** Execute-only success-commit transition. The payload writer must already
 * have placed all 28 container files in the exact fixed scratch directory;
 * this function validates that directory, invokes the authenticated helper,
 * fsyncs the destination parent in the helper path, then revalidates the
 * canonical final path. No callback can substitute a commit primitive. */
export async function commitExactValidatedSuccess({ authorizationBytes, claimBytes, authorization, retainedHelperBinary = null, spawnImpl = nodeSpawn }) {
  const scratchRoot = `${abs(OUTPUT_REL)}.scratch`; const destinationRoot = abs(OUTPUT_REL);
  validateScratchBeforeAtomicCommit({ scratchRoot, authorizationBytes, claimBytes });
  const commit = await commitNoReplaceWithPinnedHelper({ scratchRoot, destinationRoot, authorizedHelper: authorization?.commitHelper, retainedHelperBinary, spawnImpl });
  const final = revalidateCommittedSuccess();
  return Object.freeze({ ...commit, final });
}

/** Execute-only protocol. A live driver must provide observed 24 payloads; no expected output is synthesized. */
export async function executeAuthorizedAttempt() {
  const opened = readAuthorizationByDescriptor();
  /* Do not consume the attempt until the missing internal observed-evidence
     builder and sealed failure publisher exist. In particular, a caller can
     never inject raw/normalized/cross payloads into the production path. */
  assert(opened.authorization.contentDigest.value === buildAuthorizationTemplate().contentDigest.value, 'descriptor/current authority digest');
  throw new Error('cohort-executor-v3 runner-open: live observed-evidence builder, retained authority snapshot, and sealed failure publisher are not integrated; execute remains gated before claim creation');
}

export const RUNNER_OPEN_BOUNDARY = Object.freeze({ defaultExecution: false, realEnginesInvokedAtImport: false, maxConcurrency: 1, endpointOrder, externalCombinedOutputCapBytes: 134217728, leanSharedDeadlineMilliseconds: 600000, evidenceBuilder: typeof deriveCompleteSuccessPayloadBytes === 'function', commit: 'pinned-renameat2-no-replace-helper-integrated-after-full-scratch-validation', claim: 'exclusive-no-follow-0600-fsync-before-endpoint' });
