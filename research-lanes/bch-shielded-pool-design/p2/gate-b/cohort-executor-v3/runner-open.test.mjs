import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawn } from 'node:child_process';
import { captureExternalEndpoint, captureLeanPair, captureModuleEndpoint, commitNoReplaceWithPinnedHelper, encodeEndpointStdin, executeAuthorizedAttempt, RUNNER_OPEN_BOUNDARY } from './runner-open.mjs';
import { buildAuthorizationTemplate } from './authority.mjs';
import { createScratchDirectory, ensureExactOwnedDirectory, fsyncDirectory, openCaptureSlot, readRegularFileNoFollow, requirePinnedNoReplaceDirectoryCommit, writeExclusiveFileNoFollow } from './durable-io.mjs';

const sha = body => crypto.createHash('sha256').update(body).digest('hex');
const mk = () => fs.mkdtempSync(path.join(os.tmpdir(), 'cohort-executor-v3-runner-'));
const cleanup = root => fs.rmSync(root, { recursive: true, force: true });
const deadline = milliseconds => process.hrtime.bigint() + BigInt(milliseconds) * 1000000n;
const endpoint = script => Object.freeze({ endpointKind: 'external-process', engineId: 'engine:bchn', endpointRole: 'primary', invocation: Object.freeze({ argv: Object.freeze([process.execPath, '-e', script]), cwd: os.tmpdir(), environment: Object.freeze({}), stdinCodec: 'synthetic-test' }) });
const moduleEndpoint = Object.freeze({ endpointKind: 'module-ndjson', engineId: 'engine:native', endpointRole: 'primary' });
const readyRows = () => Array.from({ length: 4608 }, (_, index) => Object.freeze({ workItem: Object.freeze({ workItemId: `synthetic-work-${index}` }) }));

test('descriptor reader binds one no-follow inode and rejects a symlink leaf', () => {
  const root = mk(); try {
    fs.mkdirSync(path.join(root, 'a'), { mode: 0o700 }); fs.writeFileSync(path.join(root, 'a', 'authority.json'), Buffer.from('{"x":1}\n'));
    const read = readRegularFileNoFollow(root, 'a/authority.json'); assert.equal(read.rawSha256, sha(Buffer.from('{"x":1}\n'))); assert.equal(read.byteLength, 8);
    fs.symlinkSync('authority.json', path.join(root, 'a', 'alias.json')); assert.throws(() => readRegularFileNoFollow(root, 'a/alias.json'), /symbolic|ELOOP/i);
  } finally { cleanup(root); }
});

test('exclusive 0600 durable write and scratch root are race/mode/fsync guarded', () => {
  const root = mk(); try {
    const auth = path.join(root, 'auth'); fs.mkdirSync(auth, { mode: 0o700 });
    const file = path.join(auth, 'claim.json'); const first = writeExclusiveFileNoFollow(file, Buffer.from('claim\n'));
    assert.equal(first.byteLength, 6); assert.equal(fs.statSync(file).mode & 0o777, 0o600); assert.throws(() => writeExclusiveFileNoFollow(file, Buffer.from('second\n')), /EEXIST/);
    const scratch = path.join(root, 'attempt-001.scratch'); const result = createScratchDirectory(scratch, root); assert.equal(result.mode, 0o700); assert.equal(fs.statSync(scratch).mode & 0o777, 0o700); fsyncDirectory(root);
  } finally { cleanup(root); }
});

test('claim namespace is private, exact, and refuses stale or extra entries before O_EXCL claim creation', () => {
  const root = mk(); try {
    fs.chmodSync(root, 0o700); const namespace = path.join(root, 'authorization'); ensureExactOwnedDirectory(namespace);
    writeExclusiveFileNoFollow(path.join(namespace, 'attempt-001.authorization.v3.json'), Buffer.from('auth\n'));
    assert.equal(ensureExactOwnedDirectory(namespace, { expectedEntries: ['attempt-001.authorization.v3.json'] }), namespace);
    writeExclusiveFileNoFollow(path.join(namespace, 'stale-claim.json'), Buffer.from('claim\n'));
    assert.throws(() => ensureExactOwnedDirectory(namespace, { expectedEntries: ['attempt-001.authorization.v3.json'] }), /namespace/);
  } finally { cleanup(root); }
});

test('capture slots enforce partial-write cap and durable close', () => {
  const root = mk(); try {
    const slot = openCaptureSlot(path.join(root, 'out.bin'), { capBytes: 3 }); slot.append(Buffer.from('ab')); assert.throws(() => slot.append(Buffer.from('cd')), /cap exceeded/); const bound = slot.finish(); assert.equal(bound.byteLength, 2); assert.equal(bound.fsynced, true);
  } finally { cleanup(root); }
});

test('synthetic external child capture binds stdin/stdout/stderr, backpressure, and normal exit', async () => {
  const root = mk(); try {
    const script = "process.stdin.on('data',x=>process.stdout.write(x));process.stdin.on('end',()=>process.stderr.write('done\\n'));";
    const result = await captureExternalEndpoint({ endpoint: endpoint(script), stdinBytes: Buffer.alloc(1024 * 128, 0x61), streamDirectory: path.join(root, 'capture'), deadlineNs: deadline(5000), spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(result.status, 'complete'); assert.equal(result.observedExitCode, 0); assert.equal(result.streams.stdin.byteLength, 1024 * 128); assert.equal(fs.readFileSync(result.streams.stdout.path).length, 1024 * 128); assert.equal(fs.readFileSync(result.streams.stderr.path).toString(), 'done\n');
  } finally { cleanup(root); }
});

test('pathname execution is test-only; a future production runner must supply a retained executable fd', async () => {
  const root = mk(); try {
    await assert.rejects(() => captureExternalEndpoint({ endpoint: endpoint('process.exit(0)'), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'capture'), deadlineNs: deadline(5000), spawnImpl: spawn }), /test-only/);
  } finally { cleanup(root); }
});

test('synthetic nonzero, signal, spawn, and timeout paths remain terminal and non-attributed unless controller-killed', async () => {
  const root = mk(); try {
    const nonzero = await captureExternalEndpoint({ endpoint: endpoint('process.exit(7)'), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'nonzero'), deadlineNs: deadline(5000), spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(nonzero.terminalClosure, 'exit'); assert.equal(nonzero.failureStage, 'process-exit'); assert.equal(nonzero.observedExitCode, 7); assert.equal(nonzero.status, 'failed');
    const signal = await captureExternalEndpoint({ endpoint: endpoint("process.kill(process.pid, 'SIGTERM')"), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'signal'), deadlineNs: deadline(5000), spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(signal.terminalClosure, 'signal'); assert.equal(signal.observedOutcomeAttribution, null);
    const timeout = await captureExternalEndpoint({ endpoint: endpoint('setInterval(()=>{},1000)'), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'timeout'), deadlineNs: deadline(25), spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(timeout.timedOut, true); assert.equal(timeout.killAttempts[0].signal, 'SIGTERM'); assert.equal(timeout.observedOutcomeAttribution, 'not-attributed-to-requested-signal');
    const missing = Object.freeze({ ...endpoint(''), invocation: Object.freeze({ ...endpoint('').invocation, argv: Object.freeze(['/definitely-not-cohort-executor-v3']) }) });
    const failed = await captureExternalEndpoint({ endpoint: missing, stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'spawn'), deadlineNs: deadline(5000), spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(failed.status, 'failed'); assert.equal(failed.terminalClosure, 'spawn-error'); assert.equal(failed.failureStage, 'spawn-error'); assert.ok(Object.values(failed.streams).every(slot => slot.captureStatus === 'unavailable' && slot.path === null)); assert.equal(fs.readdirSync(path.join(root, 'spawn')).length, 0);
  } finally { cleanup(root); }
});

test('failed TERM dispatch reaches the bounded executor-abort fallback without rewriting its timeout intent', async () => {
  const root = mk(); try {
    const immediateTimer = callback => setTimeout(callback, 0); const result = await captureExternalEndpoint({
      endpoint: endpoint('setTimeout(()=>process.exit(0),100)'), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'fallback'), deadlineNs: deadline(5000), spawnImpl: spawn, testOnlyAllowPathExecutable: true,
      dispatchImpl: () => ({ kind: 'returned', value: false, error: null }), setTimer: immediateTimer,
    });
    assert.equal(result.status, 'failed'); assert.equal(result.terminalClosure, 'executor-abort'); assert.equal(result.failureStage, 'executor-abort'); assert.equal(result.killAttempts.length, 1); assert.equal(result.killAttempts[0].reason, 'timeout'); assert.equal(result.killAttempts[0].dispatchResult.value, false); assert.equal(result.captureClosed, false); assert.ok(Object.values(result.streams).every(slot => slot.fsynced)); assert.ok(Object.values(result.streams).some(slot => slot.captureStatus === 'partial'));
    await new Promise(resolve => setTimeout(resolve, 125));
  } finally { cleanup(root); }
});

test('an asynchronous capture append fault is routed through the controller boundary, never thrown from a stream callback', async () => {
  const root = mk(); try {
    let slotOrdinal = 0; const result = await captureExternalEndpoint({
      endpoint: endpoint('process.stdout.write("synthetic-output");setTimeout(()=>process.exit(0),100)'), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'append-fault'), deadlineNs: deadline(100), spawnImpl: spawn, testOnlyAllowPathExecutable: true,
      dispatchImpl: () => ({ kind: 'returned', value: false, error: null }), setTimer: (callback, milliseconds) => setTimeout(callback, milliseconds === 5000 ? 0 : milliseconds),
      captureSlotFactory: (...args) => { const slot = openCaptureSlot(...args); slotOrdinal += 1; return slotOrdinal === 1 ? Object.freeze({ ...slot, append: () => { throw Object.assign(new Error('synthetic append fault'), { code: 'EIO' }); } }) : slot; },
    });
    assert.equal(result.status, 'failed'); assert.equal(result.terminalClosure, 'executor-abort'); assert.equal(result.failureStage, 'executor-abort'); assert.ok(result.controllerError); assert.equal(result.killAttempts[0].reason, 'executor-abort');
    await new Promise(resolve => setTimeout(resolve, 125));
  } finally { cleanup(root); }
});

test('a post-spawn transport error enters bounded controller teardown and preserves its separate durable cause', async () => {
  const root = mk(); try {
    const spawnWithInjectedPostSpawnError = (...args) => { const child = spawn(...args); child.once('spawn', () => setImmediate(() => child.emit('error', Object.assign(new Error('synthetic post-spawn transport error'), { code: 'EIO' })))); return child; };
    const result = await captureExternalEndpoint({ endpoint: endpoint('setTimeout(()=>process.exit(0),100)'), stdinBytes: Buffer.alloc(0), streamDirectory: path.join(root, 'post-spawn'), deadlineNs: deadline(5000), spawnImpl: spawnWithInjectedPostSpawnError, testOnlyAllowPathExecutable: true });
    assert.equal(result.status, 'failed'); assert.equal(result.terminalClosure, 'executor-abort'); assert.equal(result.failureStage, 'executor-abort'); assert.equal(result.killAttempts[0].reason, 'executor-abort'); assert.ok(result.transportError); assert.equal(result.controllerError, null); assert.ok(Object.values(result.streams).every(slot => slot.fsynced));
  } finally { cleanup(root); }
});

test('stdin delivery failure after an early normal exit is never complete', async () => {
  const root = mk(); try {
    const result = await captureExternalEndpoint({ endpoint: endpoint('process.stdin.destroy();process.exit(0)'), stdinBytes: Buffer.alloc(1024 * 1024, 0x61), streamDirectory: path.join(root, 'early-exit'), deadlineNs: deadline(5000), spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(result.terminalClosure, 'exit'); assert.equal(result.observedExitCode, 0); assert.equal(result.status, 'failed'); assert.equal(result.failureStage, 'capture-write'); assert.ok(result.lifecycle.stdinWriteError); assert.equal(result.runnerError, null);
  } finally { cleanup(root); }
});

test('stdin keeps its error listener through end completion and captures a late end-time transport failure', async () => {
  const root = mk(); try {
    const lateErrorSpawn = (...args) => { const child = spawn(...args); child.once('spawn', () => child.stdin.once('finish', () => setImmediate(() => child.stdin.emit('error', Object.assign(new Error('synthetic late stdin error'), { code: 'EPIPE' }))))); return child; };
    const result = await captureExternalEndpoint({ endpoint: endpoint('process.stdin.resume();process.stdin.on("end",()=>setTimeout(()=>process.exit(0),40))'), stdinBytes: Buffer.from('late\n'), streamDirectory: path.join(root, 'late-stdin'), deadlineNs: deadline(5000), spawnImpl: lateErrorSpawn, testOnlyAllowPathExecutable: true });
    assert.equal(result.status, 'failed'); assert.equal(result.failureStage, 'capture-write'); assert.equal(result.terminalClosure, 'exit'); assert.ok(result.lifecycle.stdinWriteError); assert.equal(result.lifecycle.stdinWriteError.code, 'EPIPE');
  } finally { cleanup(root); }
});

test('module evaluator throw closes/fsyncs its durable LF prefix and returns module-error', async () => {
  const root = mk(); try {
    const rows = readyRows(); let calls = 0;
    const result = await captureModuleEndpoint({ endpoint: moduleEndpoint, readyRows: rows, streamDirectory: path.join(root, 'module'), evaluateRow: async row => {
      calls += 1; if (calls === 2) throw Object.assign(new Error('synthetic module throw'), { code: 'ESYNTH' }); return { workItemId: row.workItem.workItemId, verdict: 'accept' };
    } });
    assert.equal(result.status, 'failed'); assert.equal(result.terminalClosure, 'module-error'); assert.equal(result.failureStage, 'module-error'); assert.equal(result.rowPrefixCardinality, 1); assert.equal(result.lifecycle.threw, true); assert.equal(result.lifecycle.streamsFsynced, true); assert.equal(result.streams.stdout.fsynced, true); assert.match(fs.readFileSync(result.streams.stdout.path, 'utf8'), /synthetic-work-0/);
  } finally { cleanup(root); }
});

test('Lean primary and secondary share one deadline and exact endpoint order', async () => {
  const root = mk(); try {
    const primary = Object.freeze({ ...endpoint('process.stdout.write("primary\\n")'), engineId: 'engine:leanbch', endpointRole: 'primary' });
    const secondary = Object.freeze({ ...endpoint('process.stdout.write("secondary\\n")'), engineId: 'engine:leanbch', endpointRole: 'secondary' });
    const pair = await captureLeanPair({ primary, secondary, primaryStdin: Buffer.alloc(0), secondaryStdin: Buffer.alloc(0), streamRoot: root, deadlineMilliseconds: 600000, spawnImpl: spawn, testOnlyAllowPathExecutable: true });
    assert.equal(pair.sharedDeadline, true); assert.equal(pair.primary.status, 'complete'); assert.equal(pair.secondary.status, 'complete');
  } finally { cleanup(root); }
});

test('runner uses fixed serial endpoint order, exact codecs reject incomplete row sets, and no-replace commit stays closed', () => {
  assert.deepEqual(RUNNER_OPEN_BOUNDARY.endpointOrder, ['engine:native/primary', 'engine:libauth/primary', 'engine:bchn/primary', 'engine:leanbch/primary', 'engine:leanbch/secondary']);
  assert.equal(RUNNER_OPEN_BOUNDARY.maxConcurrency, 1); assert.throws(() => encodeEndpointStdin({ engineId: 'engine:bchn', endpointRole: 'primary' }, []), /ready row/);
  const root = mk(); try { const scratch = path.join(root, 'scratch'); fs.mkdirSync(scratch); assert.throws(() => requirePinnedNoReplaceDirectoryCommit({ scratchRoot: scratch, destinationRoot: path.join(root, 'attempt-001') }), /renameat2/); fs.mkdirSync(path.join(root, 'attempt-001')); assert.throws(() => requirePinnedNoReplaceDirectoryCommit({ scratchRoot: scratch, destinationRoot: path.join(root, 'attempt-001') }), /precondition/); } finally { cleanup(root); }
});

test('pinned renameat2 helper commits an owner-only temp scratch by inherited file descriptors only', async () => {
  const root = mk(); try {
    fs.chmodSync(root, 0o700); const scratch = path.join(root, 'attempt-001.scratch'); const destination = path.join(root, 'attempt-001'); fs.mkdirSync(scratch, { mode: 0o700 }); fs.writeFileSync(path.join(scratch, 'synthetic'), 'x');
    const result = await commitNoReplaceWithPinnedHelper({ scratchRoot: scratch, destinationRoot: destination, authorizedHelper: buildAuthorizationTemplate().commitHelper });
    assert.equal(result.exitCode, 0); assert.equal(result.signal, null); assert.equal(result.helper.binary.rawSha256, 'da9aa54fb5318a093d46bb797293465d1f2c6a12ca53c397e35ea07a36d17943'); assert.equal(fs.existsSync(scratch), false); assert.equal(fs.readFileSync(path.join(destination, 'synthetic'), 'utf8'), 'x');
  } finally { cleanup(root); }
});

test('default execute cannot reach a child process without the exact absent authorization', async () => {
  await assert.rejects(() => executeAuthorizedAttempt(), /absent|ENOENT|no such/i);
});
