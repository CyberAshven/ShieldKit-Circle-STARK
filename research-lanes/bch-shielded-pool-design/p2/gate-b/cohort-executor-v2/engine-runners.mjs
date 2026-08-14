/**
 * The only engine dispatch surface. Importing this module is inert: process
 * creation is reachable solely from executeAuthorized after its exact
 * authorization validation has passed.
 */
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import {
  buildBchnInvocationDescriptor,
  buildLeanCostprobeInvocationDescriptor,
  buildLeanVmbconfInvocationDescriptor,
  evaluateLibauthVerifiedRow,
  parseBchnBatchStdout,
  parseLeanCostprobeStdout,
  parseLeanVmbconfAggregate,
  replayNativeDirectExtension,
  TX_CHECKS_UNSUPPORTED,
} from '../cohort-execution-v2/engine-adapters.mjs';

export const ENGINE_ORDER = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
const canonical = (value) => `${JSON.stringify(value, null, 2)}\n`;
const streamPath = (engineId, role, processRole = null) => `attempt-000/raw/${engineId}/${processRole ? `${processRole}-` : ''}${role}.log`;
const utf8 = (bytes, label) => {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (error) { throw new Error(`${label} is not strict UTF-8: ${error.message}`); }
};
const bytes = (value, label) => {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  throw new Error(`${label} must be exact bytes or UTF-8 text`);
};
const ndjsonTranscript = (engineId, rows, evaluate) => {
  const observations = new Map();
  const lines = [];
  let byteStart = 0;
  for (const row of rows) {
    const result = evaluate(row);
    // A successful script-engine verdict has a canonical terminal stage even
    // when the Libauth evaluator exposes no finer stage field. Rejections are
    // not guessed: null remains null unless the engine exposed a stage.
    const entry = { workItemId: row.workItem.workItemId, verdict: result.verdict, failureStage: result.stage ?? (result.verdict === 'accept' ? 'accept' : null), metrics: result.metrics ?? null, txChecks: result.txChecks ?? TX_CHECKS_UNSUPPORTED, phase: result.phase, terminalStatus: result.terminalStatus };
    const line = `${JSON.stringify(entry)}\n`;
    const encoded = Buffer.from(line, 'utf8');
    observations.set(entry.workItemId, { ...entry, sourceStream: { path: streamPath(engineId, 'stdout'), byteStart, byteEnd: byteStart + encoded.length, lineStart: lines.length + 1, lineEnd: lines.length + 1, spanSha256: sha(encoded) } });
    lines.push(line); byteStart += encoded.length;
  }
  return { stdout: Buffer.from(lines.join(''), 'utf8'), observations };
};
const spansByWorkItem = (buffer, stream, identify) => {
  const found = new Map(); let start = 0; let line = 1;
  for (let end = 0; end < buffer.length; end += 1) {
    if (buffer[end] !== 0x0a) continue;
    const span = buffer.subarray(start, end + 1);
    const id = identify(utf8(buffer.subarray(start, end), `${stream} line ${line}`));
    if (id !== null) {
      assert(!found.has(id), `${stream} duplicate work item ${id}`);
      found.set(id, { path: stream, byteStart: start, byteEnd: end + 1, lineStart: line, lineEnd: line, spanSha256: sha(span) });
    }
    start = end + 1; line += 1;
  }
  assert(start === buffer.length, `${stream} must end with LF`);
  return found;
};

const exactProcess = (descriptor, timeoutMs, maxBufferBytes) => {
  assert(descriptor && Array.isArray(descriptor.argv) && descriptor.argv.length > 0, 'pinned process descriptor required');
  assert(typeof descriptor.cwd === 'string' && descriptor.cwd.length > 0, 'pinned process cwd required');
  assert(descriptor.environment && typeof descriptor.environment === 'object', 'closed process environment required');
  const [file, ...args] = descriptor.argv;
  const result = spawnSync(file, args, {
    cwd: descriptor.cwd,
    env: { ...descriptor.environment },
    input: bytes(descriptor.stdin, 'process stdin'),
    encoding: null,
    shell: false,
    timeout: timeoutMs,
    maxBuffer: maxBufferBytes,
  });
  assert(!result.error, `engine process failed to start: ${result.error?.message ?? 'unknown'}`);
  assert(result.signal === null, `engine process timed out or was signaled: ${result.signal}`);
  assert(Number.isInteger(result.status), 'engine process exit status unavailable');
  return Object.freeze({ stdin: bytes(descriptor.stdin, 'process stdin'), stdout: Buffer.from(result.stdout ?? Buffer.alloc(0)), stderr: Buffer.from(result.stderr ?? Buffer.alloc(0)), exitCode: result.status, timedOut: false });
};
const assertAuthorizedDescriptor = (descriptor, authorization, engineId, role = 'primary') => {
  const engine = authorization?.engines?.find((item) => item.engineId === engineId); assert(engine, `authorization engine missing: ${engineId}`);
  const argv = role === 'secondary' ? engine.secondaryEntrypointArgv : engine.entrypointArgv;
  const endpoint = role === 'secondary' ? engine.secondaryEntrypoint : engine.entrypoint;
  const expectedArgv = argv?.length ? argv : [endpoint.realpath];
  assert(JSON.stringify(descriptor.argv) === JSON.stringify(expectedArgv) && descriptor.cwd === engine.cwd && JSON.stringify(descriptor.environment) === JSON.stringify(engine.environment), `external descriptor differs from authorization: ${engineId}/${role}`);
};

const inProcessTranscript = (engineId, rows, evaluate) => {
  const { stdout, observations } = ndjsonTranscript(engineId, rows, evaluate);
  assert(observations.size === rows.length, `${engineId} transcript work-item duplication`);
  return Object.freeze({
    engineId,
    status: 'complete',
    invocation: { entrypointKind: 'module', entrypoints: [], stdinCodec: 'in-process-canonical-transcript-v1', environment: {}, runtime: {}, implementationDigest: sha(Buffer.from(engineId)) },
    streams: new Map([[streamPath(engineId, 'stdin'), Buffer.alloc(0)], [streamPath(engineId, 'stdout'), stdout], [streamPath(engineId, 'stderr'), Buffer.alloc(0)]]),
    processResults: Object.freeze({ primary: Object.freeze({ exitCode: null, timedOut: false }) }),
    observations,
  });
};

export const runNativeBatch = async ({ engineId, rows }) => {
  assert(engineId === 'engine:native', 'native runner identity drift');
  return inProcessTranscript(engineId, rows, (row) => replayNativeDirectExtension({ caseEntry: row.caseEntry, fixture: row.fixture }));
};

export const runLibauthBatch = async ({ engineId, rows }) => {
  assert(engineId === 'engine:libauth', 'libauth runner identity drift');
  return inProcessTranscript(engineId, rows, (row) => evaluateLibauthVerifiedRow(row));
};

export const runBchnBatch = async ({ engineId, rows, artifacts, authorization, timeoutMs, maxBufferBytes }) => {
  assert(engineId === 'engine:bchn', 'BCHN runner identity drift');
  const descriptor = buildBchnInvocationDescriptor(rows, { artifacts });
  assertAuthorizedDescriptor(descriptor, authorization, engineId);
  const process = exactProcess(descriptor, timeoutMs, maxBufferBytes);
  assert(process.exitCode === 0, `BCHN exited ${process.exitCode}`);
  const stdout = utf8(process.stdout, 'BCHN stdout');
  const parsed = parseBchnBatchStdout(stdout, { rows });
  const sourceSpans = spansByWorkItem(process.stdout, streamPath(engineId, 'stdout'), (line) => JSON.parse(line).ident);
  const observations = new Map();
  for (const row of rows) {
    const result = parsed.get(row.workItem.workItemId);
    assert(result?.phaseClass === 'script-engine', `BCHN outer/vector result is not agreement-eligible: ${row.workItem.workItemId}`);
    observations.set(row.workItem.workItemId, { workItemId: row.workItem.workItemId, verdict: result.outcome, failureStage: result.outcome === 'accept' ? 'accept' : null, metrics: result.metrics ?? null, txChecks: result.txChecks, phase: result.phase, terminalStatus: 'supported', sourceStream: sourceSpans.get(row.workItem.workItemId) });
  }
  return Object.freeze({ engineId, status: 'complete', invocation: descriptor, streams: new Map([[streamPath(engineId, 'stdin'), process.stdin], [streamPath(engineId, 'stdout'), process.stdout], [streamPath(engineId, 'stderr'), process.stderr]]), processResults: Object.freeze({ primary: Object.freeze({ exitCode: process.exitCode, timedOut: process.timedOut }) }), observations });
};

export const runLeanBatch = async ({ engineId, rows, artifacts, authorization, timeoutMs, maxBufferBytes }) => {
  assert(engineId === 'engine:leanbch', 'LeanBCH runner identity drift');
  // This clock is enforcement-only. It is intentionally never emitted as a
  // metric, timestamp, or evidence field.
  const deadline = process.hrtime.bigint() + BigInt(timeoutMs) * 1_000_000n;
  const remaining = () => { const nanos = deadline - process.hrtime.bigint(); assert(nanos > 0n, 'Lean logical batch deadline exhausted'); return Number((nanos + 999_999n) / 1_000_000n); };
  const primary = buildLeanVmbconfInvocationDescriptor(rows, { artifacts });
  assertAuthorizedDescriptor(primary, authorization, engineId, 'primary');
  const primaryProcess = exactProcess(primary, remaining(), maxBufferBytes);
  assert(primaryProcess.exitCode === 0, `Lean vmbconf exited ${primaryProcess.exitCode}`);
  const aggregate = parseLeanVmbconfAggregate(utf8(primaryProcess.stdout, 'Lean vmbconf stdout'), { rows });
  assert(aggregate.aggregateOnly === true && aggregate.countedAsAgreement === false, 'Lean aggregate boundary drift');
  const secondary = buildLeanCostprobeInvocationDescriptor(rows, { artifacts });
  assertAuthorizedDescriptor(secondary, authorization, engineId, 'secondary');
  const secondaryProcess = exactProcess(secondary, remaining(), maxBufferBytes);
  assert(secondaryProcess.exitCode === 0, `Lean CostProbe exited ${secondaryProcess.exitCode}`);
  const parsed = parseLeanCostprobeStdout(utf8(secondaryProcess.stdout, 'Lean costprobe stdout'), { rows });
  const sourceSpans = spansByWorkItem(secondaryProcess.stdout, streamPath(engineId, 'stdout', 'secondary'), (line) => /^(?:METRICS|SKIP) ([^\s]+)/u.exec(line)?.[1] ?? null);
  const observations = new Map();
  for (const row of rows) {
    const result = parsed.get(row.workItem.workItemId);
    // Complete-only materialization: a SKIP is terminally unsupported and is
    // intentionally cleaned rather than misrepresented as a complete run.
    assert(result?.supportStatus === 'supported', `Lean CostProbe unsupported/incomplete: ${row.workItem.workItemId}`);
    observations.set(row.workItem.workItemId, { workItemId: row.workItem.workItemId, verdict: result.verdict, failureStage: result.verdict === 'accept' ? 'accept' : null, metrics: result.metrics, txChecks: result.txChecks, phase: result.phase, terminalStatus: 'supported', sourceStream: sourceSpans.get(row.workItem.workItemId) });
  }
  return Object.freeze({
    engineId,
    status: 'complete',
    invocation: Object.freeze({ entrypointKind: 'paired', entrypoints: [primary, secondary], stdinCodec: primary.stdinCodec, environment: primary.environment, runtime: {}, implementationDigest: sha(Buffer.from('lean-primary-costprobe-v1')) }),
    aggregate,
    streams: new Map([
      [streamPath(engineId, 'stdin', 'primary'), primaryProcess.stdin], [streamPath(engineId, 'stdout', 'primary'), primaryProcess.stdout], [streamPath(engineId, 'stderr', 'primary'), primaryProcess.stderr],
      [streamPath(engineId, 'stdin', 'secondary'), secondaryProcess.stdin], [streamPath(engineId, 'stdout', 'secondary'), secondaryProcess.stdout], [streamPath(engineId, 'stderr', 'secondary'), secondaryProcess.stderr],
    ]),
    processResults: Object.freeze({ primary: Object.freeze({ exitCode: primaryProcess.exitCode, timedOut: primaryProcess.timedOut }), secondary: Object.freeze({ exitCode: secondaryProcess.exitCode, timedOut: secondaryProcess.timedOut }) }),
    observations,
  });
};

export const defaultRunners = Object.freeze({ 'engine:native': runNativeBatch, 'engine:libauth': runLibauthBatch, 'engine:bchn': runBchnBatch, 'engine:leanbch': runLeanBatch });
export const assertDefaultRunnerOrder = () => assert(Object.keys(defaultRunners).join('|') === ENGINE_ORDER.join('|'), 'default runner engine order drift');
export const streamPathFor = streamPath;
