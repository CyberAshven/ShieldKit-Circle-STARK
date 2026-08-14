import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { CANONICALIZATION, FRAME, EVIDENCE_DOMAINS, assertArtifactLifecycle, canonicalBytes, canonicalize, contractPaths, digestRecord, omit, validateEvidenceShape, evidenceAuthorityRows, validateContract } from '../cohort-execution-v3/contract.mjs';
import { encodeBchnBatchStdin, encodeLeanCostprobeStdin, encodeLeanVmbconfStdin, encodeLibauthModuleStdin, encodeNativeModuleStdin, parseCanonicalNdjsonTranscript, parseBchnEffectsTranscript, parseLeanCostprobeAuthority, parseLeanAggregateCorroboration } from '../cohort-execution-v3/adapters.mjs';
import { deriveVerifiedFixtureRows } from '../cohort-execution-v3/fixtures.mjs';
import { AUTHORIZATION_REL, CLAIM_REL, OUTPUT_REL, SUCCESS_REL, buildAuthorizationTemplate, validateAuthorizationObject, expectedEndpoints } from './authority.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = contractPaths.workspace;
const sha = body => crypto.createHash('sha256').update(body).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-executor-v3 evidence validator: ${message}`); };
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));
const exact = (left, right, label) => assert(JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right)), label);
const strictText = (body, label) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(body); } catch (error) { throw new Error(`cohort-executor-v3 evidence validator: ${label} invalid UTF-8: ${error.message}`); } };
export const parseCanonicalEvidenceJson = (body, label = 'evidence JSON') => {
  const value = JSON.parse(strictText(body, label));
  assert(Buffer.isBuffer(body) && body.equals(canonicalBytes(value)), `${label} noncanonical or duplicate-key JSON`);
  return value;
};
const canonicalJson = parseCanonicalEvidenceJson;
const json = file => canonicalJson(fs.readFileSync(file), file);
const staticJson = file => JSON.parse(strictText(fs.readFileSync(file), file));
const engineOrder = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'];
const safeRel = value => { assert(typeof value === 'string' && value.length > 0 && !path.isAbsolute(value) && !value.includes('\\') && !value.split('/').includes('..'), `unsafe path ${value}`); return value; };

export function successPayloadPaths() {
  const paths = [];
  for (const engineId of engineOrder) {
    paths.push({ kind: 'raw-artifact', engineId, endpointRole: null, streamRole: null, path: `raw/${engineId}/raw-engine-observation.v3.json` });
    const endpoints = engineId === 'engine:leanbch' ? ['primary', 'secondary'] : ['primary'];
    for (const endpointRole of endpoints) for (const streamRole of ['stdin', 'stdout', 'stderr']) paths.push({ kind: 'raw-stream', engineId, endpointRole, streamRole, path: `raw/${engineId}/${endpointRole}-${streamRole}.bin` });
  }
  for (const engineId of engineOrder) paths.push({ kind: 'normalized-artifact', engineId, endpointRole: null, streamRole: null, path: `normalized/${engineId}/normalized-engine-result.v3.json` });
  paths.push({ kind: 'cross-engine-summary', engineId: null, endpointRole: null, streamRole: null, path: 'cross-engine-summary.v3.json' });
  paths.push({ kind: 'authorization-copy', engineId: null, endpointRole: null, streamRole: null, path: 'authorization.json' });
  paths.push({ kind: 'execution-claim-copy', engineId: null, endpointRole: null, streamRole: null, path: 'execution-claim.json' });
  assert(paths.length === 26, 'success payload count'); return Object.freeze(paths);
}
function file(root, relative) {
  safeRel(relative); let cursor = root;
  for (const part of relative.split('/')) { cursor = path.join(cursor, part); const st = fs.lstatSync(cursor); assert(!st.isSymbolicLink(), `symlink ${relative}`); }
  const real = fs.realpathSync(cursor); assert(real.startsWith(`${root}${path.sep}`) && fs.statSync(real).isFile() && (!Number.isInteger(fs.statSync(real).nlink) || fs.statSync(real).nlink === 1), `regular file ${relative}`); return real;
}
/* Production transports are intentionally not caller-provided.  An
 * authorization or claim alias could otherwise validate bytes unrelated to
 * the exclusive external namespace consumed by execution. */
export function readExactWorkspaceTransport(relative) {
  assert([AUTHORIZATION_REL, CLAIM_REL].includes(relative), 'unknown external transport');
  const expected = path.resolve(workspace, relative);
  assert(expected === `${workspace}${path.sep}${relative}`, 'external transport lexical path');
  assert(fs.existsSync(expected), `external transport absent ${relative}`);
  let cursor = workspace;
  for (const part of relative.split('/')) {
    cursor = path.join(cursor, part);
    const st = fs.lstatSync(cursor);
    assert(!st.isSymbolicLink(), `external transport symlink ${relative}`);
  }
  const stat = fs.statSync(cursor);
  assert(stat.isFile() && (!Number.isInteger(stat.nlink) || stat.nlink === 1), `external transport regular ${relative}`);
  assert(fs.realpathSync(cursor) === expected, `external transport alias ${relative}`);
  return fs.readFileSync(cursor);
}
function closure(root, listed) {
  const files = []; const dirs = [];
  const walk = (folder, relative = '') => { for (const name of fs.readdirSync(folder).sort(byteSort)) { const child = path.join(folder, name); const next = relative ? `${relative}/${name}` : name; const st = fs.lstatSync(child); assert(!st.isSymbolicLink(), `container symlink ${next}`); if (st.isDirectory()) { dirs.push(next); walk(child, next); } else { assert(st.isFile() && (!Number.isInteger(st.nlink) || st.nlink === 1), `container nonregular ${next}`); files.push(next); } } };
  walk(root); files.sort(byteSort); dirs.sort(byteSort); exact(files, [...listed].sort(byteSort), 'container file closure'); const expectedDirs = new Set(); for (const name of listed) { const parts = name.split('/'); for (let i = 1; i < parts.length; i += 1) expectedDirs.add(parts.slice(0, i).join('/')); } exact(dirs, [...expectedDirs].sort(byteSort), 'container directory closure');
}
function schemaCheck(name, value) { const ajv = new Ajv2020({ allErrors: true, strict: true }); const validate = ajv.compile(staticJson(path.join(here, name))); assert(validate(value), `${name}: ${ajv.errorsText(validate.errors)}`); }
export function validateEvidenceSchema(name, value) {
  assert(['authorization.v3.schema.json', 'execution-claim.v3.schema.json', 'raw-engine-observation.v3.schema.json', 'normalized-engine-result.v3.schema.json', 'cross-engine-summary.v3.schema.json', 'evidence-manifest.v3.schema.json', 'evidence-root.v3.schema.json'].includes(name), `unknown evidence schema ${name}`);
  schemaCheck(name, value); return true;
}
function verifyDigest(record, value, domain, label) { assert(record?.algorithm === 'sha256' && record.canonicalization === CANONICALIZATION && record.frame === FRAME && record.domain === domain && record.value === digestRecord(value, domain).value, `${label} digest`); }
function binding(root, relative, { contentDomain = null } = {}) { const body = fs.readFileSync(file(root, relative)); const value = relative.endsWith('.json') ? canonicalJson(body, relative) : null; const output = { path: relative, rawSha256: sha(body), byteLength: body.length, ...(value?.contentDigest ? { contentDigest: value.contentDigest } : {}) }; if (contentDomain !== null) verifyDigest(value.contentDigest, omit(value), contentDomain, relative); return output; }

const terminalFromEndpoint = endpoint => endpoint.timedOut ? 'timeout'
  : endpoint.parserStatus === 'failure' ? 'parser-failure'
    : endpoint.exitCode !== null || endpoint.signal !== null ? (endpoint.exitCode === 0 && endpoint.signal === null ? 'observed' : 'process-failure')
      : 'not-run-incomplete';
const endpointKey = (engineId, role) => `${engineId}/${role}`;
const transcriptPayload = payload => {
  const { sourceStream: _sourceStream, ...rest } = payload;
  return rest;
};
function strictLfLines(body, label) {
  const text = strictText(body, label);
  assert(!text.includes('\r') && text.endsWith('\n'), `${label} LF-only final newline`);
  const lines = text.slice(0, -1).split('\n'); assert(lines.every(line => line.length > 0), `${label} blank line`);
  return { text, lines };
}
function lfLineRecords(body, label) {
  strictLfLines(body, label);
  const lines = []; let start = 0;
  for (let index = 0; index < body.length; index += 1) if (body[index] === 0x0a) { lines.push({ start, end: index + 1 }); start = index + 1; }
  assert(start === body.length, `${label} final LF`);
  return lines;
}
function lineSpan(body, source, label) {
  assert(Number.isSafeInteger(source.byteStart) && Number.isSafeInteger(source.byteEnd) && source.byteStart >= 0 && source.byteEnd > source.byteStart && source.byteEnd <= body.length, `${label} byte bounds`);
  assert((source.byteStart === 0 || body[source.byteStart - 1] === 0x0a) && body[source.byteEnd - 1] === 0x0a, `${label} LF span bounds`);
  const span = body.subarray(source.byteStart, source.byteEnd);
  assert(sha(span) === source.spanSha256, `${label} span hash`);
  const before = body.subarray(0, source.byteStart); const start = before.length === 0 ? 1 : before.filter(byte => byte === 0x0a).length + 1;
  const end = start + span.filter(byte => byte === 0x0a).length - 1;
  assert(source.lineStart === start && source.lineEnd === end && start === end, `${label} line bounds`);
  return span;
}
function streamBinding(root, endpoint, role, expectedEntry) {
  const body = fs.readFileSync(file(root, endpoint[role].path));
  exact({ path: endpoint[role].path, rawSha256: sha(body), byteLength: body.length, mediaType: endpoint[role].mediaType, manifestPath: endpoint[role].manifestPath, manifestEntryDigest: endpoint[role].manifestEntryDigest }, endpoint[role], `stream binding ${endpoint.role}/${role}`);
  exact(endpoint[role].path, expectedEntry.path, `stream path ${endpoint.role}/${role}`);
  assert(endpoint[role].manifestPath === 'evidence-manifest.v3.json', `stream manifest path ${endpoint.role}/${role}`);
  exact(endpoint[role].manifestEntryDigest, expectedEntry.manifestEntryDigest, `stream manifest entry ${endpoint.role}/${role}`);
  return body;
}
function validateInvocationAndLifecycle(root, raw, authEndpoints, manifestEntries) {
  const expected = authEndpoints.filter(item => item.engineId === raw.engineId);
  const endpoints = raw.invocation.entrypoints;
  assert(expected.length === endpoints.length && raw.lifecycle.endpoints.length === endpoints.length, `endpoint count ${raw.engineId}`);
  const streams = new Set(); const endpointRows = new Map();
  for (let ordinal = 0; ordinal < endpoints.length; ordinal += 1) {
    const endpoint = endpoints[ordinal]; const auth = expected[ordinal]; const lifecycle = raw.lifecycle.endpoints[ordinal];
    assert(endpoint.role === auth.endpointRole && endpoint.endpointKind === auth.endpointKind, `endpoint role/kind ${raw.engineId}/${ordinal}`);
    exact({ argv: endpoint.argv, cwd: endpoint.cwd, environment: endpoint.environment, runtime: endpoint.runtime, path: endpoint.path, rawSha256: endpoint.rawSha256 }, { argv: auth.invocation.argv, cwd: auth.invocation.cwd, environment: auth.invocation.environment, runtime: auth.invocation.runtime, path: auth.invocation.entrypointBinding.path, rawSha256: auth.invocation.entrypointBinding.rawSha256 }, `endpoint authority ${raw.engineId}/${endpoint.role}`);
    assert(lifecycle.role === endpoint.role && lifecycle.exitCode === endpoint.exitCode && lifecycle.signal === endpoint.signal && lifecycle.timedOut === endpoint.timedOut && lifecycle.parserStatus === endpoint.parserStatus && lifecycle.captureClosed === endpoint.captureClosed, `endpoint lifecycle ${raw.engineId}/${endpoint.role}`);
    if (endpoint.endpointKind === 'module-ndjson') assert(endpoint.argv === null && endpoint.exitCode === null && endpoint.signal === null && endpoint.timedOut === false && endpoint.parserStatus === 'complete' && endpoint.captureClosed === true, `module endpoint invariant ${raw.engineId}`);
    else assert(Array.isArray(endpoint.argv) && endpoint.argv.length > 0 && endpoint.exitCode === 0 && endpoint.signal === null && endpoint.timedOut === false && endpoint.captureClosed === true && endpoint.parserStatus === 'complete', `external complete endpoint invariant ${raw.engineId}/${endpoint.role}`);
    for (const streamRole of ['stdin', 'stdout', 'stderr']) {
      const stream = endpoint[streamRole]; assert(!streams.has(stream.path), `duplicate stream path ${stream.path}`); streams.add(stream.path);
      const entry = manifestEntries.get(stream.path); assert(entry?.kind === 'raw-stream' && entry.engineId === raw.engineId && entry.endpointRole === endpoint.role && entry.streamRole === streamRole, `stream manifest role ${stream.path}`);
      streamBinding(root, endpoint, streamRole, entry);
    }
    if (endpoint.endpointKind === 'module-ndjson') assert(endpoint.stdin.byteLength === 0 && endpoint.stderr.byteLength === 0, `module null-stream invariant ${raw.engineId}`);
    if (endpoint.endpointKind === 'external-process') assert(endpoint.stdout.byteLength + endpoint.stderr.byteLength <= 134217728, `external combined output cap ${raw.engineId}/${endpoint.role}`);
    endpointRows.set(endpoint.role, endpoint);
  }
  assert(streams.size === endpoints.length * 3, `unique stream count ${raw.engineId}`);
  exact(raw.engineBinding, { engineId: raw.engineId, ...authEndpoints.find(item => item.engineId === raw.engineId).invocation.engineBinding }, `raw engine binding ${raw.engineId}`);
  exact(raw.invocation.stdinCodecs, expected.map(item => item.invocation.stdinCodec), `raw invocation codecs ${raw.engineId}`);
  assert(raw.invocation.implementationDigest === expected[0].invocation.implementationDigest && expected.every(item => item.invocation.implementationDigest === raw.invocation.implementationDigest), `raw invocation implementation ${raw.engineId}`);
  assertArtifactLifecycle(raw, `raw invocation lifecycle ${raw.engineId}`);
  return endpointRows;
}
function expectedStdinBytes(raw, verifiedRows) {
  const rows = verifiedRows.byEngine[raw.engineId].filter(row => !row.preflightLimitViolation);
  if (raw.engineId === 'engine:native') return new Map([['primary', encodeNativeModuleStdin(rows)]]);
  if (raw.engineId === 'engine:libauth') return new Map([['primary', encodeLibauthModuleStdin(rows)]]);
  if (raw.engineId === 'engine:bchn') return new Map([['primary', encodeBchnBatchStdin(rows)]]);
  return new Map([['primary', encodeLeanVmbconfStdin(rows)], ['secondary', encodeLeanCostprobeStdin(rows)]]);
}
function validateStdinBytes(root, raw, endpoints, verifiedRows) {
  const expected = expectedStdinBytes(raw, verifiedRows);
  for (const [role, bytes] of expected) {
    const endpoint = endpoints.get(role); const actual = fs.readFileSync(file(root, endpoint.stdin.path));
    assert(actual.equals(bytes), `stdin fixture/order/codec bytes ${raw.engineId}/${role}`);
  }
}
function validateRawTranscriptSpans(root, raw, authority, endpoints) {
  const rows = authority.byEngine.get(raw.engineId);
  const executableRows = rows.filter((row, ordinal) => {
    const fixture = authority.fixtureRoster.records[ordinal];
    return !Boolean(fixture.preflightLimitViolation?.scriptSig || fixture.preflightLimitViolation?.redeem);
  });
  const parserEndpoint = raw.engineId === 'engine:leanbch' ? endpoints.get('secondary') : endpoints.get('primary');
  const stdout = fs.readFileSync(file(root, parserEndpoint.stdout.path));
  const records = lfLineRecords(stdout, `${raw.engineId} stdout`);
  const fixtureByKey = new Map(authority.fixtureRoster.records.map(record => [record.fixtureKey, record]));
  const expectedById = new Map(rows.map(row => [row.workItemId, authority.cases.get(fixtureByKey.get(row.fixtureKey).epochIdentity.caseKey).expected]));
  let parsed;
  if (raw.engineId === 'engine:native' || raw.engineId === 'engine:libauth') parsed = parseCanonicalNdjsonTranscript(stdout, { rows: executableRows, engineId: raw.engineId });
  else if (raw.engineId === 'engine:bchn') parsed = parseBchnEffectsTranscript(stdout, { rows: executableRows });
  else parsed = parseLeanCostprobeAuthority(strictText(stdout, 'Lean CostProbe stdout'), { rows: executableRows });
  const lineOffset = raw.engineId === 'engine:leanbch' ? 1 : 0;
  assert(records.length === 4608 + lineOffset, `stdout line count ${raw.engineId}`);
  if (raw.engineId === 'engine:leanbch') assert(strictText(stdout.subarray(records[0].start, records[0].end), 'Lean CostProbe header') === 'ORACLE reject\n', 'Lean CostProbe header');
  const occupied = []; let parsedOrdinal = 0;
  for (const rawRow of raw.rows) {
    if (rawRow.disposition !== 'observed' && rawRow.disposition !== 'engine-unsupported-incomplete') continue;
    const observation = rawRow.rawObservation; assert(observation?.kind === 'structured' && observation.endpointRole === parserEndpoint.role, `structured parser endpoint ${raw.engineId}/${rawRow.workItemOrdinal}`);
    assert(observation.exitCode === (parserEndpoint.endpointKind === 'module-ndjson' ? 0 : parserEndpoint.exitCode) && observation.parserStatus === parserEndpoint.parserStatus, `observation endpoint outcome ${raw.engineId}/${rawRow.workItemOrdinal}`);
    const source = observation.payload.sourceStream; assert(source.path === parserEndpoint.stdout.path && source.artifactRawSha256 === sha(stdout) && source.artifactByteLength === stdout.length && source.manifestPath === 'evidence-manifest.v3.json', `source stream authority ${raw.engineId}/${rawRow.workItemOrdinal}`);
    exact(source.manifestEntryDigest, parserEndpoint.stdout.manifestEntryDigest, `source stream manifest entry ${raw.engineId}/${rawRow.workItemOrdinal}`);
    const line = records[lineOffset + parsedOrdinal];
    assert(rawRow.workItemId === executableRows[parsedOrdinal].workItemId && source.byteStart === line.start && source.byteEnd === line.end, `source span row-order binding ${raw.engineId}/${rawRow.workItemOrdinal}`);
    const span = lineSpan(stdout, source, `${raw.engineId}/${rawRow.workItemOrdinal}`); occupied.push([source.byteStart, source.byteEnd]);
    const transcript = parsed.get(rawRow.workItemId); assert(transcript, `parsed row omitted ${raw.engineId}/${rawRow.workItemId}`);
    if (raw.engineId === 'engine:leanbch' && transcript.status === 'engine-unsupported-incomplete') {
      assert(rawRow.disposition === 'engine-unsupported-incomplete' && observation.payload.verdict === null && observation.payload.metrics === null && observation.payload.terminalStatus === 'engine-unsupported-incomplete', `Lean SKIP disposition ${rawRow.workItemOrdinal}`);
    } else {
      assert(rawRow.disposition === 'observed', `non-SKIP observed disposition ${raw.engineId}/${rawRow.workItemOrdinal}`);
      const canonical = raw.engineId === 'engine:leanbch'
        ? { workItemId: transcript.workItemId, verdict: transcript.verdict, failureStage: transcript.verdict === 'accept' ? 'accept' : null, metrics: transcript.metrics, txChecks: 'unsupported', phase: 'costprobe', terminalStatus: 'observed' }
        : transcript;
      exact(transcriptPayload(observation.payload), canonical, `transcript payload ${raw.engineId}/${rawRow.workItemOrdinal}`);
    }
    const text = strictText(span, `span ${raw.engineId}/${rawRow.workItemOrdinal}`); assert(text.endsWith('\n') && !text.includes('\r'), `span strict LF ${raw.engineId}/${rawRow.workItemOrdinal}`);
    parsedOrdinal += 1;
  }
  occupied.sort((a, b) => a[0] - b[0]); let cursor = 0;
  if (raw.engineId === 'engine:leanbch') cursor = records[0].end;
  for (const [start, end] of occupied) { assert(start === cursor && end > start, `stdout span gap/overlap ${raw.engineId}`); cursor = end; }
  assert(cursor === stdout.length && occupied.length === parsed.size && parsed.size === 4608 && parsedOrdinal === executableRows.length, `stdout span partition ${raw.engineId}`);
  if (raw.status === 'complete') for (const rawRow of raw.rows) if (rawRow.disposition === 'observed') assert(rawRow.rawObservation.payload.terminalStatus === 'observed', `complete artifact terminal status ${raw.engineId}/${rawRow.workItemOrdinal}`);
  if (raw.engineId === 'engine:leanbch') {
    const primary = endpoints.get('primary'); const aggregate = parseLeanAggregateCorroboration(strictText(fs.readFileSync(file(root, primary.stdout.path)), 'Lean vmbconf stdout'), { rows: executableRows });
    let rejectedValid = 0; let acceptedInvalid = 0;
    for (const row of raw.rows) if (row.disposition === 'observed') { const output = parsed.get(row.workItemId); const expected = expectedById.get(row.workItemId).verdict; if (output.verdict === 'reject' && expected === 'accept') rejectedValid += 1; if (output.verdict === 'accept' && expected === 'reject') acceptedInvalid += 1; }
    assert(aggregate.rejectedValid === rejectedValid && aggregate.acceptedInvalid === acceptedInvalid, 'Lean aggregate/per-item disagreement');
  }
}

export function validateExecutionClaimCopy(claimBytes, authorization, authorizationBytes) {
  const claim = canonicalJson(claimBytes, 'execution claim');
  schemaCheck('execution-claim.v3.schema.json', claim);
  verifyDigest(claim.contentDigest, omit(claim), 'shieldkit-labs/p2/gate-b/cohort-executor-v3/execution-claim/v3/root', 'execution claim');
  assert(claim.attemptIndex === 1 && claim.outputRoot === OUTPUT_REL && claim.status === 'claimed-unexecuted', 'claim attempt/output/status');
  exact(claim.authorizationBinding, { path: AUTHORIZATION_REL, rawSha256: sha(authorizationBytes), byteLength: authorizationBytes.length, contentDigest: authorization.contentDigest }, 'claim authorization binding');
  const contract = buildAuthorizationTemplate().contractBinding;
  exact(claim.contractBinding, { path: contract.path, rawSha256: contract.rawSha256, byteLength: contract.byteLength, contentDigest: contract.contentDigest }, 'claim contract binding');
  exact(claim.runtime, authorization.runtime, 'claim runtime');
  return Object.freeze(claim);
}
function artifactRootBinding(root, relative, artifact) {
  const body = fs.readFileSync(file(root, relative));
  return { engineId: artifact.engineId, batchOrdinal: artifact.engineBatchOrdinal, shardIndex: artifact.shardIndex, shardCount: artifact.shardCount, path: relative, rawSha256: sha(body), byteLength: body.length, contentDigest: artifact.contentDigest.value, status: artifact.status };
}
function contentCopyBinding(root, relative) {
  const body = fs.readFileSync(file(root, relative)); const value = canonicalJson(body, relative);
  return { path: relative, rawSha256: sha(body), byteLength: body.length, contentDigest: value.contentDigest };
}

/**
 * Read-only full semantic validator for an already-captured complete success
 * container. It cannot authorize, spawn, decode a transaction, or run a VM.
 * The future durable writer/capture/runner remains a separate gate.
 */
function validateSuccessContainer({ successRoot, authorizationBytes, claimBytes, synthetic = false, staged = false }) {
  assert(!(synthetic && staged), 'success validation mode');
  if (!synthetic && !staged) assert(path.resolve(successRoot) === path.resolve(workspace, SUCCESS_REL), 'exact external success root');
  else if (synthetic) assert(path.basename(path.resolve(successRoot)) === 'success' && !path.resolve(successRoot).startsWith(`${workspace}${path.sep}`), 'synthetic success root must be an isolated temporary directory');
  else assert(path.resolve(successRoot) === `${path.resolve(workspace, OUTPUT_REL)}.scratch${path.sep}success`, 'exact staged success root');
  assert(Buffer.isBuffer(authorizationBytes) && Buffer.isBuffer(claimBytes), 'authorization and claim buffers');
  validateContract();
  const authorization = canonicalJson(authorizationBytes, 'authorization');
  validateAuthorizationObject(authorization);
  validateExecutionClaimCopy(claimBytes, authorization, authorizationBytes);
  const root = fs.realpathSync(successRoot); assert(root === path.resolve(successRoot) && fs.statSync(root).isDirectory(), 'success root real directory');
  const attempt = path.dirname(root); const siblings = fs.readdirSync(attempt).sort(byteSort); exact(siblings, ['success'], 'success/failure exclusivity');
  const payloads = successPayloadPaths(); const expected = ['evidence-root.v3.json', 'evidence-manifest.v3.json', ...payloads.map(item => item.path)]; closure(root, expected);
  const manifest = json(file(root, 'evidence-manifest.v3.json')); schemaCheck('evidence-manifest.v3.schema.json', manifest); verifyDigest(manifest.contentDigest, omit(manifest), 'shieldkit-labs/p2/gate-b/execution-evidence/v3/manifest/root', 'manifest');
  const entries = payloads.map((item, ordinal) => { const body = fs.readFileSync(file(root, item.path)); const core = { ordinal, ...item, rawSha256: sha(body), byteLength: body.length }; return { ...core, manifestEntryDigest: digestRecord(core, `shieldkit-labs/p2/gate-b/execution-evidence/v3/manifest/entry/${item.path}`) }; });
  exact(manifest.files, entries, 'manifest payload inventory');
  assert(manifest.files.length === 26 && manifest.evidenceRootExcluded === true && manifest.selfManifestExcluded === true, 'manifest coverage');
  verifyDigest(manifest.inventoryDigest, manifest.files, 'shieldkit-labs/p2/gate-b/execution-evidence/v3/manifest/inventory', 'manifest inventory');
  const manifestEntries = new Map(entries.map(entry => [entry.path, entry]));
  const rawArtifacts = engineOrder.map(engineId => json(file(root, `raw/${engineId}/raw-engine-observation.v3.json`))); const normalizedArtifacts = engineOrder.map(engineId => json(file(root, `normalized/${engineId}/normalized-engine-result.v3.json`))); const crossSummary = json(file(root, 'cross-engine-summary.v3.json'));
  for (const artifact of rawArtifacts) schemaCheck('raw-engine-observation.v3.schema.json', artifact); for (const artifact of normalizedArtifacts) schemaCheck('normalized-engine-result.v3.schema.json', artifact); schemaCheck('cross-engine-summary.v3.schema.json', crossSummary);
  const authority = evidenceAuthorityRows(); const verifiedRows = deriveVerifiedFixtureRows(); const endpointAuthority = expectedEndpoints();
  const allStreamPaths = new Set();
  for (const raw of rawArtifacts) {
    const endpoints = validateInvocationAndLifecycle(root, raw, endpointAuthority, manifestEntries);
    assert(raw.status === 'complete', `success raw artifact status ${raw.engineId}`);
    for (const endpoint of raw.invocation.entrypoints) for (const role of ['stdin', 'stdout', 'stderr']) { assert(!allStreamPaths.has(endpoint[role].path), `cross-engine reused stream ${endpoint[role].path}`); allStreamPaths.add(endpoint[role].path); }
    validateRawTranscriptSpans(root, raw, authority, endpoints);
    validateStdinBytes(root, raw, endpoints, verifiedRows);
  }
  assert(allStreamPaths.size === 15, 'all fifteen raw streams unique');
  for (const normalized of normalizedArtifacts) assert(normalized.status === 'complete', `success normalized artifact status ${normalized.engineId}`);
  assert(crossSummary.status === 'complete', 'success cross status');
  validateEvidenceShape({ rawArtifacts, normalizedArtifacts, crossSummary });
  const authCopy = fs.readFileSync(file(root, 'authorization.json')); const claimCopy = fs.readFileSync(file(root, 'execution-claim.json')); assert(authCopy.equals(authorizationBytes) && claimCopy.equals(claimBytes), 'authorization/claim exact copies');
  const rootValue = json(file(root, 'evidence-root.v3.json')); schemaCheck('evidence-root.v3.schema.json', rootValue); verifyDigest(rootValue.contentDigest, omit(rootValue), 'shieldkit-labs/p2/gate-b/execution-evidence/v3/root', 'evidence root');
  assert(rootValue.status === 'complete' && rootValue.ranking === null && rootValue.selection === null && rootValue.componentAndScriptEngineOnly === true && rootValue.bchnTxChecks === 'unsupported', 'root boundary');
  const contractBinding = buildAuthorizationTemplate().contractBinding;
  exact(rootValue.contractBinding, { path: contractBinding.path, rawSha256: contractBinding.rawSha256, byteLength: contractBinding.byteLength, contentDigest: contractBinding.contentDigest }, 'root contract binding');
  const manifestBody = fs.readFileSync(file(root, 'evidence-manifest.v3.json')); const manifestSchemaRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3/evidence-manifest.v3.schema.json'; const manifestSchemaBody = fs.readFileSync(path.resolve(workspace, manifestSchemaRel));
  exact(rootValue.manifestBinding, { path: 'evidence-manifest.v3.json', schemaPath: manifestSchemaRel, rawSha256: sha(manifestBody), schemaSha256: sha(manifestSchemaBody), contentDigest: manifest.contentDigest.value, inventoryDigest: manifest.inventoryDigest.value, listedPayloadCount: 26, selfManifestExcluded: true, evidenceRootExcluded: true }, 'root manifest binding');
  exact(rootValue.authorizationCopy, contentCopyBinding(root, 'authorization.json'), 'root authorization copy'); exact(rootValue.claimCopy, contentCopyBinding(root, 'execution-claim.json'), 'root claim copy');
  exact(rootValue.rawArtifacts, rawArtifacts.map((artifact, ordinal) => artifactRootBinding(root, `raw/${engineOrder[ordinal]}/raw-engine-observation.v3.json`, artifact)), 'root raw bindings'); exact(rootValue.normalizedArtifacts, normalizedArtifacts.map((artifact, ordinal) => artifactRootBinding(root, `normalized/${engineOrder[ordinal]}/normalized-engine-result.v3.json`, artifact)), 'root normalized bindings');
  const summaryBody = fs.readFileSync(file(root, 'cross-engine-summary.v3.json')); exact(rootValue.crossSummary, { path: 'cross-engine-summary.v3.json', rawSha256: sha(summaryBody), byteLength: summaryBody.length, contentDigest: crossSummary.contentDigest.value, status: crossSummary.status }, 'root cross binding');
  return Object.freeze({ status: 'PASS', payloads: 26, containerFiles: 28, outputRoot: OUTPUT_REL, claimPath: CLAIM_REL });
}
export function validateCompleteSuccessContainer() {
  return validateSuccessContainer({
    successRoot: path.resolve(workspace, SUCCESS_REL),
    authorizationBytes: readExactWorkspaceTransport(AUTHORIZATION_REL),
    claimBytes: readExactWorkspaceTransport(CLAIM_REL),
    synthetic: false,
  });
}
/** Execute-only materialization bridge: same semantics as final validation,
 * but on the one fixed sibling scratch root before the commit primitive runs.
 * It is not an external-path validator and cannot be used by the CLI. */
export function validateStagedSuccessContainerForCommit({ successRoot, authorizationBytes, claimBytes }) {
  return Object.freeze({ ...validateSuccessContainer({ successRoot, authorizationBytes, claimBytes, staged: true }), staged: true });
}
/** Test-only, process-free path for an isolated temporary evidence container. */
export function validateSyntheticCompleteSuccessContainer(input) { return Object.freeze({ ...validateSuccessContainer({ ...input, synthetic: true }), syntheticStructuralKat: true, evidence: false }); }
