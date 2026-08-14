import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv from 'ajv/dist/2020.js';
import { fileURLToPath } from 'node:url';

import {
  validateCrossSummarySemantics,
  validateEvidenceManifest,
  validateEvidenceRootSemantics,
  validateNormalizedArtifactSemantics,
  validateRawArtifactSemantics,
} from '../cohort-execution-v2/contract/execution-contract.mjs';
import {
  encodeBchnBatchStdin, encodeLeanCostprobeStdin, encodeLeanVmbconfStdin,
  loadFrozenEpochArtifacts, parseBchnBatchStdout, parseLeanCostprobeStdout,
  parseLeanVmbconfAggregate, verifyFrozenFixtureAuthority,
} from '../cohort-execution-v2/engine-adapters.mjs';
import { deriveExecutionFixture, loadSourceSetPlan, parseLowercaseEvenHex } from '../cohort-freeze-v2/execution-fixture.mjs';
import { buildAuthorization } from './executor.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const workspace = path.resolve(here, '../../../../..');
const contractDir = path.resolve(here, '../cohort-execution-v2');
const freezeDir = path.resolve(here, '../cohort-freeze-v2');
export const ENGINE_ORDER = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
export const PAYLOAD_COUNT = 25;
export const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/evidence-root/v2/root';
export const MANIFEST_DOMAIN = 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/root';
export const INVENTORY_DOMAIN = 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/inventory';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8';

export const canonicalize = (value) => Array.isArray(value)
  ? value.map(canonicalize)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]))
    : value;
export const digestRecord = (value, domain) => ({ algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value: crypto.createHash('sha256').update(Buffer.concat([Buffer.from(domain), Buffer.from([0]), Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`)])).digest('hex') });
const without = (value, field) => { const copy = structuredClone(value); delete copy[field]; return copy; };
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
const json = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const strictUtf8 = (data, label) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(data); } catch (error) { throw new Error(`${label} is not strict UTF-8: ${error.message}`); } };
const ajvValidate = (schemaPath, value) => { const validator = new Ajv({ allErrors: true, strict: true }).compile(json(schemaPath)); assert(validator(value), new Ajv({ allErrors: true }).errorsText(validator.errors)); return true; };
const resolveContained = (root, relative) => {
  assert(!fs.lstatSync(root).isSymbolicLink(), 'evidence root symlink forbidden');
  assert(typeof relative === 'string' && !path.isAbsolute(relative) && !relative.split('/').includes('..'), `unsafe relative path: ${relative}`);
  const absolute = path.resolve(root, relative);
  assert(absolute === root || absolute.startsWith(`${root}${path.sep}`), `path escapes root: ${relative}`);
  let cursor = root;
  for (const part of path.relative(root, absolute).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    assert(!fs.lstatSync(cursor).isSymbolicLink(), `symlink path component forbidden: ${relative}`);
  }
  assert(fs.existsSync(absolute) && fs.statSync(absolute).isFile(), `missing regular payload: ${relative}`);
  assert(fs.realpathSync(absolute).startsWith(`${fs.realpathSync(root)}${path.sep}`), `realpath escapes evidence root: ${relative}`);
  return absolute;
};

const validateCurrentAuthorization = (authorization) => {
  const authFile = path.join(here, 'authorization.v2.json');
  assert(Buffer.compare(fs.readFileSync(authFile), Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`)) === 0, 'authorization bytes differ from exact current authorization artifact');
  assert(sameJson(authorization, buildAuthorization()), 'authorization differs from deterministic builder');
  for (const binding of [...authorization.sourceBindings, ...authorization.schemaBindings, authorization.contractBinding, authorization.evidenceManifestSchema]) {
    assert(typeof binding.path === 'string' && !path.isAbsolute(binding.path) && !binding.path.split('/').includes('..'), 'unsafe authorization binding path');
    const file = path.resolve(workspace, binding.path); assert(file.startsWith(`${workspace}${path.sep}`) && fs.existsSync(file) && fs.lstatSync(file).isFile() && !fs.lstatSync(file).isSymbolicLink(), `authorization binding missing/symlinked: ${binding.path}`); assert(sha(fs.readFileSync(file)) === binding.rawSha256 && fs.statSync(file).size === binding.byteLength, `authorization binding drift: ${binding.path}`);
  }
  const executable = fs.realpathSync(authorization.runtime.nodeExecutable); assert(executable === authorization.runtime.nodeExecutable && fs.lstatSync(executable).isFile() && !fs.lstatSync(executable).isSymbolicLink() && fs.statSync(executable).size === authorization.runtime.nodeExecutableByteLength && sha(fs.readFileSync(executable)) === authorization.runtime.nodeExecutableRawSha256, 'Node executable provenance drift');
  const validateClosure = (closure, field, domain) => {
    assert(closure && typeof closure.root === 'string' && fs.existsSync(closure.root) && !fs.lstatSync(closure.root).isSymbolicLink(), `missing/symlinked ${field} root`);
    const files = [];
    for (const item of closure.files) { const real = fs.realpathSync(item.realpath); assert(real === item.realpath && real.startsWith(`${closure.root}${path.sep}`) && fs.lstatSync(real).isFile() && !fs.lstatSync(real).isSymbolicLink() && fs.statSync(real).size === item.byteLength && sha(fs.readFileSync(real)) === item.rawSha256, `${field} input drift: ${item.realpath}`); files.push(item); }
    const expected = digestRecord({ root: closure.root, files }, domain); const actual = closure.closureDigest ?? closure.treeDigest; assert(actual?.value === expected.value, `${field} digest drift`);
  };
  for (const tree of authorization.runtimeDependencyTrees) validateClosure({ ...tree, closureDigest: tree.treeDigest }, 'runtime dependency tree', tree.treeDigest.domain);
  for (const engine of authorization.engines) {
    const record = path.resolve(workspace, engine.recordPath); assert(fs.existsSync(record) && sha(fs.readFileSync(record)) === engine.recordRawSha256, `engine record drift: ${engine.engineId}`);
    for (const endpoint of [engine.entrypoint, engine.secondaryEntrypoint].filter(Boolean)) { const real = fs.realpathSync(endpoint.realpath); assert(real === endpoint.realpath && fs.lstatSync(real).isFile() && !fs.lstatSync(real).isSymbolicLink() && fs.statSync(real).size === endpoint.byteLength && sha(fs.readFileSync(real)) === endpoint.rawSha256 && engine.repositoryRoots.some((root) => real.startsWith(`${root}/`)), `engine binary/root provenance drift: ${engine.engineId}`); }
    validateClosure(engine.sourceClosure, `${engine.engineId} source closure`, engine.sourceClosure.closureDigest.domain);
  }
  return true;
};

export const assertNoSymlinkComponents = (root, relative) => resolveContained(root, relative);
export const validateManifestBytes = (attemptRoot, manifest) => {
  assert(manifest.files.length === PAYLOAD_COUNT, 'evidence manifest must cover exactly 25 payloads');
  const seen = new Set();
  for (const entry of manifest.files) {
    assert(!seen.has(entry.path) && !entry.path.includes('evidence-root'), `manifest duplicate/root path: ${entry.path}`);
    seen.add(entry.path);
    const file = resolveContained(attemptRoot, entry.path);
    const bytes = fs.readFileSync(file);
    assert(bytes.length === entry.byteLength && sha(bytes) === entry.rawSha256, `manifest byte/hash mismatch: ${entry.path}`);
    assert(entry.manifestEntrySha256?.value === digestRecord(without(entry, 'manifestEntrySha256'), `shieldkit-labs/p2/gate-b/evidence-manifest/v2/entry/${entry.path}`).value, `manifest entry digest mismatch: ${entry.path}`);
  }
  assert(manifest.inventoryDigest.value === digestRecord(manifest.files, INVENTORY_DOMAIN).value, 'manifest inventory digest mismatch');
  assert(manifest.contentDigest.value === digestRecord(without(manifest, 'contentDigest'), MANIFEST_DOMAIN).value, 'manifest content digest mismatch');
  return true;
};

const validateRawSpans = (attemptRoot, manifest, rawArtifacts) => {
  const entries = new Map(manifest.files.map((entry) => [entry.path, entry]));
  for (const artifact of rawArtifacts) for (const row of artifact.rows) {
    const observation = row.rawObservation;
    if (!observation) continue;
    const span = observation.kind === 'file-span' ? observation : observation.payload?.sourceStream;
    assert(span && typeof span.path === 'string', `structured observation lacks raw stream span: ${artifact.engineId}/${row.workItemId}`);
    const artifactPath = observation.kind === 'file-span' ? span.artifactPath : span.path;
    const artifactRawSha256 = observation.kind === 'file-span' ? span.artifactRawSha256 : span.artifactRawSha256;
    const entry = entries.get(artifactPath);
    assert(entry && span.manifestPath === 'attempt-000/evidence-manifest.v2.json', `raw span is not manifest-covered: ${artifactPath}`);
    assert(entry.manifestEntrySha256.value === span.manifestEntrySha256, `raw span manifest entry mismatch: ${artifactPath}`);
    const file = resolveContained(attemptRoot, artifactPath);
    const data = fs.readFileSync(file);
    assert(sha(data) === artifactRawSha256 && data.length === (span.artifactByteLength ?? data.length), `raw span artifact hash mismatch: ${artifactPath}`);
    assert(Number.isInteger(span.byteStart) && Number.isInteger(span.byteEnd) && span.byteStart >= 0 && span.byteEnd > span.byteStart && span.byteEnd <= data.length, `raw span bounds invalid: ${artifactPath}`);
    assert(span.byteStart === 0 || data[span.byteStart - 1] === 0x0a, `raw span byteStart is not LF-aligned: ${artifactPath}`);
    assert(span.byteEnd === data.length || data[span.byteEnd - 1] === 0x0a, `raw span byteEnd is not LF-aligned: ${artifactPath}`);
    const selectedBytes = data.subarray(span.byteStart, span.byteEnd);
    assert(selectedBytes.length === span.byteEnd - span.byteStart && sha(selectedBytes) === span.spanSha256, `raw span bytes mismatch: ${artifactPath}`);
    const prefix = strictUtf8(data.subarray(0, span.byteStart), `${artifactPath} prefix`);
    const selected = strictUtf8(selectedBytes, `${artifactPath} selected span`);
    const lineCount = selected.length === 0 ? 0 : (selected.match(/\n/g) ?? []).length;
    assert(prefix.split('\n').length === span.lineStart && span.lineEnd === span.lineStart + lineCount - (selected.endsWith('\n') ? 1 : 0), `raw span line bounds mismatch: ${artifactPath}`);
  }
};

let verifiedRowsCache = null;
const verifiedRowsByEngine = () => {
  if (verifiedRowsCache) return verifiedRowsCache;
  const artifacts = loadFrozenEpochArtifacts();
  verifyFrozenFixtureAuthority({ artifacts });
  const cases = new Map(artifacts.corpus.constructions.flatMap((entry) => entry.cases).map((entry) => [entry.caseKey, entry]));
  const plans = new Map(); const bases = new Map();
  for (const record of artifacts.fixtureRoster.records) {
    const caseEntry = cases.get(record.epochIdentity.caseKey); assert(caseEntry?.caseDigest?.value === record.epochIdentity.caseDigest, `cached fixture corpus drift: ${record.fixtureKey}`);
    let plan = plans.get(record.planId); if (!plan) { plan = loadSourceSetPlan(record.planId); plans.set(record.planId, plan); }
    const fixture = deriveExecutionFixture({ sourcePlan: plan, operandsBottomToTop: caseEntry.stackArgsBottomToTop.map((raw, index) => parseLowercaseEvenHex(raw, `cached corpus operand ${index}`)) });
    assert(sameJson(fixture.bindings, record.byteBindings) && sameJson(fixture.sourceBinding, record.sourceBinding), `cached fixture binding drift: ${record.fixtureKey}`);
    bases.set(record.fixtureKey, { fixtureRecord: record, fixture, caseEntry, expected: caseEntry.expected });
  }
  assert(bases.size === 4732 && plans.size === 42, 'cached fixture/source-plan cardinality drift');
  const rows = new Map(ENGINE_ORDER.map((engineId) => [engineId, []]));
  for (const workItem of artifacts.workItemRoster.workItems) { const base = bases.get(workItem.fixtureKey); assert(base, `cached work item fixture missing: ${workItem.workItemId}`); if (!base.fixtureRecord.preflightLimitViolation.scriptSig && !base.fixtureRecord.preflightLimitViolation.redeem) rows.get(workItem.engineId).push(Object.freeze({ ...base, workItem })); }
  for (const [engineId, items] of rows) assert(items.length === 4608, `cached eligible row count drift: ${engineId}`);
  verifiedRowsCache = rows; return rows;
};
const payloadProjection = (payload) => ({ workItemId: payload.workItemId, verdict: payload.verdict, failureStage: payload.failureStage, metrics: payload.metrics, txChecks: payload.txChecks, phase: payload.phase, terminalStatus: payload.terminalStatus });
const observationBytes = (attemptRoot, observation) => fs.readFileSync(resolveContained(attemptRoot, observation.payload.sourceStream.path)).subarray(observation.payload.sourceStream.byteStart, observation.payload.sourceStream.byteEnd);
const validateCapturedStreams = (attemptRoot, rawArtifact) => {
  const rows = verifiedRowsByEngine().get(rawArtifact.engineId); const endpoint = rawArtifact.invocation.entrypoints;
  const stream = (ref) => fs.readFileSync(resolveContained(attemptRoot, ref.path));
  const stdoutRef = endpoint.at(-1).stdout;
  const stdout = strictUtf8(stream(stdoutRef), `${rawArtifact.engineId} stdout`);
  assert(stdout.endsWith('\n') && !stdout.includes('\r'), `${rawArtifact.engineId} stdout must be LF-only`);
  if (rawArtifact.engineId === 'engine:native' || rawArtifact.engineId === 'engine:libauth') {
    assert(stream(endpoint[0].stdin).length === 0 && stream(endpoint[0].stderr).length === 0 && endpoint[0].exitCode === null, `${rawArtifact.engineId} module stream/process boundary drift`);
  }
  for (const row of rawArtifact.rows) if (row.disposition === 'observed') {
    assert(row.rawObservation.kind === 'structured' && row.rawObservation.exitCode === 0 && row.rawObservation.parserStatus === 'complete', `raw observation parser completion drift: ${row.workItemId}`);
    assert(row.rawObservation.payload.sourceStream.path === stdoutRef.path, `raw observation uses wrong stdout role: ${row.workItemId}`);
    if (rawArtifact.engineId === 'engine:native' || rawArtifact.engineId === 'engine:libauth') assert(endpoint[0].exitCode === null, `module endpoint must not claim an OS exit code: ${row.workItemId}`);
    else assert(endpoint.at(-1).exitCode === row.rawObservation.exitCode, `external raw observation must retain process exit code: ${row.workItemId}`);
  }
  if (rawArtifact.engineId === 'engine:bchn') {
    assert(Buffer.compare(stream(endpoint[0].stdin), Buffer.from(encodeBchnBatchStdin(rows), 'utf8')) === 0, 'BCHN stdin differs from exact eligible fixture codec');
    const parsed = parseBchnBatchStdout(stdout, { rows });
    for (const row of rawArtifact.rows) if (row.disposition === 'observed') {
      const result = parsed.get(row.workItemId); const expected = { workItemId: row.workItemId, verdict: result.outcome, failureStage: result.outcome === 'accept' ? 'accept' : null, metrics: result.metrics ?? null, txChecks: result.txChecks, phase: result.phase, terminalStatus: 'supported' };
      const line = JSON.parse(strictUtf8(observationBytes(attemptRoot, row.rawObservation), `BCHN row span ${row.workItemId}`)); assert(line.ident === row.workItemId, `BCHN row span points at another work item: ${row.workItemId}`);
      assert(sameJson(payloadProjection(row.rawObservation.payload), expected), `BCHN raw payload/parser mismatch: ${row.workItemId}`);
    }
  } else if (rawArtifact.engineId === 'engine:leanbch') {
    assert(Buffer.compare(stream(endpoint[0].stdin), Buffer.from(encodeLeanVmbconfStdin(rows), 'utf8')) === 0, 'Lean vmbconf stdin differs from exact eligible fixture codec');
    assert(Buffer.compare(stream(endpoint[1].stdin), Buffer.from(encodeLeanCostprobeStdin(rows), 'utf8')) === 0, 'Lean CostProbe stdin differs from exact eligible fixture codec');
    const aggregate = parseLeanVmbconfAggregate(strictUtf8(stream(endpoint[0].stdout), 'Lean vmbconf stdout'), { rows });
    const parsed = parseLeanCostprobeStdout(stdout, { rows });
    const rejectedValid = rows.filter((row) => row.expected.verdict === 'accept' && parsed.get(row.workItem.workItemId).verdict === 'reject').length;
    const acceptedInvalid = rows.filter((row) => row.expected.verdict === 'reject' && parsed.get(row.workItem.workItemId).verdict === 'accept').length;
    assert(aggregate.rejectedValid === rejectedValid && aggregate.acceptedInvalid === acceptedInvalid && aggregate.passed === rows.length - rejectedValid - acceptedInvalid, 'Lean aggregate/CostProbe/frozen-verdict reconciliation mismatch');
    for (const row of rawArtifact.rows) if (row.disposition === 'observed') {
      const result = parsed.get(row.workItemId); const expected = { workItemId: row.workItemId, verdict: result.verdict, failureStage: result.verdict === 'accept' ? 'accept' : null, metrics: result.metrics, txChecks: result.txChecks, phase: result.phase, terminalStatus: 'supported' };
      const line = strictUtf8(observationBytes(attemptRoot, row.rawObservation), `Lean row span ${row.workItemId}`); assert(/^METRICS ([^\s]+)/u.exec(line)?.[1] === row.workItemId, `Lean row span points at another work item: ${row.workItemId}`);
      assert(result.supportStatus === 'supported' && sameJson(payloadProjection(row.rawObservation.payload), expected), `Lean raw payload/CostProbe mismatch: ${row.workItemId}`);
    }
  } else {
    // The in-process engines emit one canonical NDJSON transcript line per
    // eligible work item. Reparse exactly the bounded line selected by every
    // source span rather than trusting a self-consistent payload object.
    const seen = new Set();
    const partition = [];
    for (const row of rawArtifact.rows) if (row.disposition === 'observed') {
      const line = strictUtf8(observationBytes(attemptRoot, row.rawObservation), `${rawArtifact.engineId} row transcript`);
      assert(line.endsWith('\n') && !line.includes('\r'), `in-process transcript framing drift: ${row.workItemId}`);
      const parsed = JSON.parse(line); assert(parsed && parsed.workItemId === row.workItemId && !seen.has(parsed.workItemId), `in-process transcript identity drift: ${row.workItemId}`); seen.add(parsed.workItemId);
      assert(sameJson(payloadProjection(row.rawObservation.payload), parsed), `in-process raw payload/transcript mismatch: ${row.workItemId}`); partition.push(row.rawObservation.payload.sourceStream);
    }
    assert(seen.size === rows.length, `${rawArtifact.engineId} transcript coverage drift`);
    partition.sort((left, right) => left.byteStart - right.byteStart); let offset = 0;
    for (const span of partition) { assert(span.byteStart === offset, `${rawArtifact.engineId} transcript has span gap/overlap`); offset = span.byteEnd; }
    assert(offset === stream(stdoutRef).length, `${rawArtifact.engineId} transcript has unreferenced bytes`);
  }
};

const validateInventory = (attemptRoot, manifest) => {
  const expected = new Set([...manifest.files.map((entry) => entry.path), 'attempt-000/evidence-manifest.v2.json', 'evidence-root.v2.json']);
  const found = [];
  const walk = (dir) => { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const file = path.join(dir, entry.name); if (entry.isDirectory()) walk(file); else found.push(path.relative(attemptRoot, file).split(path.sep).join('/')); } };
  walk(attemptRoot);
  assert(found.sort().join('|') === [...expected].sort().join('|'), 'evidence attempt has unmanifested or omitted payload');
};

const fixtureCommonMetrics = () => new Map(json(path.join(freezeDir, 'fixture-roster.v2.json')).records.map((record) => [record.fixtureKey, { lockingBytes: record.byteBindings.sourceLockingBytecode.byteLength, unlockingBytes: record.byteBindings.unlockingBytecode.byteLength, sourceBytes: record.byteBindings.sourceOutputs.byteLength, digest: record.contentDigest.value }]));
const engineMetric = (engineId, metricId, payload) => {
  const values = payload?.metrics; if (!values || typeof values !== 'object') return undefined;
  const fields = {
    'engine:native': {},
    'engine:libauth': { vmCost: ['vmCost', 'operationCost'], opCost: ['opCost', 'operationCost'], stackMax: ['stackMax'], elementMax: ['elementMax'], opcodeHistogram: ['opcodeHistogram'], mulByteProduct: ['mulByteProduct'], divByteProduct: ['divByteProduct'], modByteProduct: ['modByteProduct'], resultPushBytes: ['resultPushBytes'], limits: ['limits'], headroom: ['headroom'] },
    'engine:bchn': { vmCost: ['operationCost'], opCost: ['operationCost'], limits: ['maximumOperationCost'], headroom: ['maximumOperationCost'] },
    'engine:leanbch': { vmCost: ['arithmeticCost'], opCost: ['nativeConsensus64OperationCost'], opcodeHistogram: ['opcodeHistogram'], mulByteProduct: ['mulByteProduct'], divByteProduct: ['divByteProduct'], modByteProduct: ['modByteProduct'], resultPushBytes: ['resultPushBytes'], stackMax: ['stackMax'], elementMax: ['elementMax'], limits: ['limits'], headroom: ['headroom'] },
  }[engineId];
  const key = (fields?.[metricId] ?? []).find((name) => Object.hasOwn(values, name)); if (!key) return undefined;
  if (engineId === 'engine:bchn' && metricId === 'limits') return { operationCost: values.maximumOperationCost, hashDigestIterations: values.maximumHashDigestIterations, signatureChecks: values.maximumSignatureCheckCount };
  if (engineId === 'engine:bchn' && metricId === 'headroom') return { operationCost: values.maximumOperationCost - values.operationCost, hashDigestIterations: values.maximumHashDigestIterations - values.hashDigestIterations, signatureChecks: values.maximumSignatureCheckCount - values.signatureCheckCount };
  return values[key];
};
const sameJson = (left, right) => JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
const validateRawNormalizedProjection = (rawArtifacts, normalizedArtifacts) => {
  const common = fixtureCommonMetrics();
  for (let engineIndex = 0; engineIndex < rawArtifacts.length; engineIndex++) {
    const raw = rawArtifacts[engineIndex];
    const normalized = normalizedArtifacts[engineIndex];
    for (let i = 0; i < raw.rows.length; i++) {
      const rawRow = raw.rows[i];
      const normalizedRow = normalized.rows[i];
      assert(rawRow.disposition === normalizedRow.disposition, `raw-to-normalized disposition mismatch at ${engineIndex}/${i}`);
      if (rawRow.disposition === 'preflight-limit-unsupported' || rawRow.disposition === 'not-run-incomplete') continue;
      const observation = rawRow.rawObservation;
      assert(observation && observation.kind === 'structured', `normalized projection requires structured raw observation at ${engineIndex}/${i}`);
      const payload = observation.payload;
      assert(payload && payload.verdict === normalizedRow.observed.verdict, `raw-to-normalized verdict projection mismatch at ${engineIndex}/${i}`);
      if (Object.hasOwn(payload, 'failureStage')) assert(payload.failureStage === normalizedRow.observed.failureStage, `raw-to-normalized stage projection mismatch at ${engineIndex}/${i}`);
      const fixture = common.get(rawRow.fixtureKey); assert(fixture && fixture.digest === rawRow.fixtureRecordDigest, `fixture authority mismatch at ${engineIndex}/${i}`);
      for (const metric of normalizedRow.metrics) {
        if (metric.metricId === 'verdict') assert(metric.value === payload.verdict, `raw-to-normalized verdict metric mismatch at ${engineIndex}/${i}`);
        else if (metric.status === 'derived-common') assert(Object.hasOwn(fixture, metric.metricId) && metric.provenance?.sourceArtifactDigest === rawRow.fixtureRecordDigest && metric.provenance?.method === 'frozen-fixture-byte-binding-v1' && sameJson(metric.value, fixture[metric.metricId]), `fixture-derived metric mismatch at ${engineIndex}/${i}/${metric.metricId}`);
        else if (metric.status === 'measured' || metric.status === 'measured-noncomparable' || metric.status === 'derived-engine') assert(metric.provenance?.sourceArtifactDigest === raw.contentDigest.value && sameJson(metric.value, engineMetric(raw.engineId, metric.metricId, payload)), `raw-to-normalized metric projection mismatch at ${engineIndex}/${i}/${metric.metricId}`);
        else assert(metric.value === null, `unmeasured metric has value at ${engineIndex}/${i}/${metric.metricId}`);
      }
    }
  }
};

const validateInvocationJoins = (attemptRoot, manifest, rawArtifact, engineAuth, authorizationRuntime) => {
  const entries = new Map(manifest.files.map((entry) => [entry.path, entry]));
  const endpoints = rawArtifact.invocation.entrypoints;
  for (let endpointIndex = 0; endpointIndex < endpoints.length; endpointIndex++) {
    const endpoint = endpoints[endpointIndex];
    const expected = endpointIndex === 0 ? engineAuth.entrypoint : engineAuth.secondaryEntrypoint;
    const expectedPath = expected.realpath;
    const expectedSha = expected.rawSha256;
    const expectedArgv = endpointIndex === 0 ? (engineAuth.entrypointArgv.length ? engineAuth.entrypointArgv : [expectedPath]) : engineAuth.secondaryEntrypointArgv;
    const isModule = engineAuth.kind === 'module';
    assert(endpoint.path === expectedPath && endpoint.rawSha256 === expectedSha && JSON.stringify(endpoint.argv) === JSON.stringify(expectedArgv) && endpoint.exitCode === (isModule ? null : 0) && endpoint.timedOut === false, `invocation endpoint pin/process metadata mismatch for ${rawArtifact.engineId}`);
    for (const stream of [endpoint.stdin, endpoint.stdout, endpoint.stderr]) {
      const entry = entries.get(stream.path);
      assert(entry && stream.manifestPath === 'attempt-000/evidence-manifest.v2.json' && entry.rawSha256 === stream.rawSha256 && entry.manifestEntrySha256.value === stream.manifestEntrySha256, `endpoint stream manifest join mismatch for ${rawArtifact.engineId}`);
      assert(sha(fs.readFileSync(resolveContained(attemptRoot, stream.path))) === stream.rawSha256, `endpoint stream bytes mismatch for ${rawArtifact.engineId}`);
    }
  }
  for (const stream of [rawArtifact.logs.stdin, rawArtifact.logs.stdout, rawArtifact.logs.stderr]) {
    const entry = entries.get(stream.path);
    assert(entry && entry.rawSha256 === stream.rawSha256 && stream.manifestPath === 'attempt-000/evidence-manifest.v2.json', `artifact log manifest join mismatch for ${rawArtifact.engineId}`);
  }
  assert(rawArtifact.invocation.stdinCodec === engineAuth.stdinCodec && JSON.stringify(canonicalize(rawArtifact.invocation.environment.variables)) === JSON.stringify(canonicalize(engineAuth.environment)), `invocation environment/codec mismatch for ${rawArtifact.engineId}`);
  assert(rawArtifact.invocation.runtime.nodeVersion === authorizationRuntime.nodeVersion && rawArtifact.invocation.runtime.os === authorizationRuntime.platform && rawArtifact.invocation.runtime.arch === authorizationRuntime.arch && rawArtifact.invocation.runtime.runtimeDigest === authorizationRuntime.runtimeDigest && rawArtifact.invocation.runtime.cwd === engineAuth.cwd && rawArtifact.invocation.implementationDigest === engineAuth.implementationDigest, `invocation runtime/implementation mismatch for ${rawArtifact.engineId}`);
  assert(rawArtifact.logs.logSetDigest.value === digestRecord({ engineId: rawArtifact.engineId, endpoints: rawArtifact.invocation.entrypoints.map((x) => ({ role: x.role, stdin: x.stdin, stdout: x.stdout, stderr: x.stderr })) }, `shieldkit-labs/p2/gate-b/cohort-executor-v2/log-set/${rawArtifact.engineId}`).value, `log set digest mismatch for ${rawArtifact.engineId}`);
};

export const validateEvidencePackage = ({ attemptRoot, authorization, contract = json(path.join(contractDir, 'execution-contract.v2.json')) } = {}) => {
  assert(attemptRoot && fs.existsSync(attemptRoot), 'attempt root required');
  const root = json(resolveContained(attemptRoot, 'evidence-root.v2.json'));
  const manifest = json(resolveContained(attemptRoot, 'attempt-000/evidence-manifest.v2.json'));
  ajvValidate(path.join(contractDir, 'contract/evidence-root.v2.schema.json'), root);
  ajvValidate(path.join(contractDir, 'contract/evidence-manifest.v2.schema.json'), manifest);
  assert(root.contractDigest === contract.contentDigest.value, 'evidence root contract binding mismatch');
  assert(authorization && authorization.executionAllowed === true, 'authorized evidence validation required');
  ajvValidate(path.join(here, 'authorization.v2.schema.json'), authorization);
  assert(authorization.contentDigest?.value === digestRecord(without(authorization, 'contentDigest'), 'shieldkit-labs/p2/gate-b/cohort-executor-v2/authorization/v2/root').value, 'authorization content digest is not deterministic'); validateCurrentAuthorization(authorization);
  assert(root.ranking === null && root.selection === null, 'ranking or selection must remain null');
  assert(root.manifestBinding.listedPayloadCount === PAYLOAD_COUNT, 'root payload accounting mismatch');
  validateInventory(attemptRoot, manifest);
  validateManifestBytes(attemptRoot, manifest);
  const authorizationBytes = fs.readFileSync(resolveContained(attemptRoot, 'attempt-000/authorization.json'));
  assert(sha(authorizationBytes) === sha(Buffer.from(`${JSON.stringify(authorization, null, 2)}\n`)), 'attempt authorization bytes differ from authorized artifact');
  validateEvidenceManifest(manifest);
  const raw = root.rawArtifacts.map((ref) => json(resolveContained(attemptRoot, ref.path)));
  const normalized = root.normalizedArtifacts.map((ref) => json(resolveContained(attemptRoot, ref.path)));
  const summary = json(resolveContained(attemptRoot, root.crossEngineSummary.path));
  for (let i = 0; i < ENGINE_ORDER.length; i++) {
    ajvValidate(path.join(contractDir, 'contract/raw-engine-observation.v2.schema.json'), raw[i]);
    ajvValidate(path.join(contractDir, 'contract/normalized-engine-result.v2.schema.json'), normalized[i]);
    validateRawArtifactSemantics(raw[i]);
    const engineAuth = authorization?.engines?.[i];
    assert(engineAuth && raw[i].engineId === engineAuth.engineId && raw[i].enginePin.artifactRawSha256 === engineAuth.recordRawSha256 && raw[i].enginePin.artifactContentDigest === engineAuth.recordContentDigest, `engine pin join mismatch at ${i}`);
    const endpoints = raw[i].invocation.entrypoints;
    assert(endpoints.length === (engineAuth.engineId === 'engine:leanbch' ? 2 : 1), `invocation endpoint count mismatch at ${i}`);
    validateInvocationJoins(attemptRoot, manifest, raw[i], engineAuth, authorization.runtime);
    validateCapturedStreams(attemptRoot, raw[i]);
    validateNormalizedArtifactSemantics(normalized[i], raw[i]);
    assert(root.rawArtifacts[i].status === raw[i].status && root.normalizedArtifacts[i].status === normalized[i].status, `root status binding mismatch at ${i}`);
    assert(root.rawArtifacts[i].rawSha256 === sha(fs.readFileSync(resolveContained(attemptRoot, root.rawArtifacts[i].path))), `raw root hash mismatch at ${i}`);
    assert(root.normalizedArtifacts[i].rawSha256 === sha(fs.readFileSync(resolveContained(attemptRoot, root.normalizedArtifacts[i].path))), `normalized root hash mismatch at ${i}`);
    assert(root.rawArtifacts[i].contentDigest === raw[i].contentDigest.value && root.normalizedArtifacts[i].contentDigest === normalized[i].contentDigest.value, `root content digest join mismatch at ${i}`);
    assert(raw[i].schema === 'shieldkit-labs/p2/gate-b/cohort-execution-v2/raw-engine-observation' && normalized[i].schema === 'shieldkit-labs/p2/gate-b/cohort-execution-v2/normalized-engine-result', `artifact schema identity mismatch at ${i}`);
  }
  validateRawSpans(attemptRoot, manifest, raw);
  validateRawNormalizedProjection(raw, normalized);
  ajvValidate(path.join(contractDir, 'contract/cross-engine-summary.v2.schema.json'), summary);
  validateCrossSummarySemantics(summary, normalized, raw);
  assert(root.crossEngineSummary.status === summary.status, 'summary status binding mismatch');
  assert(root.crossEngineSummary.rawSha256 === sha(fs.readFileSync(resolveContained(attemptRoot, root.crossEngineSummary.path))) && root.crossEngineSummary.contentDigest === summary.contentDigest.value, 'summary root reference join mismatch');
  assert(root.manifestBinding.rawSha256 === sha(fs.readFileSync(resolveContained(attemptRoot, root.manifestBinding.path))) && root.manifestBinding.contentDigest === manifest.contentDigest.value && root.manifestBinding.inventoryDigest === manifest.inventoryDigest.value, 'manifest root reference join mismatch');
  validateEvidenceRootSemantics(root, contract);
  return { status: 'PASS', obligations: { total: 18928, preflightUnsupported: 496, executable: 18432 }, payloads: PAYLOAD_COUNT };
};

export const validateSerialInterruption = (statuses) => {
  assert(Array.isArray(statuses) && statuses.length === 4, 'four engine statuses required');
  let current = false;
  let notStarted = false;
  for (const status of statuses) {
    if (status === 'complete') assert(!current && !notStarted, 'complete after interruption is noncausal');
    else if (status === 'incomplete' || status === 'failed') { assert(!current && !notStarted, 'multiple/current interruption is noncausal'); current = true; }
    else if (status === 'not-started') notStarted = true;
    else throw new Error(`invalid engine status ${status}`);
  }
  return true;
};

export const packagePaths = Object.freeze({ workspace, contractDir, freezeDir });
