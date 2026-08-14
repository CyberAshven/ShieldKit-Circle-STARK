import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { ENGINE_ORDER, streamPathFor } from './engine-runners.mjs';
import { digestRecord, canonicalize, validateEvidencePackage } from './validator.mjs';

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = path.resolve(here, '../../../../..');
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
const bytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
const value = (record) => record?.value ?? record;
const rawDomain = (engineId, ordinal, kind, suffix = '') => `shieldkit-labs/p2/gate-b/execution-evidence/v2/${kind}/${engineId}/batch/${ordinal}/shard/0${suffix}`;
const metricIds = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];
const json = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const write = (root, relative, body) => { const file = path.join(root, relative); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, Buffer.isBuffer(body) ? body : bytes(body), { flag: 'wx' }); return file; };
const streamRoles = (engineId) => engineId === 'engine:leanbch' ? [['primary', 'stdin'], ['primary', 'stdout'], ['primary', 'stderr'], ['secondary', 'stdin'], ['secondary', 'stdout'], ['secondary', 'stderr']] : [[null, 'stdin'], [null, 'stdout'], [null, 'stderr']];
const streams = () => ENGINE_ORDER.flatMap((engineId) => streamRoles(engineId).map(([processRole, role]) => ({ engineId, processRole, role, path: streamPathFor(engineId, role, processRole) })));
const canonical = (x) => JSON.stringify(canonicalize(x));

const manifestEntry = (ordinal, kind, engineId, processRole, role, relative, content) => {
  const entry = { ordinal, kind, engineId, processRole, role, path: relative, byteLength: Buffer.byteLength(content), rawSha256: sha(content) };
  entry.manifestEntrySha256 = digestRecord(entry, `shieldkit-labs/p2/gate-b/evidence-manifest/v2/entry/${relative}`);
  return entry;
};
const streamManifestEntries = (streamText) => {
  const output = new Map(); let ordinal = 0;
  for (const engineId of ENGINE_ORDER) {
    ordinal += 1; // raw artifact precedes this engine's streams
    for (const item of streams().filter((x) => x.engineId === engineId)) {
      assert(streamText.has(item.path), `missing captured stream: ${item.path}`);
      output.set(item.path, manifestEntry(ordinal++, 'raw-stream', item.engineId, item.processRole, item.role, item.path, streamText.get(item.path)));
    }
  }
  return output;
};
const ref = (entry) => ({ path: entry.path, rawSha256: entry.rawSha256, byteLength: entry.byteLength, mediaType: 'text/plain-utf8', manifestPath: 'attempt-000/evidence-manifest.v2.json', manifestEntrySha256: entry.manifestEntrySha256.value });
const invocation = (engine, authorization, streamEntries, batch) => {
  const endpoint = (secondary = false) => {
    const role = secondary ? 'secondary' : 'primary';
    const prefix = secondary ? 'secondary' : 'primary';
    const entry = secondary ? engine.secondaryEntrypoint : engine.entrypoint;
    const argv = secondary ? engine.secondaryEntrypointArgv : engine.entrypointArgv;
    const selected = (name) => ref(streamEntries.get(streamPathFor(engine.engineId, name, engine.engineId === 'engine:leanbch' ? prefix : null)));
    const result = batch.processResults?.[role];
    assert(result && (result.exitCode === null || Number.isInteger(result.exitCode)) && typeof result.timedOut === 'boolean', `captured process metadata missing: ${engine.engineId}/${role}`);
    return { role, path: entry.realpath, rawSha256: entry.rawSha256, argv: argv.length ? argv : [entry.realpath], stdin: selected('stdin'), stdout: selected('stdout'), stderr: selected('stderr'), exitCode: result.exitCode, timedOut: result.timedOut };
  };
  const endpoints = engine.engineId === 'engine:leanbch' ? [endpoint(), endpoint(true)] : [endpoint()];
  const primaryLogs = { stdin: endpoints[0].stdin, stdout: endpoints[0].stdout, stderr: endpoints[0].stderr };
  const logSetDigest = digestRecord({ engineId: engine.engineId, endpoints: endpoints.map((x) => ({ role: x.role, stdin: x.stdin, stdout: x.stdout, stderr: x.stderr })) }, `shieldkit-labs/p2/gate-b/cohort-executor-v2/log-set/${engine.engineId}`);
  return {
    invocation: { entrypointKind: engine.engineId === 'engine:leanbch' ? 'paired' : engine.kind, entrypoints: endpoints, stdinCodec: engine.stdinCodec, environment: { allowlistDigest: sha(bytes(engine.environment)), variables: engine.environment }, runtime: { nodeVersion: authorization.runtime.nodeVersion, os: authorization.runtime.platform, arch: authorization.runtime.arch, cwd: engine.cwd, runtimeDigest: authorization.runtime.runtimeDigest }, implementationDigest: engine.implementationDigest },
    logs: { ...primaryLogs, logSetDigest },
  };
};

const rawObservation = (engineId, ordinal, workItemId, observed, streamEntries) => {
  const source = observed.sourceStream;
  assert(source && typeof source.path === 'string', `missing exact source stream/span: ${engineId}/${workItemId}`);
  const entry = streamEntries.get(source.path);
  assert(entry, `observation source stream is not manifest-covered: ${source.path}`);
  const sourceStream = { ...source, artifactRawSha256: entry.rawSha256, artifactByteLength: entry.byteLength, manifestPath: 'attempt-000/evidence-manifest.v2.json', manifestEntrySha256: entry.manifestEntrySha256.value };
  const body = { kind: 'structured', status: 'observed', exitCode: 0, parserStatus: 'complete', payload: { engineId, workItemId, verdict: observed.verdict, failureStage: observed.failureStage ?? null, metrics: observed.metrics ?? null, txChecks: observed.txChecks, phase: observed.phase, terminalStatus: observed.terminalStatus, sourceStream } };
  body.rawObservationDigest = digestRecord(body, rawDomain(engineId, ordinal, 'raw', `/observation/${workItemId}`));
  return body;
};
const preflight = (record) => ({ kind: 'preflight-limit', executionCeilingBytes: 10000, scriptSig: Boolean(record.preflightLimitViolation.scriptSig), redeem: Boolean(record.preflightLimitViolation.redeem), reason: 'preflight-limit-unsupported-no-engine-invocation' });
const commonMetricValues = (record) => Object.freeze({
  lockingBytes: record.byteBindings.sourceLockingBytecode.byteLength,
  unlockingBytes: record.byteBindings.unlockingBytecode.byteLength,
  sourceBytes: record.byteBindings.sourceOutputs.byteLength,
});
const engineMetricValue = (engineId, metricId, payload) => {
  const values = payload?.metrics;
  if (!values || typeof values !== 'object') return undefined;
  // The mapping is deliberately closed: only fields captured by that engine's
  // parser/transcript are normalized. No expected case value or another
  // engine's value is ever used as an observed measurement.
  const fields = {
    'engine:native': {},
    'engine:libauth': { vmCost: ['vmCost', 'operationCost'], opCost: ['opCost', 'operationCost'], stackMax: ['stackMax'], elementMax: ['elementMax'], opcodeHistogram: ['opcodeHistogram'], mulByteProduct: ['mulByteProduct'], divByteProduct: ['divByteProduct'], modByteProduct: ['modByteProduct'], resultPushBytes: ['resultPushBytes'], limits: ['limits'], headroom: ['headroom'] },
    'engine:bchn': { vmCost: ['operationCost'], opCost: ['operationCost'], limits: ['maximumOperationCost'], headroom: ['maximumOperationCost'] },
    'engine:leanbch': { vmCost: ['arithmeticCost'], opCost: ['nativeConsensus64OperationCost'], opcodeHistogram: ['opcodeHistogram'], mulByteProduct: ['mulByteProduct'], divByteProduct: ['divByteProduct'], modByteProduct: ['modByteProduct'], resultPushBytes: ['resultPushBytes'], stackMax: ['stackMax'], elementMax: ['elementMax'], limits: ['limits'], headroom: ['headroom'] },
  }[engineId];
  const choices = fields?.[metricId] ?? [];
  const key = choices.find((candidate) => Object.hasOwn(values, candidate));
  if (!key) return undefined;
  if (engineId === 'engine:bchn' && metricId === 'limits') return { operationCost: values.maximumOperationCost, hashDigestIterations: values.maximumHashDigestIterations, signatureChecks: values.maximumSignatureCheckCount };
  if (engineId === 'engine:bchn' && metricId === 'headroom') return { operationCost: values.maximumOperationCost - values.operationCost, hashDigestIterations: values.maximumHashDigestIterations - values.hashDigestIterations, signatureChecks: values.maximumSignatureCheckCount - values.signatureCheckCount };
  return values[key];
};
const normalizedMetric = ({ engineId, metricId, row, record, rawDigest }) => {
  if (row.disposition === 'preflight-limit-unsupported') return { metricId, status: 'preflight-limit-unsupported', value: null, provenance: null, reason: 'preflight-limit-unsupported' };
  const payload = row.rawObservation.payload;
  if (metricId === 'verdict') return { metricId, status: 'measured', value: payload.verdict, provenance: { sourceArtifactDigest: rawDigest, method: 'captured-engine-observation-v1' }, reason: null };
  const common = commonMetricValues(record);
  if (Object.hasOwn(common, metricId)) return { metricId, status: 'derived-common', value: common[metricId], provenance: { sourceArtifactDigest: row.fixtureRecordDigest, method: 'frozen-fixture-byte-binding-v1' }, reason: null };
  const measured = engineMetricValue(engineId, metricId, payload);
  if (measured === undefined) return { metricId, status: 'not-exposed', value: null, provenance: null, reason: 'not-exposed-by-engine' };
  // Source-level/engine-specific surfaces are retained without inventing a
  // cross-engine equivalence. Common comparison is decided only downstream.
  return { metricId, status: 'measured-noncomparable', value: measured, provenance: { sourceArtifactDigest: rawDigest, method: 'captured-engine-metric-mapping-v1' }, reason: null };
};

export const buildArtifactPairs = ({ authorization, artifacts, batches, streamText }) => {
  assert(ENGINE_ORDER.every((id) => batches.get(id)?.engineId === id), 'all four concrete engine batches required');
  const streamEntries = streamManifestEntries(streamText);
  const records = artifacts.fixtureRoster.records;
  const work = artifacts.workItemRoster.workItems;
  const corpus = new Map(artifacts.corpus.constructions.flatMap((x) => x.cases).map((x) => [x.caseKey, x]));
  const rawArtifacts = []; const normalizedArtifacts = [];
  for (const [ordinal, engineId] of ENGINE_ORDER.entries()) {
    const batch = batches.get(engineId); const engine = authorization.engines[ordinal]; const rows = work.filter((x) => x.engineId === engineId);
    assert(rows.length === 4732 && batch.status === 'complete', `complete engine batch required: ${engineId}`);
    const bindings = invocation(engine, authorization, streamEntries, batch);
    const rawRows = rows.map((item, i) => {
      const record = records[i]; const limit = Boolean(record.preflightLimitViolation?.scriptSig || record.preflightLimitViolation?.redeem);
      const base = { workItemId: item.workItemId, fixtureKey: item.fixtureKey, terminalCellId: item.terminalCellId, workItemOrdinal: i, fixtureRecordDigest: value(record.contentDigest), disposition: limit ? 'preflight-limit-unsupported' : 'observed', preflightBinding: limit ? preflight(record) : null, unsupportedBinding: null, notRunBinding: null, rawObservation: null };
      if (!limit) { const observed = batch.observations.get(item.workItemId); assert(observed && observed.workItemId === item.workItemId, `missing concrete observation: ${item.workItemId}`); base.rawObservation = rawObservation(engineId, ordinal, item.workItemId, observed, streamEntries); }
      base.rawRowDigest = digestRecord(base, rawDomain(engineId, ordinal, 'raw', `/row/${item.workItemId}`)); return base;
    });
    const raw = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/raw-engine-observation', evidenceId: 'evidence:cohort-executor-v2:attempt-000', epochId: 'execution-epoch:gate-b-v2', engineId, engineBatchOrdinal: ordinal, shardIndex: 0, shardCount: 1, status: 'complete', workItemOrderDigest: digestRecord(rows.map((x) => x.workItemId), `shieldkit-labs/p2/gate-b/execution-evidence/v2/schedule/${engineId}`), enginePin: { engineId, artifactPath: engine.recordPath, artifactRawSha256: engine.recordRawSha256, artifactContentDigest: engine.recordContentDigest, schemaPath: engine.recordSchemaPath, schemaSha256: engine.recordSchemaSha256 }, ...bindings, rows: rawRows };
    raw.contentDigest = digestRecord(raw, rawDomain(engineId, ordinal, 'raw'));
    const normalRows = rawRows.map((r, i) => {
      const record = records[i]; const expected = corpus.get(record.epochIdentity.caseKey).expected; const observed = r.rawObservation?.payload;
      const metrics = metricIds.map((metricId) => {
        const metric = normalizedMetric({ engineId, metricId, row: r, record, rawDigest: raw.contentDigest.value });
        metric.contentDigest = digestRecord(metric, rawDomain(engineId, ordinal, 'normalized', `/metric/${r.workItemId}/${metricId}`)); return metric;
      });
      const normal = { workItemId: r.workItemId, fixtureKey: r.fixtureKey, terminalCellId: r.terminalCellId, workItemOrdinal: r.workItemOrdinal, fixtureRecordDigest: r.fixtureRecordDigest, disposition: r.disposition, expected, terminalStatus: r.disposition === 'preflight-limit-unsupported' ? 'preflight-limit-unsupported' : 'observed', observed: { verdict: observed?.verdict ?? null, failureStage: r.disposition === 'preflight-limit-unsupported' ? 'preflight-limit' : observed?.failureStage ?? null }, rawObservationDigest: r.disposition === 'preflight-limit-unsupported' ? null : r.rawRowDigest, unsupportedBinding: null, notRunBinding: null, metrics };
      normal.contentDigest = digestRecord(normal, rawDomain(engineId, ordinal, 'normalized', `/row/${r.workItemId}`)); return normal;
    });
    const normalized = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/normalized-engine-result', evidenceId: raw.evidenceId, epochId: raw.epochId, engineId, engineBatchOrdinal: ordinal, shardIndex: 0, shardCount: 1, status: 'complete', workItemOrderDigest: raw.workItemOrderDigest, rawArtifactDigest: raw.contentDigest.value, rows: normalRows, metricCellCount: 70980 };
    normalized.contentDigest = digestRecord(normalized, rawDomain(engineId, ordinal, 'normalized'));
    rawArtifacts.push(raw); normalizedArtifacts.push(normalized);
  }
  return { rawArtifacts, normalizedArtifacts, crossSummary: buildCrossSummary({ artifacts, rawArtifacts, normalizedArtifacts }), streamEntries };
};

export const buildCrossSummary = ({ artifacts, rawArtifacts, normalizedArtifacts }) => {
  const records = artifacts.fixtureRoster.records; const work = artifacts.workItemRoster.workItems; const corpus = new Map(artifacts.corpus.constructions.flatMap((x) => x.cases).map((x) => [x.caseKey, x]));
  const byEngine = Object.fromEntries(ENGINE_ORDER.map((id) => [id, work.filter((x) => x.engineId === id)]));
  const fixtureRows = records.map((record, i) => {
    const engines = ENGINE_ORDER.map((engineId, ordinal) => { const r = rawArtifacts[ordinal].rows[i]; const n = normalizedArtifacts[ordinal].rows[i]; const w = byEngine[engineId][i]; return { engineId, workItemId: w.workItemId, terminalCellId: w.terminalCellId, terminalStatus: n.terminalStatus, observedVerdict: n.observed.verdict, comparable: r.disposition === 'observed' && n.observed.verdict !== null, rawDigest: r.rawRowDigest.value, normalizedDigest: n.contentDigest.value }; });
    const row = { fixtureKey: record.fixtureKey, terminalCellId: byEngine['engine:native'][i].terminalCellId, fixtureRecordDigest: value(record.contentDigest), expectedVerdict: corpus.get(record.epochIdentity.caseKey).expected.verdict, engines }; row.contentDigest = digestRecord(row, `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/fixture/${row.fixtureKey}`); return row;
  });
  const metricAgreementRows = [];
  for (let fi = 0; fi < records.length; fi++) for (let mi = 0; mi < metricIds.length; mi++) {
    const cells = ENGINE_ORDER.map((engineId, ordinal) => { const n = normalizedArtifacts[ordinal].rows[fi]; const metric = n.metrics[mi]; const eligible = n.disposition === 'observed' && ['measured', 'derived-common', 'derived-engine'].includes(metric.status); return { engineId, workItemId: byEngine[engineId][fi].workItemId, terminalCellId: byEngine[engineId][fi].terminalCellId, status: metric.status, comparable: eligible, valueDigest: eligible ? digestRecord({ metricId: metric.metricId, value: metric.value }, `shieldkit-labs/p2/gate-b/execution-evidence/v2/metric-value/${metric.metricId}`).value : null, normalizedRowDigest: n.contentDigest.value, normalizedCellDigest: metric.contentDigest.value }; });
    const pre = Boolean(records[fi].preflightLimitViolation?.scriptSig || records[fi].preflightLimitViolation?.redeem); const all = cells.every((x) => x.comparable); const equal = all && new Set(cells.map((x) => x.valueDigest)).size === 1; const status = pre ? 'preflight-unsupported' : !all ? 'incomplete' : equal ? 'agree' : 'disagree'; const row = { fixtureKey: records[fi].fixtureKey, metricOrdinal: mi, metricId: metricIds[mi], cells, agreementStatus: status, comparableEngineIds: cells.filter((x) => x.comparable).map((x) => x.engineId), incomparableEngineIds: cells.filter((x) => !x.comparable).map((x) => x.engineId), valueDigests: cells.map((x) => x.valueDigest) }; row.contentDigest = digestRecord(row, `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/metric/${row.fixtureKey}/${row.metricId}`); metricAgreementRows.push(row);
  }
  const comparableFixtures = fixtureRows.filter((r) => r.engines.some((x) => x.comparable)); const verdictAgreement = comparableFixtures.every((r) => new Set(r.engines.filter((x) => x.comparable).map((x) => x.observedVerdict)).size === 1) ? 'complete-eligible-only' : 'disagreement';
  const metricCoverageAgreement = metricAgreementRows.some((r) => r.agreementStatus === 'disagree') ? 'disagreement' : metricAgreementRows.some((r) => r.agreementStatus === 'incomplete') ? 'incomplete' : 'complete-eligible-only';
  const summary = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/cross-engine-summary', evidenceId: 'evidence:cohort-executor-v2:attempt-000', epochId: 'execution-epoch:gate-b-v2', status: 'complete', normalizedArtifactDigests: normalizedArtifacts.map((x) => x.contentDigest.value), fixtureRows, metricAgreementRows, verdictAgreement, metricCoverageAgreement, ranking: null, selection: null };
  summary.contentDigest = digestRecord(summary, 'shieldkit-labs/p2/gate-b/execution-evidence/v2/summary'); return summary;
};

const artifactRef = (root, relative, artifact) => ({ engineId: artifact.engineId, batchOrdinal: artifact.engineBatchOrdinal, shardIndex: artifact.shardIndex, shardCount: artifact.shardCount, path: relative, rawSha256: sha(fs.readFileSync(path.join(root, relative))), contentDigest: artifact.contentDigest.value, status: artifact.status });
const materialize = ({ outputRoot, authorization, rawArtifacts, normalizedArtifacts, crossSummary, streamText, testOnly = false }) => {
  assert(authorization?.executionAllowed === true && typeof outputRoot === 'string', 'authorized explicit output root required');
  const authorizedBase = path.resolve(workspace, authorization.outputPolicy.basePath); const authorizedOutput = path.resolve(workspace, authorization.outputPolicy.exactOutputPath);
  if (!testOnly) {
    assert(path.resolve(outputRoot) === authorizedOutput && fs.realpathSync(authorizedBase) === authorization.outputPolicy.baseRealpath, 'materializer requires the one authorized output path');
    assert(!fs.lstatSync(authorizedBase).isSymbolicLink(), 'authorized output base symlink forbidden');
  }
  assert(!fs.existsSync(outputRoot), 'output root must be absent');
  const parent = path.dirname(outputRoot); assert(fs.existsSync(parent) && fs.lstatSync(parent).isDirectory() && !fs.lstatSync(parent).isSymbolicLink(), 'authorized output parent must be a real directory');
  const scratch = fs.mkdtempSync(path.join(parent, '.cohort-run-'));
  let moved = false;
  try {
    const rawPaths = ENGINE_ORDER.map((id) => `attempt-000/raw/${id}/raw-engine-observation.v2.json`); const normalPaths = ENGINE_ORDER.map((id) => `attempt-000/normalized/${id}/normalized-engine-result.v2.json`);
    for (const item of streams()) assert(streamText.has(item.path), `missing stream materialization: ${item.path}`);
    rawArtifacts.forEach((x, i) => write(scratch, rawPaths[i], x)); normalizedArtifacts.forEach((x, i) => write(scratch, normalPaths[i], x)); write(scratch, 'attempt-000/cross-engine-summary.v2.json', crossSummary); write(scratch, 'attempt-000/authorization.json', authorization);
    for (const item of streams()) write(scratch, item.path, Buffer.isBuffer(streamText.get(item.path)) ? streamText.get(item.path) : Buffer.from(streamText.get(item.path), 'utf8'));
    const entries = []; for (const [i, id] of ENGINE_ORDER.entries()) { entries.push(manifestEntry(entries.length, 'raw-artifact', id, null, 'artifact', rawPaths[i], fs.readFileSync(path.join(scratch, rawPaths[i])))); for (const item of streams().filter((x) => x.engineId === id)) entries.push(manifestEntry(entries.length, 'raw-stream', id, item.processRole, item.role, item.path, fs.readFileSync(path.join(scratch, item.path)))); }
    for (const [i, id] of ENGINE_ORDER.entries()) entries.push(manifestEntry(entries.length, 'normalized-artifact', id, null, 'artifact', normalPaths[i], fs.readFileSync(path.join(scratch, normalPaths[i])))); entries.push(manifestEntry(entries.length, 'cross-engine-summary', null, null, 'artifact', 'attempt-000/cross-engine-summary.v2.json', fs.readFileSync(path.join(scratch, 'attempt-000/cross-engine-summary.v2.json')))); entries.push(manifestEntry(entries.length, 'authorization-binding', null, null, 'authorization', 'attempt-000/authorization.json', fs.readFileSync(path.join(scratch, 'attempt-000/authorization.json')))); assert(entries.length === 25, 'payload inventory drift');
    const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/evidence-manifest', manifestId: 'evidence-manifest:cohort-execution-v2:attempt-000', status: 'complete', attemptIndex: 0, evidenceRootExcluded: true, selfManifestExcluded: true, files: entries, inventoryDigest: digestRecord(entries, 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/inventory') }; manifest.contentDigest = digestRecord(manifest, 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/root'); write(scratch, 'attempt-000/evidence-manifest.v2.json', manifest);
    const root = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/evidence-root', evidenceId: 'evidence:cohort-executor-v2:attempt-000', epochId: 'execution-epoch:gate-b-v2', status: 'complete', contractDigest: authorization.contractBinding.contentDigest, rawArtifacts: rawArtifacts.map((x, i) => artifactRef(scratch, rawPaths[i], x)), normalizedArtifacts: normalizedArtifacts.map((x, i) => artifactRef(scratch, normalPaths[i], x)), crossEngineSummary: { path: 'attempt-000/cross-engine-summary.v2.json', rawSha256: sha(fs.readFileSync(path.join(scratch, 'attempt-000/cross-engine-summary.v2.json'))), contentDigest: crossSummary.contentDigest.value, status: crossSummary.status }, manifestBinding: { path: 'attempt-000/evidence-manifest.v2.json', rawSha256: sha(fs.readFileSync(path.join(scratch, 'attempt-000/evidence-manifest.v2.json'))), schemaPath: authorization.evidenceManifestSchema.path, schemaSha256: authorization.evidenceManifestSchema.rawSha256, contentDigest: manifest.contentDigest.value, inventoryDigest: manifest.inventoryDigest.value, listedPayloadCount: 25, selfManifestExcluded: true, evidenceRootExcluded: true }, obligationAccounting: { total: 18928, preflightUnsupported: 496, executable: 18432 }, ranking: null, selection: null }; root.contentDigest = digestRecord(root, 'shieldkit-labs/p2/gate-b/evidence-root/v2/root'); write(scratch, 'evidence-root.v2.json', root);
    validateEvidencePackage({ attemptRoot: scratch, authorization }); fs.renameSync(scratch, outputRoot); moved = true; validateEvidencePackage({ attemptRoot: outputRoot, authorization }); return { status: 'PASS', path: outputRoot, root, manifest };
  } catch (error) { fs.rmSync(moved ? outputRoot : scratch, { recursive: true, force: true }); throw error; }
};
/** Host-test-only primitive. The CLI never imports or reaches this route. */
export const materializeTestAttempt = (options) => materialize({ ...options, testOnly: true });
export const materializeAttempt = (options) => materialize({ ...options, testOnly: false });
