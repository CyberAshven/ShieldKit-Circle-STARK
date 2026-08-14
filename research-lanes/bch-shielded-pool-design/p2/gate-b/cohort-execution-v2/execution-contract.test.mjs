import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { buildContract, validateContract, validateManifest, validateInvocation, validateRawInvocationSemantics, validateNormalizedRowSemantics, validateRawRowSemantics, validateCrossSummarySemantics, validateEvidenceManifest, validateEvidenceRootSemantics, digestRecord, ROOT_DOMAIN } from './contract/execution-contract.mjs';

const packageDir = path.dirname(new URL(import.meta.url).pathname);
const rootSchema = JSON.parse(fs.readFileSync(path.join(packageDir, 'contract/execution-root.v2.schema.json')));
const ajv = new Ajv2020({ allErrors: true, strict: true });
const rootValidate = ajv.compile(rootSchema);

test('frozen contract validates and preserves accounting', () => {
  const result = validateContract();
  assert.equal(result.status, 'PASS');
  assert.equal(result.totalObligations, 18928);
  assert.equal(result.preflightObligations, 496);
  assert.equal(result.executableObligations, 18432);
});

test('manifest binds every generated file', () => assert.equal(validateManifest().status, 'PASS'));

test('root digest and batch order digest are self-describing', () => {
  const c = buildContract();
  assert.deepEqual(Object.keys(c.contentDigest).sort(), ['algorithm', 'canonicalization', 'domain', 'frame', 'value']);
  assert.equal(c.contentDigest.domain, ROOT_DOMAIN);
  for (const batch of c.schedule.batches) assert.equal(batch.workItemOrderDigest.frame, 'utf8(domain)||0x00||canonical-json-utf8');
  assert.deepEqual(Object.keys(c.digestDomains).sort(), ['crossFixtureRow', 'crossMetricRow', 'evidenceRoot', 'inventory', 'manifest', 'metricCell', 'metricValue', 'normalizedArtifact', 'normalizedRow', 'rawArtifact', 'rawObservation', 'rawRow', 'root', 'scheduleBatch', 'summary']);
});

test('schema rejects execution, retry, shard, ranking, and accounting mutations', () => {
  const c = buildContract();
  for (const mutate of [
    x => { x.execution = {}; },
    x => { x.retryPolicy.retries = 1; },
    x => { x.schedule.batches[0].shardCount = 2; },
    x => { x.ranking = {}; },
    x => { x.obligationAccounting.preflightObligations = 495; }
  ]) {
    const m = structuredClone(c); mutate(m); assert.equal(rootValidate(m), false);
  }
});

test('order and digest substitutions are rejected by deterministic validation', () => {
  const c = buildContract();
  const reordered = structuredClone(c); [reordered.schedule.batches[0].firstWorkItemId, reordered.schedule.batches[0].lastWorkItemId] = [reordered.schedule.batches[0].lastWorkItemId, reordered.schedule.batches[0].firstWorkItemId];
  assert.throws(() => validateContract(reordered), /contract differs|digest mismatch/);
  const substituted = structuredClone(c); substituted.schedule.batches[1].workItemOrderDigest.value = '0'.repeat(64); substituted.contentDigest = digestRecord(Object.fromEntries(Object.entries(substituted).filter(([k]) => k !== 'contentDigest')), ROOT_DOMAIN);
  assert.throws(() => validateContract(substituted), /contract differs|digest mismatch/);
});

test('engine schema path and hash are authoritative', () => {
  const c = buildContract();
  assert.equal(c.enginePins[0].schemaPath, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engine.v2.schema.json');
  const mutated = structuredClone(c); mutated.enginePins[0].schemaPath = `${mutated.enginePins[0].schemaPath.replace('/engine.v2.schema.json', '/engines/engine.v2.schema.json')}`;
  assert.throws(() => validateContract(mutated), /engine schema missing|contract differs/);
});

test('contract source contains no engine invocation path', () => {
  const source = fs.readFileSync(path.join(packageDir, 'contract/execution-contract.mjs'), 'utf8');
  assert.doesNotMatch(source, /child_process|spawn\(|execFile\(|engineRunner|vm\.run/i);
});

test('all seven evidence schemas are strict-compilable and pinned', () => {
  const names = ['execution-root.v2.schema.json', 'evidence-root.v2.schema.json', 'evidence-manifest.v2.schema.json', 'raw-engine-observation.v2.schema.json', 'normalized-engine-result.v2.schema.json', 'cross-engine-summary.v2.schema.json', 'manifest.v1.schema.json'];
  const localAjv = new Ajv2020({ allErrors: true, strict: true });
  for (const name of names) localAjv.compile(JSON.parse(fs.readFileSync(path.join(packageDir, 'contract', name))));
  assert.deepEqual(buildContract().artifactSchemas.map(x => x.kind), ['execution-root', 'evidence-root', 'evidence-manifest', 'raw-engine-observation', 'normalized-engine-result', 'cross-engine-summary', 'manifest']);
});

test('invocation semantics require closed runtime and Lean primary plus costprobe secondary', () => {
  const base = { entrypoints: [{ role: 'primary', path: 'vmbconf', rawSha256: 'a'.repeat(64), argv: ['vmbconf'] }, { role: 'secondary', path: 'costprobe', rawSha256: 'b'.repeat(64), argv: ['costprobe'] }], runtime: { nodeVersion: '22', os: 'linux', arch: 'x64', cwd: '/frozen', runtimeDigest: 'c'.repeat(64) }, environment: { allowlistDigest: 'd'.repeat(64), variables: {} } };
  assert.doesNotThrow(() => validateInvocation('engine:leanbch', base));
  assert.throws(() => validateInvocation('engine:leanbch', { ...base, entrypoints: base.entrypoints.slice(0, 1) }), /LeanBCH/);
  assert.throws(() => validateInvocation('engine:native', base), /non-Lean/);
  assert.throws(() => validateInvocation('engine:native', { ...base, entrypoints: [base.entrypoints[0]], runtime: { ...base.runtime, extra: 'reject' } }), /runtime shape/);
});

test('normalized semantics reject taxonomy, metric-order, verdict, and preflight mutations', () => {
  const ids = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];
  const row = { disposition: 'preflight-limit-unsupported', terminalStatus: 'preflight-limit-unsupported', observed: { verdict: null, failureStage: 'preflight-limit' }, metrics: ids.map(metricId => ({ metricId, status: 'preflight-limit-unsupported' })) };
  assert.doesNotThrow(() => validateNormalizedRowSemantics(row));
  const order = structuredClone(row); [order.metrics[0], order.metrics[1]] = [order.metrics[1], order.metrics[0]]; assert.throws(() => validateNormalizedRowSemantics(order), /order/);
  const verdict = structuredClone(row); verdict.metrics[0].status = 'measured-noncomparable'; assert.throws(() => validateNormalizedRowSemantics(verdict), /verdict/);
  const stage = structuredClone(row); stage.observed.failureStage = 'unknown-stage'; assert.throws(() => validateNormalizedRowSemantics(stage), /failure stage/);
  const observed = structuredClone(row); observed.disposition = 'observed'; observed.terminalStatus = 'observed'; observed.metrics = ids.map(metricId => ({ metricId, status: 'measured' })); assert.doesNotThrow(() => validateNormalizedRowSemantics(observed));
  observed.terminalStatus = 'preflight-limit-unsupported'; assert.throws(() => validateNormalizedRowSemantics(observed), /unreachable/);
  const unsupported = { disposition: 'engine-unsupported-incomplete', terminalStatus: 'engine-unsupported-incomplete', observed: { verdict: null, failureStage: 'process' }, rawObservationDigest: { value: 'a'.repeat(64) }, unsupportedBinding: { agreementEligible: false }, metrics: ids.map(metricId => ({ metricId, status: 'not-applicable' })) };
  assert.doesNotThrow(() => validateNormalizedRowSemantics(unsupported));
  const notRun = { disposition: 'not-run-incomplete', terminalStatus: 'not-run-incomplete', observed: { verdict: null, failureStage: 'not-run-incomplete' }, rawObservationDigest: null, notRunBinding: { agreementEligible: false }, metrics: ids.map(metricId => ({ metricId, status: 'not-reached', reason: 'not-run-after-prior-engine-batch-failure' })) };
  assert.doesNotThrow(() => validateNormalizedRowSemantics(notRun));
  const laundered = structuredClone(notRun); laundered.metrics[0].status = 'measured'; assert.throws(() => validateNormalizedRowSemantics(laundered), /not-run/);
});

test('raw semantics reject digest-only and accept structured or file-span observations', () => {
  assert.doesNotThrow(() => validateRawRowSemantics({ disposition: 'observed', rawObservation: { kind: 'structured', payload: {}, byteStart: 0 } }));
  assert.doesNotThrow(() => validateRawRowSemantics({ disposition: 'observed', rawObservation: { kind: 'file-span', artifactPath: 'raw.log', artifactRawSha256: 'a'.repeat(64), byteStart: 0, byteEnd: 1, lineStart: 1, lineEnd: 1, spanSha256: 'b'.repeat(64), manifestPath: 'MANIFEST.json', manifestEntrySha256: 'c'.repeat(64) } }));
  assert.throws(() => validateRawRowSemantics({ disposition: 'observed', rawObservation: null }), /structured or manifest/);
  assert.doesNotThrow(() => validateRawRowSemantics({ disposition: 'preflight-limit-unsupported', rawObservation: null }));
  assert.doesNotThrow(() => validateRawRowSemantics({ disposition: 'engine-unsupported-incomplete', unsupportedBinding: { agreementEligible: false }, rawObservation: { kind: 'structured', payload: {} } }));
  assert.throws(() => validateRawRowSemantics({ disposition: 'engine-unsupported-incomplete', unsupportedBinding: { agreementEligible: false }, rawObservation: null }), /structured or manifest/);
  assert.doesNotThrow(() => validateRawRowSemantics({ disposition: 'not-run-incomplete', notRunBinding: { reason: 'prior-engine-batch-failure' }, rawObservation: null }));
});

test('raw endpoint semantics reject duplicate/shared Lean logs and wrong order', () => {
  const stream = p => ({ path: p });
  const endpoint = (role, base) => ({ role, stdin: stream(`${base}-stdin`), stdout: stream(`${base}-stdout`), stderr: stream(`${base}-stderr`), exitCode: 0, timedOut: false });
  assert.doesNotThrow(() => validateRawInvocationSemantics('engine:leanbch', { entrypoints: [endpoint('primary', 'vmbconf'), endpoint('secondary', 'costprobe')] }));
  assert.throws(() => validateRawInvocationSemantics('engine:leanbch', { entrypoints: [endpoint('secondary', 'costprobe'), endpoint('primary', 'vmbconf')] }), /order/);
  assert.throws(() => validateRawInvocationSemantics('engine:leanbch', { entrypoints: [endpoint('primary', 'same'), { ...endpoint('secondary', 'same'), stdout: stream('same-stdin') }] }), /shared/);
});

test('evidence manifest enforces exact 25-payload DAG and rejects duplicate-root entries', () => {
  const expected = [];
  for (const engineId of ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']) { expected.push({ kind: 'raw-artifact', engineId, processRole: null, role: 'artifact' }); const roles = engineId === 'engine:leanbch' ? [['primary', 'stdin'], ['primary', 'stdout'], ['primary', 'stderr'], ['secondary', 'stdin'], ['secondary', 'stdout'], ['secondary', 'stderr']] : [[null, 'stdin'], [null, 'stdout'], [null, 'stderr']]; for (const [processRole, role] of roles) expected.push({ kind: 'raw-stream', engineId, processRole, role }); }
  for (const engineId of ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']) expected.push({ kind: 'normalized-artifact', engineId, processRole: null, role: 'artifact' });
  expected.push({ kind: 'cross-engine-summary', engineId: null, processRole: null, role: 'artifact' }, { kind: 'authorization-binding', engineId: null, processRole: null, role: 'authorization' });
  const expectedPath = e => e.kind === 'raw-artifact' ? `attempt-000/raw/${e.engineId}/raw-engine-observation.v2.json` : e.kind === 'raw-stream' ? `attempt-000/raw/${e.engineId}/${e.processRole ? `${e.processRole}-` : ''}${e.role}.log` : e.kind === 'normalized-artifact' ? `attempt-000/normalized/${e.engineId}/normalized-engine-result.v2.json` : e.kind === 'cross-engine-summary' ? 'attempt-000/cross-engine-summary.v2.json' : 'attempt-000/authorization.json';
  const files = expected.map((e, ordinal) => { const body = { ordinal, ...e, path: expectedPath(e), rawSha256: 'a'.repeat(64), byteLength: 1 }; return { ...body, manifestEntrySha256: digestRecord(body, `shieldkit-labs/p2/gate-b/evidence-manifest/v2/entry/${body.path}`) }; });
  const manifest = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/evidence-manifest', manifestId: 'evidence-manifest:cohort-execution-v2:attempt-000', status: 'complete', attemptIndex: 0, evidenceRootExcluded: true, selfManifestExcluded: true, files, inventoryDigest: digestRecord(files, 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/inventory') };
  manifest.contentDigest = digestRecord(manifest, 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/root');
  assert.doesNotThrow(() => validateEvidenceManifest(manifest));
  const duplicate = structuredClone(manifest); duplicate.files[24].path = 'evidence-root.json'; assert.throws(() => validateEvidenceManifest(duplicate), /identity|duplicate or root/);
  const badEntry = structuredClone(manifest); badEntry.files[1].manifestEntrySha256.value = '0'.repeat(64); assert.throws(() => validateEvidenceManifest(badEntry), /entry digest/);
});

test('evidence root binds canonical paths, contract domain, and incomplete status coherently', () => {
  const c = buildContract(); const engines = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']; const zero = 'a'.repeat(64);
  const artifact = (engineId, batchOrdinal, kind) => ({ engineId, batchOrdinal, shardIndex: 0, shardCount: 1, path: kind === 'raw' ? `attempt-000/raw/${engineId}/raw-engine-observation.v2.json` : `attempt-000/normalized/${engineId}/normalized-engine-result.v2.json`, rawSha256: zero, contentDigest: zero, status: 'not-started' });
  const root = { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/evidence-root', evidenceId: 'evidence:attempt-000', epochId: 'execution-epoch:gate-b-v2', status: 'incomplete', contractDigest: c.contentDigest.value, rawArtifacts: engines.map((e, i) => artifact(e, i, 'raw')), normalizedArtifacts: engines.map((e, i) => artifact(e, i, 'normalized')), crossEngineSummary: { path: 'attempt-000/cross-engine-summary.v2.json', rawSha256: zero, contentDigest: zero, status: 'not-started' }, manifestBinding: { path: 'attempt-000/evidence-manifest.v2.json', schemaPath: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/contract/evidence-manifest.v2.schema.json', rawSha256: zero, schemaSha256: zero, contentDigest: zero, inventoryDigest: zero, listedPayloadCount: 25, selfManifestExcluded: true, evidenceRootExcluded: true }, obligationAccounting: { total: 18928, preflightUnsupported: 496, executable: 18432 }, ranking: null, selection: null };
  root.contentDigest = digestRecord(root, 'shieldkit-labs/p2/gate-b/evidence-root/v2/root');
  assert.doesNotThrow(() => validateEvidenceRootSemantics(root, c));
  const wrongPath = structuredClone(root); wrongPath.rawArtifacts[0].path = 'attempt-000/raw/engine:native/forged.json'; assert.throws(() => validateEvidenceRootSemantics(wrongPath, c), /path|digest/);
  const wrongDomain = structuredClone(root); wrongDomain.contentDigest.domain = ROOT_DOMAIN; assert.throws(() => validateEvidenceRootSemantics(wrongDomain, c), /constant|digest/);
  const premature = structuredClone(root); premature.status = 'complete'; assert.throws(() => validateEvidenceRootSemantics(premature, c), /incomplete artifact|content digest/);
  const noncausal = structuredClone(root); for (const [i, status] of ['not-started', 'complete', 'not-started', 'complete'].entries()) { noncausal.rawArtifacts[i].status = status; noncausal.normalizedArtifacts[i].status = status; } delete noncausal.contentDigest; noncausal.contentDigest = digestRecord(noncausal, 'shieldkit-labs/p2/gate-b/evidence-root/v2/root'); assert.throws(() => validateEvidenceRootSemantics(noncausal, c), /complete prefix|sequence/);
});

test('cross-engine semantic validator rejects omitted, reordered, and false-agreement shapes', () => {
  assert.throws(() => validateCrossSummarySemantics({ fixtureRows: [], metricAgreementRows: [] }), /required|omitted/);
  const authority = JSON.parse(fs.readFileSync(path.join(packageDir, '..', 'cohort-freeze-v2', 'fixture-roster.v2.json'))).records;
  const work = JSON.parse(fs.readFileSync(path.join(packageDir, '..', 'cohort-freeze-v2', 'work-item-roster.v2.json'))).workItems;
  const corpus = JSON.parse(fs.readFileSync(path.join(packageDir, '..', 'cohort-freeze-v2', 'canonical-corpus.v2.json'))).constructions.flatMap(x => x.cases);
  const corpusByKey = new Map(corpus.map(x => [x.caseKey, x]));
  const byEngine = Object.fromEntries(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'].map(e => [e, work.filter(x => x.engineId === e)]));
  const isPreflight = i => Boolean(authority[i].preflightLimitViolation?.scriptSig || authority[i].preflightLimitViolation?.redeem);
  const normalizedArtifacts = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'].map((engineId, ordinal) => {
    const rows = byEngine[engineId].map((workItem, i) => { const fixture = authority[i]; const expected = corpusByKey.get(fixture.epochIdentity.caseKey).expected; const pre = isPreflight(i); const metrics = idsForTest.map((metricId, metricOrdinal) => { const metric = { metricId, status: pre ? 'preflight-limit-unsupported' : 'measured', value: pre ? null : metricId === 'verdict' ? expected.verdict : metricOrdinal, provenance: pre ? null : { sourceArtifactDigest: 'a'.repeat(64), method: 'test' }, reason: pre ? 'preflight-limit-unsupported' : null }; metric.contentDigest = digestRecord(metric, `shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/${engineId}/batch/${ordinal}/shard/0/metric/${workItem.workItemId}/${metricId}`); return metric; }); const row = { workItemId: workItem.workItemId, fixtureKey: workItem.fixtureKey, terminalCellId: workItem.terminalCellId, workItemOrdinal: i, fixtureRecordDigest: fixture.contentDigest.value, disposition: pre ? 'preflight-limit-unsupported' : 'observed', expected, terminalStatus: pre ? 'preflight-limit-unsupported' : 'observed', observed: { verdict: pre ? null : expected.verdict, failureStage: pre ? 'preflight-limit' : expected.stage }, rawObservationDigest: null, unsupportedBinding: null, notRunBinding: null, metrics }; row.contentDigest = digestRecord(row, `shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/${engineId}/batch/${ordinal}/shard/0/row/${workItem.workItemId}`); return row; }); const artifact = { engineId, engineBatchOrdinal: ordinal, shardIndex: 0, status: 'complete', shardIndex: 0, workItemOrderDigest: digestRecord(byEngine[engineId].map(x => x.workItemId), `shieldkit-labs/p2/gate-b/execution-evidence/v2/schedule/${engineId}`), rawArtifactDigest: '0'.repeat(64), rows }; artifact.contentDigest = digestRecord(artifact, `shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/${engineId}/batch/${ordinal}/shard/0`); return artifact; });
  const rawArtifacts = normalizedArtifacts.map((nartifact, ordinal) => { const rows = nartifact.rows.map((nrow, i) => { const raw = { workItemId: nrow.workItemId, fixtureKey: nrow.fixtureKey, terminalCellId: nrow.terminalCellId, workItemOrdinal: i, fixtureRecordDigest: nrow.fixtureRecordDigest, disposition: nrow.disposition, preflightBinding: null, unsupportedBinding: null, notRunBinding: null, rawObservation: null }; raw.rawRowDigest = digestRecord(raw, `shieldkit-labs/p2/gate-b/execution-evidence/v2/raw/${nartifact.engineId}/batch/${ordinal}/shard/0/row/${nrow.workItemId}`); return raw; }); const artifact = { engineId: nartifact.engineId, engineBatchOrdinal: ordinal, shardIndex: 0, status: 'complete', rows }; artifact.contentDigest = digestRecord(artifact, `shieldkit-labs/p2/gate-b/execution-evidence/v2/raw/${nartifact.engineId}/batch/${ordinal}/shard/0`); return artifact; });
  for (const [ordinal, nartifact] of normalizedArtifacts.entries()) { for (const nrow of nartifact.rows) { const raw = rawArtifacts[ordinal].rows.find(x => x.workItemId === nrow.workItemId); if (nrow.disposition === 'observed' || nrow.disposition === 'engine-unsupported-incomplete') nrow.rawObservationDigest = raw.rawRowDigest; delete nrow.contentDigest; nrow.contentDigest = digestRecord(nrow, `shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/${nartifact.engineId}/batch/${ordinal}/shard/0/row/${nrow.workItemId}`); } nartifact.rawArtifactDigest = rawArtifacts[ordinal].contentDigest.value; delete nartifact.contentDigest; nartifact.contentDigest = digestRecord(nartifact, `shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/${nartifact.engineId}/batch/${ordinal}/shard/0`); }
  const metricValue = metric => digestRecord({ metricId: metric.metricId, value: metric.value }, `shieldkit-labs/p2/gate-b/execution-evidence/v2/metric-value/${metric.metricId}`).value;
  const ec = (e, i, metricOrdinal) => { const nrow = normalizedArtifacts.find(x => x.engineId === e).rows[i]; const metric = nrow.metrics[metricOrdinal]; const pre = isPreflight(i); return { engineId: e, workItemId: byEngine[e][i].workItemId, terminalCellId: byEngine[e][i].terminalCellId, comparable: !pre, valueDigest: pre ? null : metricValue(metric), normalizedRowDigest: nrow.contentDigest.value, normalizedCellDigest: metric.contentDigest.value, status: pre ? 'preflight-limit-unsupported' : 'measured' }; };
  const c = { normalizedArtifactDigests: normalizedArtifacts.map(x => x.contentDigest.value), fixtureRows: authority.map((r, i) => { const expected = corpusByKey.get(r.epochIdentity.caseKey).expected; const pre = isPreflight(i); const row = { fixtureKey: r.fixtureKey, terminalCellId: byEngine['engine:native'][i].terminalCellId, fixtureRecordDigest: r.contentDigest.value, expectedVerdict: expected.verdict, engines: ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'].map(e => { const nrow = normalizedArtifacts.find(x => x.engineId === e).rows[i]; return { engineId: e, workItemId: byEngine[e][i].workItemId, terminalCellId: byEngine[e][i].terminalCellId, terminalStatus: nrow.terminalStatus, observedVerdict: nrow.observed.verdict, comparable: !pre, rawDigest: 'd'.repeat(64), normalizedDigest: nrow.contentDigest.value }; }) }; row.contentDigest = digestRecord(row, `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/fixture/${r.fixtureKey}`); return row; }), metricAgreementRows: Array.from({ length: 70980 }, (_, i) => { const fi = Math.floor(i / 15); const pre = isPreflight(fi); const cells = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'].map(e => ec(e, fi, i % 15)); const row = { fixtureKey: authority[fi].fixtureKey, metricOrdinal: i % 15, metricId: idsForTest[i % 15], cells, agreementStatus: pre ? 'preflight-unsupported' : 'agree', comparableEngineIds: pre ? [] : ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'], incomparableEngineIds: pre ? ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'] : [], valueDigests: cells.map(x => x.valueDigest) }; row.contentDigest = digestRecord(row, `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/metric/${row.fixtureKey}/${row.metricId}`); return row; }) };
  c.schema = 'shieldkit-labs/p2/gate-b/cohort-execution-v2/cross-engine-summary'; c.evidenceId = 'cross:test'; c.epochId = 'execution-epoch:gate-b-v2'; c.status = 'complete'; c.verdictAgreement = 'complete-eligible-only'; c.metricCoverageAgreement = 'complete-eligible-only'; c.ranking = null; c.selection = null;
  for (let i = 0; i < c.fixtureRows.length; i++) { for (const cell of c.fixtureRows[i].engines) cell.rawDigest = rawArtifacts.find(x => x.engineId === cell.engineId).rows[i].rawRowDigest.value; delete c.fixtureRows[i].contentDigest; c.fixtureRows[i].contentDigest = digestRecord(c.fixtureRows[i], `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/fixture/${c.fixtureRows[i].fixtureKey}`); }
  c.contentDigest = digestRecord(c, 'shieldkit-labs/p2/gate-b/execution-evidence/v2/summary');
  assert.doesNotThrow(() => validateCrossSummarySemantics(c, normalizedArtifacts, rawArtifacts));
  const refreshSummary = s => { s.contentDigest = digestRecord(Object.fromEntries(Object.entries(s).filter(([k]) => k !== 'contentDigest')), 'shieldkit-labs/p2/gate-b/execution-evidence/v2/summary'); return s; };
  const falseAgree = structuredClone(c); falseAgree.metricAgreementRows[0].cells[1].valueDigest = 'b'.repeat(64); falseAgree.metricAgreementRows[0].contentDigest = digestRecord(Object.fromEntries(Object.entries(falseAgree.metricAgreementRows[0]).filter(([k]) => k !== 'contentDigest')), `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/metric/${falseAgree.metricAgreementRows[0].fixtureKey}/${falseAgree.metricAgreementRows[0].metricId}`); refreshSummary(falseAgree); assert.throws(() => validateCrossSummarySemantics(falseAgree, normalizedArtifacts, rawArtifacts), /agreement|projection/);
  const eligibleFixture = authority.findIndex((_, i) => !isPreflight(i)); const forgedComparable = structuredClone(c); forgedComparable.fixtureRows[eligibleFixture].engines[0].comparable = false; forgedComparable.fixtureRows[eligibleFixture].contentDigest = digestRecord(Object.fromEntries(Object.entries(forgedComparable.fixtureRows[eligibleFixture]).filter(([k]) => k !== 'contentDigest')), `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/fixture/${forgedComparable.fixtureRows[eligibleFixture].fixtureKey}`); refreshSummary(forgedComparable); assert.throws(() => validateCrossSummarySemantics(forgedComparable, normalizedArtifacts, rawArtifacts), /comparable projection/);
  const forgedExpected = structuredClone(c); forgedExpected.fixtureRows[0].expectedVerdict = forgedExpected.fixtureRows[0].expectedVerdict === 'accept' ? 'reject' : 'accept'; forgedExpected.fixtureRows[0].contentDigest = digestRecord(Object.fromEntries(Object.entries(forgedExpected.fixtureRows[0]).filter(([k]) => k !== 'contentDigest')), `shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/fixture/${forgedExpected.fixtureRows[0].fixtureKey}`); refreshSummary(forgedExpected); assert.throws(() => validateCrossSummarySemantics(forgedExpected, normalizedArtifacts, rawArtifacts), /expected/);
  const forgedDomain = structuredClone(c); forgedDomain.contentDigest.domain = ROOT_DOMAIN; assert.throws(() => validateCrossSummarySemantics(forgedDomain, normalizedArtifacts, rawArtifacts), /domain|frame/);
  const reordered = structuredClone(c); [reordered.normalizedArtifactDigests[0], reordered.normalizedArtifactDigests[1]] = [reordered.normalizedArtifactDigests[1], reordered.normalizedArtifactDigests[0]]; refreshSummary(reordered); assert.throws(() => validateCrossSummarySemantics(reordered, normalizedArtifacts, rawArtifacts), /artifact digest/);
});

const idsForTest = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];
