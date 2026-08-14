import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const packageDir = path.resolve(here, '..');
const workspaceDir = path.resolve(packageDir, '../../../../..');
const freezeDir = path.resolve(packageDir, '../cohort-freeze-v2');
const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-contract/v2/root';
const SCHEDULE_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-evidence/v2/schedule/<engineId>';
const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
const FRAME = 'utf8(domain)||0x00||canonical-json-utf8';

const engineOrder = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'];
const relationOrder = ['relation:e-mac', 'relation:e-square-mac', 'relation:e-inverse-check'];
const categoryOrder = ['category:valid', 'category:boundary', 'category:random', 'category:metamorphic', 'category:malformed'];
const metricVocabulary = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }
function relative(file) { return path.relative(workspaceDir, file).split(path.sep).join('/'); }
function fileSha(file) { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); }
function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonicalize(value[k])]));
  return value;
}
function canonicalBytes(value) { return Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8'); }
function digestRecord(value, domain) {
  const hash = crypto.createHash('sha256').update(Buffer.concat([Buffer.from(domain), Buffer.from([0]), canonicalBytes(value)])).digest('hex');
  return { algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value: hash };
}
function valueDigest(value) { return typeof value === 'string' ? value : value.value; }
function withoutDigest(value) { const copy = structuredClone(value); delete copy.contentDigest; return copy; }
function assert(condition, message) { if (!condition) throw new Error(message); }
const exactMetricOrder = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];
const exactFailureStages = ['accept', 'coefficient-range-check-before-arithmetic', 'unused-high-bit-check-before-numeric-decode', 'exact-extension-element-length-check-before-limb-decode', 'relation-check', 'inverse-relation-check', 'preflight-limit', 'process', 'timeout', 'parser', 'not-run-incomplete', 'outer-transaction-or-token'];
const EVIDENCE_MANIFEST_ENTRY_DOMAIN = 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/entry/';
const EVIDENCE_MANIFEST_INVENTORY_DOMAIN = 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/inventory';
const DIGEST_DOMAINS = {
  root: ROOT_DOMAIN,
  scheduleBatch: SCHEDULE_DOMAIN,
  rawArtifact: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/raw/<engineId>/batch/<batchOrdinal>/shard/<shardIndex>',
  rawRow: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/raw/<engineId>/batch/<batchOrdinal>/shard/<shardIndex>/row/<workItemId>',
  rawObservation: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/raw/<engineId>/batch/<batchOrdinal>/shard/<shardIndex>/observation/<workItemId>',
  normalizedArtifact: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/<engineId>/batch/<batchOrdinal>/shard/<shardIndex>',
  normalizedRow: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/<engineId>/batch/<batchOrdinal>/shard/<shardIndex>/row/<workItemId>',
  metricCell: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/normalized/<engineId>/batch/<batchOrdinal>/shard/<shardIndex>/metric/<workItemId>/<metricId>',
  metricValue: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/metric-value/<metricId>',
  crossFixtureRow: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/fixture/<fixtureKey>',
  crossMetricRow: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/summary/metric/<fixtureKey>/<metricId>',
  summary: 'shieldkit-labs/p2/gate-b/execution-evidence/v2/summary',
  manifest: 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/root',
  inventory: 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/inventory',
  evidenceRoot: 'shieldkit-labs/p2/gate-b/evidence-root/v2/root'
};
function instantiateDomain(template, values) { return template.replace(/<([A-Za-z]+)>/g, (_, key) => { assert(Object.hasOwn(values, key), `missing digest domain binding: ${key}`); return values[key]; }); }
function verifyDigest(record, value, domain, label) {
  assert(record && typeof record === 'object', `${label} digest missing`);
  assert(record.algorithm === 'sha256' && record.canonicalization === CANONICALIZATION && record.frame === FRAME && record.domain === domain, `${label} digest domain/frame mismatch`);
  assert(record.value === digestRecord(value, domain).value, `${label} digest value mismatch`);
}
function withoutField(value, field) { const copy = structuredClone(value); delete copy[field]; return copy; }
function validateInvocation(engineId, invocation) {
  assert(invocation && Array.isArray(invocation.entrypoints), 'invocation entrypoints missing');
  const roles = invocation.entrypoints.map(e => e.role);
  assert(new Set(roles).size === roles.length, 'duplicate invocation endpoint role');
  assert(roles.includes('primary'), 'primary invocation endpoint missing');
  if (engineId === 'engine:leanbch') assert(roles.length === 2 && roles.includes('secondary'), 'LeanBCH requires primary vmbconf and secondary costprobe endpoints');
  else assert(roles.length === 1, 'non-Lean engine requires exactly one primary endpoint');
  assert(Object.keys(invocation.runtime).sort().join(',') === 'arch,cwd,nodeVersion,os,runtimeDigest', 'runtime shape is not closed');
  assert(Object.keys(invocation.environment).sort().join(',') === 'allowlistDigest,variables', 'environment shape is not closed');
  return true;
}
function validateNormalizedRowSemantics(row) {
  assert(row.metrics.length === 15, 'normalized metric count mismatch');
  assert(JSON.stringify(row.metrics.map(m => m.metricId)) === JSON.stringify(exactMetricOrder), 'normalized metric order or uniqueness mismatch');
  assert(row.metrics[0].status !== 'measured-noncomparable', 'verdict cannot be measured-noncomparable');
  assert(exactFailureStages.includes(row.observed.failureStage) || row.observed.failureStage === null, 'observed failure stage outside exact taxonomy');
  if (row.disposition === 'preflight-limit-unsupported') assert(row.metrics.every(m => m.status === 'preflight-limit-unsupported'), 'preflight row metric status mismatch');
  if (row.disposition === 'engine-unsupported-incomplete') assert(row.metrics.every(m => m.status === 'not-applicable') && row.unsupportedBinding?.agreementEligible === false && row.rawObservationDigest, 'unsupported row laundering');
  if (row.disposition === 'not-run-incomplete') assert(row.metrics.every(m => m.status === 'not-reached' && m.reason === 'not-run-after-prior-engine-batch-failure') && row.notRunBinding?.agreementEligible === false && row.rawObservationDigest === null && row.observed.verdict === null && row.observed.failureStage === 'not-run-incomplete', 'not-run row laundering');
  if (row.disposition === 'observed') assert(['observed', 'process-failure', 'timeout', 'parser-failure'].includes(row.terminalStatus), 'unreachable observed terminal status');
  return true;
}
function validateRawRowSemantics(row) {
  if (row.disposition === 'preflight-limit-unsupported') { assert(row.rawObservation === null, 'preflight raw observation must be null'); return true; }
  if (row.disposition === 'not-run-incomplete') { assert(row.rawObservation === null && row.notRunBinding?.reason === 'prior-engine-batch-failure', 'not-run raw observation must be null and explicitly bound'); return true; }
  assert(row.rawObservation && ['structured', 'file-span'].includes(row.rawObservation.kind), 'raw row lacks structured or manifest-covered file-span observation');
  if (row.rawObservation.kind === 'file-span') { assert(row.rawObservation.artifactPath && row.rawObservation.manifestPath && /^[0-9a-f]{64}$/.test(row.rawObservation.artifactRawSha256) && /^[0-9a-f]{64}$/.test(row.rawObservation.spanSha256) && /^[0-9a-f]{64}$/.test(row.rawObservation.manifestEntrySha256), 'raw file span is not manifest-bound'); assert(row.rawObservation.byteEnd > row.rawObservation.byteStart, 'raw span is empty'); assert(row.rawObservation.lineEnd >= row.rawObservation.lineStart, 'raw span lines inverted'); }
  return true;
}
function validateRawInvocationSemantics(engineId, invocation) {
  const endpoints = invocation?.entrypoints ?? [];
  assert(new Set(endpoints.map(e => e.role)).size === endpoints.length, 'duplicate raw endpoint role');
  if (engineId === 'engine:leanbch') assert(endpoints.map(e => e.role).join('|') === 'primary|secondary', 'Lean endpoint order must be primary vmbconf then secondary costprobe');
  else assert(endpoints.length === 1 && endpoints[0].role === 'primary', 'non-Lean raw endpoint cardinality/role drift');
  const streamPaths = new Set();
  for (const endpoint of endpoints) { assert(endpoint.stdin.path !== endpoint.stdout.path && endpoint.stdin.path !== endpoint.stderr.path && endpoint.stdout.path !== endpoint.stderr.path, 'shared raw log path'); for (const stream of [endpoint.stdin, endpoint.stdout, endpoint.stderr]) { assert(!streamPaths.has(stream.path), 'shared raw log path across endpoints'); streamPaths.add(stream.path); } assert(typeof endpoint.exitCode === 'number' || endpoint.exitCode === null, 'raw exit code shape'); assert(typeof endpoint.timedOut === 'boolean', 'raw timeout shape'); }
  return true;
}
function authorityRows() {
  const fixtureRoster = readJson(path.join(freezeDir, 'fixture-roster.v2.json'));
  const workRoster = readJson(path.join(freezeDir, 'work-item-roster.v2.json'));
  const corpus = readJson(path.join(freezeDir, 'canonical-corpus.v2.json'));
  const corpusCases = corpus.constructions.flatMap(c => c.cases);
  const corpusByCaseKey = new Map(corpusCases.map(c => [c.caseKey, c]));
  assert(fixtureRoster.records.length === 4732 && workRoster.workItems.length === 18928, 'frozen authority roster count mismatch');
  const byEngine = new Map(engineOrder.map(engineId => [engineId, workRoster.workItems.filter(w => w.engineId === engineId)]));
  for (const engineId of engineOrder) { const rows = byEngine.get(engineId); assert(rows.length === 4732, `frozen work roster engine count mismatch: ${engineId}`); assert(rows.every((w, i) => w.fixtureKey === fixtureRoster.records[i].fixtureKey), `frozen work roster order mismatch: ${engineId}`); }
  for (const fixture of fixtureRoster.records) assert(corpusByCaseKey.has(fixture.epochIdentity.caseKey), `fixture case missing from canonical corpus: ${fixture.fixtureKey}`);
  return { fixtureRecords: fixtureRoster.records, byEngine, corpusByCaseKey };
}
function validateRawArtifactSemantics(artifact) {
  const schema = readJson(path.join(here, 'raw-engine-observation.v2.schema.json')); const ajv = new Ajv({ allErrors: true, strict: true }); const validator = ajv.compile(schema); assert(validator(artifact), ajv.errorsText(validator.errors));
  const authority = authorityRows(); const expected = authority.byEngine.get(artifact.engineId); assert(expected, 'unknown raw artifact engine'); assert(artifact.engineBatchOrdinal === engineOrder.indexOf(artifact.engineId), 'raw artifact engine batch ordinal mismatch'); assert(artifact.rows.length === 4732, 'raw artifact row count mismatch'); validateRawInvocationSemantics(artifact.engineId, artifact.invocation);
  const domainValues = { engineId: artifact.engineId, batchOrdinal: artifact.engineBatchOrdinal, shardIndex: artifact.shardIndex }; const orderDomain = instantiateDomain(DIGEST_DOMAINS.scheduleBatch, { engineId: artifact.engineId }); verifyDigest(artifact.workItemOrderDigest, expected.map(w => w.workItemId), orderDomain, 'raw work-item order'); verifyDigest(artifact.contentDigest, withoutDigest(artifact), instantiateDomain(DIGEST_DOMAINS.rawArtifact, domainValues), 'raw artifact');
  for (let i = 0; i < expected.length; i++) { const row = artifact.rows[i]; const work = expected[i]; const fixture = authority.fixtureRecords[i]; const preflight = Boolean(fixture.preflightLimitViolation?.scriptSig || fixture.preflightLimitViolation?.redeem); assert(row.workItemOrdinal === i && row.workItemId === work.workItemId && row.fixtureKey === work.fixtureKey && row.terminalCellId === work.terminalCellId && row.fixtureRecordDigest === valueDigest(fixture.contentDigest), `raw row identity/order mismatch at ${i}`); verifyDigest(row.rawRowDigest, withoutField(row, 'rawRowDigest'), instantiateDomain(DIGEST_DOMAINS.rawRow, { ...domainValues, workItemId: row.workItemId }), `raw row ${i}`); if (row.rawObservation?.kind === 'structured') verifyDigest(row.rawObservation.rawObservationDigest, withoutField(row.rawObservation, 'rawObservationDigest'), instantiateDomain(DIGEST_DOMAINS.rawObservation, { ...domainValues, workItemId: row.workItemId }), `raw observation ${i}`); if (preflight) { assert(row.disposition === 'preflight-limit-unsupported' && row.preflightBinding?.kind === 'preflight-limit' && row.preflightBinding.scriptSig === Boolean(fixture.preflightLimitViolation.scriptSig) && row.preflightBinding.redeem === Boolean(fixture.preflightLimitViolation.redeem) && row.rawObservation === null, `preflight raw row escaped preflight at ${i}`); } else if (row.disposition === 'engine-unsupported-incomplete') { assert(['incomplete', 'failed'].includes(artifact.status) && artifact.engineId === 'engine:leanbch' && row.rawObservation && row.unsupportedBinding?.agreementEligible === false, `unsupported raw row laundering at ${i}`); } else if (row.disposition === 'not-run-incomplete') { assert(['incomplete', 'failed'].includes(artifact.status) && row.rawObservation === null && row.notRunBinding?.reason === 'prior-engine-batch-failure', `not-run raw row invalid at ${i}`); } else { assert(row.disposition === 'observed' && row.preflightBinding === null && row.rawObservation, `observed raw row missing observation at ${i}`); } validateRawRowSemantics(row); }
  return true;
}
function validateNormalizedArtifactSemantics(artifact, rawArtifact) {
  const schema = readJson(path.join(here, 'normalized-engine-result.v2.schema.json')); const ajv = new Ajv({ allErrors: true, strict: true }); const validator = ajv.compile(schema); assert(validator(artifact), ajv.errorsText(validator.errors));
  const authority = authorityRows(); const expected = authority.byEngine.get(artifact.engineId); assert(expected && artifact.engineBatchOrdinal === engineOrder.indexOf(artifact.engineId) && rawArtifact.engineId === artifact.engineId && rawArtifact.engineBatchOrdinal === artifact.engineBatchOrdinal, 'normalized/raw engine identity mismatch'); assert(artifact.status === rawArtifact.status, 'normalized/raw artifact status mismatch'); assert(artifact.rows.length === 4732 && rawArtifact.rows.length === 4732, 'normalized/raw row count mismatch');
  const domainValues = { engineId: artifact.engineId, batchOrdinal: artifact.engineBatchOrdinal, shardIndex: artifact.shardIndex }; verifyDigest(rawArtifact.workItemOrderDigest, expected.map(w => w.workItemId), instantiateDomain(DIGEST_DOMAINS.scheduleBatch, { engineId: artifact.engineId }), 'raw work-item order'); verifyDigest(rawArtifact.contentDigest, withoutDigest(rawArtifact), instantiateDomain(DIGEST_DOMAINS.rawArtifact, domainValues), 'raw artifact binding'); verifyDigest(artifact.workItemOrderDigest, expected.map(w => w.workItemId), instantiateDomain(DIGEST_DOMAINS.scheduleBatch, { engineId: artifact.engineId }), 'normalized work-item order'); assert(artifact.rawArtifactDigest === rawArtifact.contentDigest.value, 'normalized rawArtifactDigest binding mismatch'); verifyDigest(artifact.contentDigest, withoutDigest(artifact), instantiateDomain(DIGEST_DOMAINS.normalizedArtifact, domainValues), 'normalized artifact');
  for (let i = 0; i < expected.length; i++) { const row = artifact.rows[i]; const raw = rawArtifact.rows[i]; const work = expected[i]; const fixture = authority.fixtureRecords[i]; const corpusCase = authority.corpusByCaseKey.get(fixture.epochIdentity.caseKey); const preflight = Boolean(fixture.preflightLimitViolation?.scriptSig || fixture.preflightLimitViolation?.redeem); assert(row.workItemOrdinal === i && row.workItemId === work.workItemId && row.fixtureKey === work.fixtureKey && row.terminalCellId === work.terminalCellId && row.fixtureRecordDigest === valueDigest(fixture.contentDigest), `normalized row identity/order mismatch at ${i}`); assert(row.disposition === raw.disposition, `normalized/raw disposition relabel at ${i}`); assert(row.expected.verdict === corpusCase.expected.verdict && row.expected.stage === corpusCase.expected.stage, `normalized expected corpus mismatch at ${i}`); if (raw.disposition === 'preflight-limit-unsupported' || raw.disposition === 'not-run-incomplete') assert(row.rawObservationDigest === null, `normalized raw binding mismatch at ${i}`); else verifyDigest(row.rawObservationDigest, withoutField(raw, 'rawRowDigest'), instantiateDomain(DIGEST_DOMAINS.rawRow, { ...domainValues, workItemId: row.workItemId }), `normalized raw binding ${i}`); if (preflight) assert(row.disposition === 'preflight-limit-unsupported' && row.terminalStatus === 'preflight-limit-unsupported', `normalized preflight row escaped preflight at ${i}`); if (row.disposition === 'engine-unsupported-incomplete') assert(artifact.engineId === 'engine:leanbch' && row.rawObservationDigest && row.unsupportedBinding?.agreementEligible === false && row.terminalStatus === 'engine-unsupported-incomplete', `normalized unsupported row laundering at ${i}`); if (row.disposition === 'not-run-incomplete') assert(['incomplete', 'failed'].includes(artifact.status) && row.rawObservationDigest === null && row.notRunBinding?.reason === 'prior-engine-batch-failure' && row.terminalStatus === 'not-run-incomplete', `normalized not-run row invalid at ${i}`); verifyDigest(row.contentDigest, withoutDigest(row), instantiateDomain(DIGEST_DOMAINS.normalizedRow, { ...domainValues, workItemId: row.workItemId }), `normalized row ${i}`); for (const metric of row.metrics) verifyDigest(metric.contentDigest, withoutField(metric, 'contentDigest'), instantiateDomain(DIGEST_DOMAINS.metricCell, { ...domainValues, workItemId: row.workItemId, metricId: metric.metricId }), `metric ${i}/${metric.metricId}`); validateNormalizedRowSemantics(row); }
  return true;
}
function metricValueDigest(metric) { return digestRecord({ metricId: metric.metricId, value: metric.value }, instantiateDomain(DIGEST_DOMAINS.metricValue, { metricId: metric.metricId })).value; }
function validateFixtureComparableProjection(summary, normalizedArtifacts) {
  if (!Array.isArray(summary?.fixtureRows) || !Array.isArray(normalizedArtifacts) || normalizedArtifacts.length !== 4) return;
  const authority = authorityRows();
  for (let i = 0; i < summary.fixtureRows.length; i++) {
    const fixture = authority.fixtureRecords[i];
    if (!fixture) continue;
    const preflight = Boolean(fixture.preflightLimitViolation?.scriptSig || fixture.preflightLimitViolation?.redeem);
    for (const cell of summary.fixtureRows[i].engines ?? []) {
      const nrow = normalizedArtifacts[engineOrder.indexOf(cell.engineId)]?.rows?.[i];
      if (!nrow) continue;
      const eligible = !preflight && nrow.disposition === 'observed' && nrow.terminalStatus === 'observed' && nrow.observed?.verdict !== null;
      assert(cell.comparable === eligible, `fixture comparable projection mismatch at ${i}`);
    }
  }
}
function validateCrossSummarySemantics(summary, normalizedArtifacts, rawArtifacts) {
  const schema = readJson(path.join(here, 'cross-engine-summary.v2.schema.json')); const ajv = new Ajv({ allErrors: true, strict: true }); const validator = ajv.compile(schema); assert(validator(summary), ajv.errorsText(validator.errors));
  assert(summary.fixtureRows.length === 4732 && summary.metricAgreementRows.length === 70980, 'cross-engine rows omitted');
  validateFixtureComparableProjection(summary, normalizedArtifacts);
  verifyDigest(summary.contentDigest, withoutDigest(summary), DIGEST_DOMAINS.summary, 'cross summary');
  assert(Array.isArray(normalizedArtifacts) && normalizedArtifacts.length === 4 && Array.isArray(rawArtifacts) && rawArtifacts.length === 4, 'cross summary requires four normalized and raw artifacts');
  const authority = authorityRows(); const normalizedByEngine = new Map(); const rawByEngine = new Map();
  for (let ordinal = 0; ordinal < 4; ordinal++) { const artifact = rawArtifacts[ordinal]; assert(artifact.engineId === engineOrder[ordinal] && artifact.engineBatchOrdinal === ordinal && artifact.rows?.length === 4732, `raw artifact order/count mismatch at ${ordinal}`); verifyDigest(artifact.contentDigest, withoutDigest(artifact), instantiateDomain(DIGEST_DOMAINS.rawArtifact, { engineId: artifact.engineId, batchOrdinal: ordinal, shardIndex: artifact.shardIndex }), `cross raw artifact ${ordinal}`); rawByEngine.set(artifact.engineId, artifact); for (let i = 0; i < 4732; i++) { const rrow = artifact.rows[i]; const work = authority.byEngine.get(artifact.engineId)[i]; assert(rrow.workItemId === work.workItemId && rrow.fixtureKey === work.fixtureKey && rrow.terminalCellId === work.terminalCellId && rrow.workItemOrdinal === i, `raw artifact identity mismatch at ${ordinal}/${i}`); verifyDigest(rrow.rawRowDigest, withoutField(rrow, 'rawRowDigest'), instantiateDomain(DIGEST_DOMAINS.rawRow, { engineId: artifact.engineId, batchOrdinal: ordinal, shardIndex: artifact.shardIndex, workItemId: rrow.workItemId }), `cross raw row ${ordinal}/${i}`); } }
  for (let ordinal = 0; ordinal < 4; ordinal++) { const artifact = normalizedArtifacts[ordinal]; const rawArtifact = rawArtifacts[ordinal]; assert(artifact.engineId === engineOrder[ordinal] && artifact.engineBatchOrdinal === ordinal && artifact.rows?.length === 4732, `normalized artifact order/count mismatch at ${ordinal}`); assert(artifact.status === rawArtifact.status, `normalized/raw artifact status mismatch at ${ordinal}`); verifyDigest(artifact.contentDigest, withoutDigest(artifact), instantiateDomain(DIGEST_DOMAINS.normalizedArtifact, { engineId: artifact.engineId, batchOrdinal: ordinal, shardIndex: artifact.shardIndex }), `cross normalized artifact ${ordinal}`); normalizedByEngine.set(artifact.engineId, artifact); assert(summary.normalizedArtifactDigests?.[ordinal] === artifact.contentDigest.value, `normalized artifact digest/order mismatch at ${ordinal}`); for (let i = 0; i < 4732; i++) { const nrow = artifact.rows[i]; const rrow = rawArtifact.rows[i]; const work = authority.byEngine.get(artifact.engineId)[i]; assert(nrow.workItemId === work.workItemId && nrow.fixtureKey === work.fixtureKey && nrow.terminalCellId === work.terminalCellId && nrow.workItemOrdinal === i, `normalized artifact identity mismatch at ${ordinal}/${i}`); assert(nrow.disposition === rrow.disposition, `normalized/raw disposition mismatch at ${ordinal}/${i}`); if (rrow.disposition === 'preflight-limit-unsupported' || rrow.disposition === 'not-run-incomplete') assert(nrow.rawObservationDigest === null, `normalized raw digest mismatch at ${ordinal}/${i}`); else assert(nrow.rawObservationDigest?.value === rrow.rawRowDigest.value, `normalized raw digest mismatch at ${ordinal}/${i}`); verifyDigest(nrow.contentDigest, withoutDigest(nrow), instantiateDomain(DIGEST_DOMAINS.normalizedRow, { engineId: artifact.engineId, batchOrdinal: ordinal, shardIndex: artifact.shardIndex, workItemId: nrow.workItemId }), `cross normalized row ${ordinal}/${i}`); for (const metric of nrow.metrics) verifyDigest(metric.contentDigest, withoutField(metric, 'contentDigest'), instantiateDomain(DIGEST_DOMAINS.metricCell, { engineId: artifact.engineId, batchOrdinal: ordinal, shardIndex: artifact.shardIndex, workItemId: nrow.workItemId, metricId: metric.metricId }), `cross metric ${ordinal}/${i}/${metric.metricId}`); } }
  const fixtureAgreementStates = [];
  for (let i = 0; i < summary.fixtureRows.length; i++) { const row = summary.fixtureRows[i]; const fixture = authority.fixtureRecords[i]; const corpusCase = authority.corpusByCaseKey.get(fixture.epochIdentity.caseKey); const preflight = Boolean(fixture.preflightLimitViolation?.scriptSig || fixture.preflightLimitViolation?.redeem); assert(row.fixtureKey === fixture.fixtureKey && row.terminalCellId === authority.byEngine.get(engineOrder[0])[i].terminalCellId && row.fixtureRecordDigest === valueDigest(fixture.contentDigest) && row.expectedVerdict === corpusCase.expected.verdict, `fixture authority/expected mismatch at ${i}`); verifyDigest(row.contentDigest, withoutDigest(row), instantiateDomain(DIGEST_DOMAINS.crossFixtureRow, { fixtureKey: row.fixtureKey }), `cross fixture row ${i}`); assert(row.engines.map(e => e.engineId).join('|') === engineOrder.join('|'), `fixture engine order mismatch at ${i}`); for (const cell of row.engines) { const work = authority.byEngine.get(cell.engineId)[i]; const nrow = normalizedByEngine.get(cell.engineId).rows[i]; const rrow = rawByEngine.get(cell.engineId).rows[i]; assert(cell.workItemId === work.workItemId && cell.terminalCellId === work.terminalCellId && cell.normalizedDigest === nrow.contentDigest.value && cell.rawDigest === rrow.rawRowDigest.value, `fixture engine cell identity/digest mismatch at ${i}`); assert(cell.terminalStatus === nrow.terminalStatus && cell.observedVerdict === nrow.observed.verdict, `fixture terminal/observed coherence mismatch at ${i}`); if (preflight) assert(cell.comparable === false && cell.terminalStatus === 'preflight-limit-unsupported' && cell.observedVerdict === null, `preflight fixture cell laundering at ${i}`); if (['engine-unsupported-incomplete', 'not-run-incomplete'].includes(cell.terminalStatus)) assert(cell.comparable === false && cell.observedVerdict === null, `incomplete fixture cell laundering at ${i}`); } const comparable = row.engines.filter(c => c.comparable); const incomplete = row.engines.some(c => ['not-run-incomplete', 'process-failure', 'timeout', 'parser-failure'].includes(c.terminalStatus)); fixtureAgreementStates.push(preflight ? 'preflight-unsupported' : incomplete ? 'incomplete' : comparable.length === 0 ? 'not-comparable' : new Set(comparable.map(c => c.observedVerdict)).size === 1 ? 'agree' : 'disagree'); }
  const derivedMetricAgreements = [];
  for (let i = 0; i < summary.metricAgreementRows.length; i++) { const row = summary.metricAgreementRows[i]; const fixtureIndex = Math.floor(i / 15); const preflight = Boolean(authority.fixtureRecords[fixtureIndex].preflightLimitViolation?.scriptSig || authority.fixtureRecords[fixtureIndex].preflightLimitViolation?.redeem); assert(row.fixtureKey === authority.fixtureRecords[fixtureIndex].fixtureKey, `metric fixture identity/order mismatch at ${i}`); assert(row.metricOrdinal === i % 15, `metric ordinal mismatch at ${i}`); assert(row.metricId === exactMetricOrder[row.metricOrdinal], `metric id mismatch at ${i}`); verifyDigest(row.contentDigest, withoutDigest(row), instantiateDomain(DIGEST_DOMAINS.crossMetricRow, { fixtureKey: row.fixtureKey, metricId: row.metricId }), `cross metric row ${i}`); assert(row.cells.map(e => e.engineId).join('|') === engineOrder.join('|'), `metric engine order mismatch at ${i}`); for (const cell of row.cells) { const work = authority.byEngine.get(cell.engineId)[fixtureIndex]; const nrow = normalizedByEngine.get(cell.engineId).rows[fixtureIndex]; const metric = nrow.metrics[row.metricOrdinal]; const eligible = !preflight && nrow.disposition === 'observed' && ['measured', 'derived-common', 'derived-engine'].includes(metric.status); assert(cell.workItemId === work.workItemId && cell.terminalCellId === work.terminalCellId && cell.status === metric.status && cell.normalizedRowDigest === nrow.contentDigest.value && cell.normalizedCellDigest === metric.contentDigest.value, `metric normalized identity/status/digest mismatch at ${i}`); assert(cell.comparable === eligible, `metric comparability projection mismatch at ${i}`); assert(cell.valueDigest === (eligible ? metricValueDigest(metric) : null), `metric value projection mismatch at ${i}`); } const allComparable = row.cells.every(c => c.comparable); const allValuesEqual = allComparable && new Set(row.cells.map(c => c.valueDigest)).size === 1; const hasNotReached = row.cells.some(c => c.status === 'not-reached'); const hasUnsupported = row.cells.some(c => c.status === 'not-applicable'); const derived = preflight ? 'preflight-unsupported' : hasNotReached ? 'incomplete' : !allComparable ? (hasUnsupported ? 'not-comparable' : 'incomplete') : allValuesEqual ? 'agree' : 'disagree'; derivedMetricAgreements.push(derived); assert(row.agreementStatus === derived, `metric agreement derivation mismatch at ${i}`); assert(JSON.stringify(row.valueDigests) === JSON.stringify(row.cells.map(c => c.valueDigest)), `metric value digest projection mismatch at ${i}`); assert(JSON.stringify(row.comparableEngineIds) === JSON.stringify(row.cells.filter(c => c.comparable).map(c => c.engineId)), `comparable engine projection mismatch at ${i}`); assert(JSON.stringify(row.incomparableEngineIds) === JSON.stringify(row.cells.filter(c => !c.comparable).map(c => c.engineId)), `incomparable engine projection mismatch at ${i}`); }
  const eligibleFixtureStates = fixtureAgreementStates.filter(s => s !== 'preflight-unsupported'); const eligibleMetricStates = derivedMetricAgreements.filter(s => s !== 'preflight-unsupported'); const derivedVerdictAgreement = eligibleFixtureStates.length === 0 ? 'not-started' : eligibleFixtureStates.includes('incomplete') ? 'incomplete' : eligibleFixtureStates.includes('disagree') ? 'disagreement' : 'complete-eligible-only'; const derivedMetricCoverage = eligibleMetricStates.length === 0 ? 'not-started' : eligibleMetricStates.includes('incomplete') ? 'incomplete' : eligibleMetricStates.includes('disagree') ? 'disagreement' : 'complete-eligible-only'; assert(summary.verdictAgreement === derivedVerdictAgreement, 'top-level verdictAgreement is not derived from fixture rows'); assert(summary.metricCoverageAgreement === derivedMetricCoverage, 'top-level metricCoverageAgreement is not derived from metric rows'); const statuses = [...rawArtifacts, ...normalizedArtifacts].map(a => a.status); const derivedStatus = statuses.every(s => s === 'not-started') ? 'not-started' : statuses.some(s => s === 'failed') ? 'failed' : statuses.some(s => s === 'incomplete') ? 'incomplete' : statuses.every(s => s === 'complete') ? 'complete' : 'incomplete'; assert(summary.status === derivedStatus, 'cross summary status is not coherent with in-memory artifacts'); return true;
}
// Root state machine: complete* (incomplete|failed)? not-started*.
function validateEvidenceRootSemantics(root, contract = readJson(path.join(packageDir, 'execution-contract.v2.json'))) {
  const schema = readJson(path.join(here, 'evidence-root.v2.schema.json'));
  const ajv = new Ajv({ allErrors: true, strict: true });
  const validator = ajv.compile(schema);
  assert(validator(root), ajv.errorsText(validator.errors));
  const expectedContractValue = typeof contract === 'string' ? contract : (contract.contentDigest?.value ?? contract.value);
  const expectedContractDomain = typeof contract === 'string' ? ROOT_DOMAIN : (contract.contentDigest?.domain ?? ROOT_DOMAIN);
  assert(root.contractDigest === expectedContractValue, 'evidence root contract digest mismatch');
  assert(expectedContractDomain === ROOT_DOMAIN, 'evidence root contract domain mismatch');
  assert(root.contentDigest.value === digestRecord(withoutDigest(root), 'shieldkit-labs/p2/gate-b/evidence-root/v2/root').value, 'evidence root content digest mismatch');
  const expectedRaw = engineOrder.map(engineId => `attempt-000/raw/${engineId}/raw-engine-observation.v2.json`);
  const expectedNorm = engineOrder.map(engineId => `attempt-000/normalized/${engineId}/normalized-engine-result.v2.json`);
  assert(root.rawArtifacts.map(x => x.path).join('|') === expectedRaw.join('|') && root.normalizedArtifacts.map(x => x.path).join('|') === expectedNorm.join('|'), 'evidence root artifact path/order mismatch');
  assert(root.rawArtifacts.every((x, i) => x.status === root.normalizedArtifacts[i].status), 'evidence root raw/normalized status mismatch');
  assert(root.crossEngineSummary.path === 'attempt-000/cross-engine-summary.v2.json', 'evidence root summary path mismatch');
  assert(root.manifestBinding.path === 'attempt-000/evidence-manifest.v2.json' && root.manifestBinding.listedPayloadCount === 25, 'evidence root manifest binding mismatch');
  const batchStatuses = root.rawArtifacts.map(x => x.status);
  let seenCurrent = false;
  let seenNotStarted = false;
  for (const status of batchStatuses) {
    if (status === 'complete') assert(!seenCurrent && !seenNotStarted, 'evidence root engine-major sequence is not a complete prefix');
    else if (status === 'incomplete' || status === 'failed') { assert(!seenCurrent && !seenNotStarted, 'evidence root has multiple current/noncausal batches'); seenCurrent = true; }
    else if (status === 'not-started') seenNotStarted = true;
    else assert(false, `invalid engine-major status ${status}`);
  }
  const derivedEngineStatus = batchStatuses.every(s => s === 'complete') ? 'complete' : batchStatuses.some(s => s === 'failed') ? 'failed' : batchStatuses.every(s => s === 'not-started') ? 'not-started' : 'incomplete';
  assert(root.crossEngineSummary.status === derivedEngineStatus, 'cross summary status is incoherent with engine-major artifacts');
  const statuses = [...root.rawArtifacts, ...root.normalizedArtifacts, root.crossEngineSummary].map(x => x.status);
  if (root.status === 'complete') assert(statuses.every(s => s === 'complete'), 'complete evidence root has incomplete artifact');
  const derivedRootStatus = statuses.every(s => s === 'complete') ? 'complete' : statuses.some(s => s === 'failed') ? 'failed' : 'incomplete';
  assert(root.status === derivedRootStatus, 'evidence root status is incoherent with artifact statuses');
  return true;
}
function validateEvidenceManifest(manifest) {
  const schema = readJson(path.join(here, 'evidence-manifest.v2.schema.json')); const evidenceAjv = new Ajv({ allErrors: true, strict: true }); const validator = evidenceAjv.compile(schema); assert(validator(manifest), evidenceAjv.errorsText(validator.errors));
  assert(manifest.files.length === 25, 'evidence manifest payload count mismatch');
  const expected = [];
  for (const engineId of engineOrder) { expected.push({ kind: 'raw-artifact', engineId, processRole: null, role: 'artifact' }); const roles = engineId === 'engine:leanbch' ? [['primary', 'stdin'], ['primary', 'stdout'], ['primary', 'stderr'], ['secondary', 'stdin'], ['secondary', 'stdout'], ['secondary', 'stderr']] : [[null, 'stdin'], [null, 'stdout'], [null, 'stderr']]; for (const [processRole, role] of roles) expected.push({ kind: 'raw-stream', engineId, processRole, role }); }
  for (const engineId of engineOrder) expected.push({ kind: 'normalized-artifact', engineId, processRole: null, role: 'artifact' });
  expected.push({ kind: 'cross-engine-summary', engineId: null, processRole: null, role: 'artifact' }, { kind: 'authorization-binding', engineId: null, processRole: null, role: 'authorization' });
  const paths = new Set();
  const expectedPath = exp => exp.kind === 'raw-artifact' ? `attempt-000/raw/${exp.engineId}/raw-engine-observation.v2.json` : exp.kind === 'raw-stream' ? `attempt-000/raw/${exp.engineId}/${exp.processRole ? `${exp.processRole}-` : ''}${exp.role}.log` : exp.kind === 'normalized-artifact' ? `attempt-000/normalized/${exp.engineId}/normalized-engine-result.v2.json` : exp.kind === 'cross-engine-summary' ? 'attempt-000/cross-engine-summary.v2.json' : 'attempt-000/authorization.json';
  for (let i = 0; i < expected.length; i++) { const entry = manifest.files[i]; const exp = expected[i]; assert(entry.ordinal === i && entry.kind === exp.kind && entry.engineId === exp.engineId && entry.processRole === exp.processRole && entry.role === exp.role && entry.path === expectedPath(exp), `evidence manifest order/identity/path mismatch at ${i}`); assert(!paths.has(entry.path) && !entry.path.includes('evidence-root'), `evidence manifest duplicate or root entry at ${i}`); paths.add(entry.path); const body = structuredClone(entry); delete body.manifestEntrySha256; assert(entry.manifestEntrySha256.value === digestRecord(body, `${EVIDENCE_MANIFEST_ENTRY_DOMAIN}${entry.path}`).value, `evidence manifest entry digest mismatch at ${i}`); }
  assert(manifest.inventoryDigest.value === digestRecord(manifest.files, EVIDENCE_MANIFEST_INVENTORY_DOMAIN).value, 'evidence manifest inventory digest mismatch');
  assert(manifest.contentDigest.value === digestRecord(Object.fromEntries(Object.entries(manifest).filter(([k]) => k !== 'contentDigest')), 'shieldkit-labs/p2/gate-b/evidence-manifest/v2/root').value, 'evidence manifest content digest mismatch');
  return true;
}

function binding(record, fallbackSchemaPath) {
  const file = path.resolve(workspaceDir, record.path);
  const schemaPath = record.schemaPath ?? fallbackSchemaPath;
  const schemaFile = path.resolve(workspaceDir, schemaPath);
  return { artifactId: record.artifactId, path: record.path, schemaPath, rawSha256: record.rawSha256 ?? fileSha(file), schemaSha256: record.schemaSha256 ?? fileSha(schemaFile), contentDigest: valueDigest(record.contentDigest) };
}

function schemaPins() {
  const entries = [
    ['execution-root', 'execution-root.v2.schema.json'],
    ['evidence-root', 'evidence-root.v2.schema.json'],
    ['evidence-manifest', 'evidence-manifest.v2.schema.json'],
    ['raw-engine-observation', 'raw-engine-observation.v2.schema.json'],
    ['normalized-engine-result', 'normalized-engine-result.v2.schema.json'],
    ['cross-engine-summary', 'cross-engine-summary.v2.schema.json'],
    ['manifest', 'manifest.v1.schema.json']
  ];
  return entries.map(([kind, name]) => ({ kind, path: relative(path.join(here, name)), rawSha256: fileSha(path.join(here, name)) }));
}

function enginePins(epoch) {
  return epoch.engineRecords.map(e => ({ engineId: e.engineId, artifactId: e.artifactId, path: e.path, rawSha256: e.rawSha256, schemaPath: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/engine.v2.schema.json', schemaSha256: e.schemaSha256, contentDigest: valueDigest(e.contentDigest), capabilityStatus: e.capabilityStatus, role: 'engine' }));
}

function buildContract() {
  const epoch = readJson(path.join(freezeDir, 'execution-epoch.v2.json'));
  const roster = readJson(path.join(freezeDir, 'work-item-roster.v2.json'));
  const records = readJson(path.join(freezeDir, 'fixture-roster.v2.json'));
  const campaign = readJson(path.join(freezeDir, 'campaign.v2.json'));
  const corpus = readJson(path.join(freezeDir, 'canonical-corpus.v2.json'));
  const sourceSet = readJson(path.resolve(workspaceDir, epoch.sourceSet.path));
  const schedule = epoch.physicalSchedule.batches.map((b, ordinal) => {
    assert(b.engineId === engineOrder[ordinal], `engine order mismatch at batch ${ordinal}`);
    assert(b.workItemIds.length === 4732, `work-item count mismatch for ${b.engineId}`);
    const digest = digestRecord(b.workItemIds, SCHEDULE_DOMAIN.replace('<engineId>', b.engineId));
    return { engineId: b.engineId, batchOrdinal: ordinal, shardIndex: 0, shardCount: 1, workItemCount: 4732, workItemOrderDigest: digest, firstWorkItemId: b.workItemIds[0], lastWorkItemId: b.workItemIds.at(-1), preflightObligationCount: 124, executableObligationCount: 4608, checkpointBoundary: 'terminal-engine-batch-only' };
  });
  const artifact = {
    schema: 'shieldkit-labs/p2/gate-b/cohort-execution/v2', contractId: 'execution-contract:gate-b-v2', status: 'frozen-unexecuted', evidenceClassification: 'contract-only-not-execution-evidence', executionAllowed: false, metricsAllowed: false, ranking: null, selection: null,
    executionGate: { status: 'closed-contract-only', permittedEpochId: 'execution-epoch:gate-b-v2', permittedAttemptIndex: 0, permittedRetries: 0, runnerBinding: null, runnerBindingRequired: true },
    epochBinding: binding({ ...epoch, artifactId: 'execution-epoch:gate-b-v2', path: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.json' }, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/execution-epoch.v2.schema.json'), sourceSetBinding: binding(epoch.sourceSet, 'research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.schema.json'), campaignBinding: binding(epoch.campaign, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/campaign.v2.schema.json'), corpusBinding: binding(epoch.corpus, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/canonical-corpus.v2.schema.json'), fixtureRosterBinding: binding(epoch.fixtureRoster, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/fixture-roster.v2.schema.json'),
    workItemRosterBinding: { ...binding(epoch.workItemRoster, 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2/work-item-roster.v2.schema.json'), counts: roster.counts }, engineOrder, enginePins: enginePins(epoch), relationOrder, categoryOrder,
    schedule: { policy: { engineMajorBatches: true, maxConcurrency: 1, warmups: 0, oneProcessOrModuleLifecyclePerEngineBatch: true, automaticRetries: false, timeoutMsPerExternalBatch: 600000, cpuAffinity: false, timingMetrics: false, resultDependentScheduling: false, incompleteBatchBlocksEpoch: true, retryWholeIdenticalEpochOnly: true, rawAttemptAccounting: true }, batches: schedule },
    obligationAccounting: { totalObligations: 18928, perEngineObligations: 4732, fixtureCases: 4732, preflightFixtureCases: 124, preflightObligations: 496, executableFixtureCases: 4608, executableObligations: 18432, rawRows: 18928, normalizedRows: 18928, preflightPlanRelation: 'arm:optimized:m31-d6-direct-toom6-v1|relation:e-mac', preflightCategoryBreakdown: { 'category:valid': 16, 'category:boundary': 18, 'category:random': 32, 'category:metamorphic': 16, 'category:malformed': 42 } },
    metricVocabulary, statusTaxonomy: { terminal: ['observed', 'preflight-limit-unsupported', 'process-failure', 'timeout', 'parser-failure', 'engine-unsupported-incomplete', 'not-run-incomplete'], metric: ['measured', 'measured-noncomparable', 'derived-common', 'derived-engine', 'not-reached', 'not-exposed', 'not-applicable', 'preflight-limit-unsupported'], failureStages: ['accept', 'coefficient-range-check-before-arithmetic', 'unused-high-bit-check-before-numeric-decode', 'exact-extension-element-length-check-before-limb-decode', 'relation-check', 'inverse-relation-check', 'preflight-limit', 'process', 'timeout', 'parser', 'not-run-incomplete', 'outer-transaction-or-token'] },
    retryPolicy: { attemptIndex: 0, retries: 0, automaticRetries: false, partialMerge: false, restartRule: 'rerun-identical-complete-epoch-from-ordinal-zero-under-new-evidence-root' }, shardPolicy: { shardCountPerEngine: 1, shardBoundary: 'one-shard-all-4732-work-items-in-frozen-batch-order', partialShardEvidence: 'incomplete-not-admissible', checkpointDigest: 'digest-of-complete-engine-batch-raw-artifact', intraEngineShardingChange: 'requires-new-contract-version', checkpointOrdering: 'engine-major-batch-order-native-libauth-bchn-leanbch' },
    artifactSchemas: schemaPins(), digestDomains: DIGEST_DOMAINS,
    rawObservationPolicy: { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/raw-engine-observation', oneArtifactPerEngineBatch: true, rowsPerArtifact: 4732, preflightRowsHaveNoObservation: true, rawStreams: ['stdin', 'stdout', 'stderr'], rawObservationRequired: true, normalizationForbidden: true }, normalizedResultPolicy: { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/normalized-engine-result', oneArtifactPerEngineBatch: true, rowsPerArtifact: 4732, metricCellCountPerArtifact: 70980, rawReferenceRequired: true, expectedCorpusStageRequired: true }, crossEnginePolicy: { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/cross-engine-summary', fixtureRows: 4732, metricAgreementRows: 70980, preflightAgreement: 'not-comparable-does-not-count-as-agreement', ranking: null, selection: null }, execution: null, result: null, metric: null
  };
  for (const pin of artifact.enginePins) {
    const schemaFile = path.resolve(workspaceDir, pin.schemaPath);
    assert(fs.existsSync(schemaFile), `engine schema missing: ${pin.schemaPath}`);
    assert(fileSha(schemaFile) === pin.schemaSha256, `engine schema hash mismatch: ${pin.engineId}`);
  }
  artifact.contentDigest = digestRecord(withoutDigest(artifact), ROOT_DOMAIN);
  assert(sourceSet.contentDigest?.value === valueDigest(epoch.sourceSet.contentDigest), 'source-set authority mismatch');
  assert(campaign.contentDigest?.value === valueDigest(epoch.campaign.contentDigest), 'campaign authority mismatch');
  assert(corpus.contentDigest?.value === valueDigest(epoch.corpus.contentDigest), 'corpus authority mismatch');
  assert(records.counts.uniquePlanCaseFixtures === 4732, 'fixture roster count mismatch');
  return artifact;
}

function validateContract(artifact = readJson(path.join(packageDir, 'execution-contract.v2.json'))) {
  const schema = readJson(path.join(here, 'execution-root.v2.schema.json'));
  const ajv = new Ajv({ allErrors: true, strict: true });
  const validator = ajv.compile(schema); const valid = validator(artifact);
  assert(valid, ajv.errorsText(validator.errors));
  const expected = buildContract();
  assert(JSON.stringify(artifact) === JSON.stringify(expected), 'contract differs from deterministic materialization');
  assert(artifact.contentDigest.value === digestRecord(withoutDigest(artifact), ROOT_DOMAIN).value, 'root content digest mismatch');
  return { status: 'PASS', contractDigest: artifact.contentDigest.value, totalObligations: 18928, preflightObligations: 496, executableObligations: 18432, batches: 4 };
}

function buildManifest(contract) {
  const paths = ['README.md', 'COMMAND.txt', 'contract/execution-contract.mjs', 'contract/execution-root.v2.schema.json', 'contract/evidence-root.v2.schema.json', 'contract/evidence-manifest.v2.schema.json', 'contract/raw-engine-observation.v2.schema.json', 'contract/normalized-engine-result.v2.schema.json', 'contract/cross-engine-summary.v2.schema.json', 'contract/manifest.v1.schema.json', 'execution-contract.v2.json', 'execution-contract.test.mjs', 'engine-adapters.mjs', 'engine-adapters.test.mjs'];
  return { schema: 'shieldkit-labs/p2/gate-b/cohort-execution-v2/manifest/v1', manifestId: 'manifest:cohort-execution-v2', status: 'frozen-unexecuted', evidenceClassification: 'contract-only-not-execution-evidence', executionAllowed: false, metricsAllowed: false, ranking: null, selection: null, executionGate: { status: 'closed-contract-only', permittedEpochId: 'execution-epoch:gate-b-v2', permittedAttemptIndex: 0, permittedRetries: 0, runnerBinding: null, runnerBindingRequired: true }, contractDigest: contract.contentDigest, coverage: { packageRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2', symlinksForbidden: true, unmanifestedPayloads: [], listedPayloadCount: 14, selfManifestExcluded: true }, files: paths.map(p => { const f = path.join(packageDir, p); return { path: `research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2/${p}`, byteLength: fs.statSync(f).size, rawSha256: fileSha(f) }; }) };
}

function validateManifest(manifest = readJson(path.join(packageDir, 'MANIFEST.json'))) {
  const schema = readJson(path.join(here, 'manifest.v1.schema.json')); const ajv = new Ajv({ allErrors: true, strict: true }); const validator = ajv.compile(schema); const ok = validator(manifest); assert(ok, ajv.errorsText(validator.errors));
  const contract = readJson(path.join(packageDir, 'execution-contract.v2.json')); assert(manifest.contractDigest.value === contract.contentDigest.value, 'manifest contract digest mismatch');
  const listed = new Set(manifest.files.map(f => f.path)); const found = [];
  function walk(dir) { for (const entry of fs.readdirSync(dir, { withFileTypes: true })) { const file = path.join(dir, entry.name); if (entry.isSymbolicLink()) throw new Error(`manifest symlink forbidden: ${file}`); if (entry.isDirectory()) walk(file); else if (relative(file) !== relative(path.join(packageDir, 'MANIFEST.json'))) found.push(relative(file)); } }
  walk(packageDir); assert(found.sort().join('|') === [...listed].sort().join('|'), 'manifest has unlisted or omitted package payload');
  for (const f of manifest.files) { const file = path.resolve(workspaceDir, f.path); assert(fs.existsSync(file), `manifest file missing: ${f.path}`); assert(fs.statSync(file).size === f.byteLength, `manifest byte length mismatch: ${f.path}`); assert(fileSha(file) === f.rawSha256, `manifest raw hash mismatch: ${f.path}`); }
  return { status: 'PASS', files: manifest.files.length };
}

function writeArtifacts() { const contract = buildContract(); fs.writeFileSync(path.join(packageDir, 'execution-contract.v2.json'), `${JSON.stringify(contract, null, 2)}\n`); const manifest = buildManifest(contract); fs.writeFileSync(path.join(packageDir, 'MANIFEST.json'), `${JSON.stringify(manifest, null, 2)}\n`); return { contract, manifest }; }

if (process.argv.includes('--write')) { const { contract } = writeArtifacts(); console.log(JSON.stringify({ status: 'PASS', mode: 'write', contractDigest: contract.contentDigest.value, totalObligations: 18928, preflightObligations: 496, executableObligations: 18432 }, null, 2)); }
else if (process.argv.includes('--check')) console.log(JSON.stringify({ ...validateContract(), ...validateManifest() }, null, 2));

export { buildContract, buildManifest, validateContract, validateManifest, validateInvocation, validateRawInvocationSemantics, validateNormalizedRowSemantics, validateRawRowSemantics, validateCrossSummarySemantics, validateRawArtifactSemantics, validateNormalizedArtifactSemantics, validateEvidenceManifest, validateEvidenceRootSemantics, canonicalize, digestRecord, ROOT_DOMAIN };
