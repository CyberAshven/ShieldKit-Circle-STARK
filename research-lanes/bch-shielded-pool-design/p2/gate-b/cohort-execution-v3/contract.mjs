import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { validateRetry } from '../cohort-retry-v1/validator.mjs';

export const CANONICALIZATION = 'recursive-lexicographic-object-key-sort-arrays-preserve-order-json-utf8-lf-v1';
export const FRAME = 'utf8(domain)||0x00||canonical-json-utf8';
export const ROOT_DOMAIN = 'shieldkit-labs/p2/gate-b/execution-contract/v3/root';
export const ENGINE_ORDER = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);
export const METRICS = Object.freeze(['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom']);
export const PACKAGE_REL = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v3';
export const EVIDENCE_DOMAINS = Object.freeze({
  rawArtifact: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/raw/<engineId>/batch/<batchOrdinal>', rawRow: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/raw/<engineId>/batch/<batchOrdinal>/row/<workItemId>', rawObservation: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/raw/<engineId>/batch/<batchOrdinal>/observation/<workItemId>',
  normalizedArtifact: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/normalized/<engineId>/batch/<batchOrdinal>', normalizedRow: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/normalized/<engineId>/batch/<batchOrdinal>/row/<workItemId>', metricCell: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/normalized/<engineId>/batch/<batchOrdinal>/metric/<workItemId>/<metricId>', metricValue: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/metric-value/<metricId>',
  summary: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/summary', summaryFixture: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/summary/fixture/<fixtureKey>', summaryMetric: 'shieldkit-labs/p2/gate-b/execution-evidence/v3/summary/metric/<fixtureKey>/<metricId>',
});

const here = path.dirname(new URL(import.meta.url).pathname);
const workspace = path.resolve(here, '../../../../..');
const freezeRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-freeze-v2';
const v2Rel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-v2';
const retryRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-retry-v1';
const accountingRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-attempt-accounting-v1';
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const assert = (condition, message) => { if (!condition) throw new Error(`cohort-execution-v3: ${message}`); };
const byteSort = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b));

export const canonicalize = value => Array.isArray(value)
  ? value.map(canonicalize)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort(byteSort).map(key => [key, canonicalize(value[key])]))
    : value;
export const canonicalBytes = value => Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
export const digestRecord = (value, domain) => ({ algorithm: 'sha256', canonicalization: CANONICALIZATION, domain, frame: FRAME, value: sha(Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), canonicalBytes(value)])) });
/** A shallow omission is sufficient for framed object digests and avoids cloning 70,980-cell artifacts. */
export const omit = (value, field = 'contentDigest') => {
  const { [field]: _omitted, ...rest } = value;
  return rest;
};
export const repoPath = file => path.relative(workspace, file).split(path.sep).join('/');
const abs = rel => path.resolve(workspace, rel);
const readJson = rel => JSON.parse(fs.readFileSync(abs(rel), 'utf8'));
const rawSha = rel => sha(fs.readFileSync(abs(rel)));
const bytes = rel => fs.readFileSync(abs(rel));

function componentFile(rel) {
  assert(typeof rel === 'string' && rel.length > 0 && !path.isAbsolute(rel) && !rel.includes('\\') && !rel.split('/').includes('..'), `unsafe path ${rel}`);
  const base = fs.realpathSync(workspace);
  let cursor = base;
  for (const part of rel.split('/')) {
    cursor = path.join(cursor, part);
    const st = fs.lstatSync(cursor);
    assert(!st.isSymbolicLink(), `symlink component ${rel}`);
  }
  const real = fs.realpathSync(cursor);
  assert(real.startsWith(`${base}${path.sep}`), `path escapes workspace ${rel}`);
  const final = fs.statSync(real); assert(final.isFile() && (!Number.isInteger(final.nlink) || final.nlink === 1), `not singly-linked regular file ${rel}`);
  return real;
}

function contentDigestOf(value) {
  return value?.contentDigest?.value ?? value?.contractDigest?.value ?? null;
}
function verifyEmbeddedContentDigest(value, rel) {
  const digest = value?.contentDigest;
  if (digest === undefined) return null;
  assert(digest?.algorithm === 'sha256' && digest.canonicalization === CANONICALIZATION && digest.frame === FRAME && typeof digest.domain === 'string' && /^[0-9a-f]{64}$/u.test(digest.value), `content digest metadata ${rel}`);
  assert(digest.value === digestRecord(omit(value), digest.domain).value, `content digest bytes ${rel}`);
  return digest;
}
function binding(rel, { schema = null, domain = null, artifactId = null } = {}) {
  componentFile(rel);
  const raw = bytes(rel);
  const value = rel.endsWith('.json') ? JSON.parse(raw) : null;
  const embedded = verifyEmbeddedContentDigest(value, rel);
  const content = embedded?.value ?? contentDigestOf(value);
  if (schema !== null) assert(value?.schema === schema, `schema drift ${rel}`);
  if (domain !== null) assert(value?.contentDigest?.domain === domain, `content domain drift ${rel}`);
  return {
    ...(artifactId === null ? {} : { artifactId }),
    path: rel,
    rawSha256: sha(raw),
    byteLength: raw.length,
    ...(content === null ? {} : { contentDigest: embedded }),
  };
}
function exactBinding(actual, expected, label) {
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${label} binding drift`);
}

const externalBindings = () => {
  /* The v3 contract narrows the retry wrapper only after its sealed package
   * envelope and immutable v2 joins have been validated. */
  validateRetry();
  const engineSchema = `${freezeRel}/engine.v2.schema.json`;
  const engines = ENGINE_ORDER.map(id => binding(`${freezeRel}/engines/${id.slice(7)}.v2.json`, { schema: 'shieldkit-labs/p2/gate-b/cohort-freeze-v2/engine-artifact/v2', artifactId: `engine-record:${id}` }));
  return {
    sourceSet: binding('research-lanes/bch-shielded-pool-design/p2/source-set-v1/source-set.v1.json', { artifactId: 'source-set:mechanical-bch-script-v1' }),
    epoch: binding(`${freezeRel}/execution-epoch.v2.json`, { artifactId: 'execution-epoch:gate-b-v2', schema: 'shieldkit-labs/p2/gate-b/execution-epoch/v2' }),
    campaign: binding(`${freezeRel}/campaign.v2.json`, { artifactId: 'campaign:bch-shielded-pool-design-gate-b-v2' }),
    corpus: binding(`${freezeRel}/canonical-corpus.v2.json`, { artifactId: 'corpus:canonical-gate-b-v2' }),
    fixtureRoster: binding(`${freezeRel}/fixture-roster.v2.json`, { artifactId: 'fixture-roster:gate-b-v2' }),
    workItemRoster: binding(`${freezeRel}/work-item-roster.v2.json`, { artifactId: 'work-item-roster:gate-b-v2' }),
    engineSchema: binding(engineSchema, { artifactId: 'schema:cohort-freeze-v2:engine' }),
    engines,
    v2Contract: binding(`${v2Rel}/execution-contract.v2.json`, { artifactId: 'execution-contract:gate-b-v2', schema: 'shieldkit-labs/p2/gate-b/cohort-execution/v2', domain: 'shieldkit-labs/p2/gate-b/execution-contract/v2/root' }),
    retry: binding(`${retryRel}/attempt-001.retry-wrapper.v1.json`, { artifactId: 'retry-wrapper:gate-b-v2:attempt-001' }),
    accountingRoot: binding(`${accountingRel}/attempt-accounting-root.v1.json`, { artifactId: 'attempt-accounting:attempt-000' }),
    accountingAttemptManifest: binding(`${accountingRel}/attempt-manifest.v1.json`, { artifactId: 'attempt-accounting-manifest:attempt-000' }),
    accountingPackageManifest: binding(`${accountingRel}/MANIFEST.json`, { artifactId: 'accounting-package-manifest' }),
    accountingChecksums: binding(`${accountingRel}/SHA256SUMS`, { artifactId: 'accounting-package-checksums' }),
  };
};

function authoritySurface() {
  const fixtureRoster = readJson(`${freezeRel}/fixture-roster.v2.json`);
  const workItemRoster = readJson(`${freezeRel}/work-item-roster.v2.json`);
  const corpus = readJson(`${freezeRel}/canonical-corpus.v2.json`);
  const cases = new Map(corpus.constructions.flatMap(construction => construction.cases).map(entry => [entry.caseKey, entry]));
  assert(fixtureRoster.records.length === 4732, 'fixture roster cardinality');
  assert(workItemRoster.workItems.length === 18928, 'work roster cardinality');
  const byEngine = new Map(ENGINE_ORDER.map(engineId => [engineId, workItemRoster.workItems.filter(row => row.engineId === engineId)]));
  for (const engineId of ENGINE_ORDER) {
    const rows = byEngine.get(engineId);
    assert(rows.length === 4732, `${engineId} work cardinality`);
    for (let ordinal = 0; ordinal < rows.length; ordinal += 1) {
      const row = rows[ordinal]; const fixture = fixtureRoster.records[ordinal];
      assert(row.fixtureKey === fixture.fixtureKey, `${engineId} work/fixture order ${ordinal}`);
      assert(cases.has(fixture.epochIdentity.caseKey), `missing canonical case ${fixture.fixtureKey}`);
    }
  }
  const preflight = fixtureRoster.records.filter(record => Boolean(record.preflightLimitViolation?.scriptSig || record.preflightLimitViolation?.redeem));
  assert(preflight.length === 124, 'preflight fixture cardinality');
  return { fixtureRoster, workItemRoster, cases, byEngine, preflight };
}

function schedule(authority) {
  const endpointRows = [
    ['engine:native', 0, 'primary', 'module-ndjson', 4608],
    ['engine:libauth', 1, 'primary', 'module-ndjson', 4608],
    ['engine:bchn', 2, 'primary', 'external-process', 4608],
    ['engine:leanbch', 3, 'primary', 'external-process', 4608],
    ['engine:leanbch', 3, 'secondary', 'external-process', 4608],
  ].map(([engineId, engineOrdinal, endpointRole, endpointKind, expectedRowCount], endpointOrdinal) => ({ endpointOrdinal, engineId, engineOrdinal, endpointRole, endpointKind, expectedRowCount }));
  return {
    engineOrder: ENGINE_ORDER,
    endpointOrder: endpointRows,
    executionOrdering: 'native-then-libauth-then-bchn-then-lean-primary-then-lean-secondary',
    maxConcurrency: 1,
    warmups: 0,
    automaticRetries: false,
    timingMetrics: false,
    resultDependentScheduling: false,
    perExternalEndpointCombinedOutputCapBytes: 134217728,
    leanSharedAggregateDeadlineMilliseconds: 600000,
    terminationGraceMilliseconds: 5000,
    componentAndScriptEngineOnly: true,
    bchnTransactionChecks: 'unsupported-not-an-agreement-cell',
    batchWorkItemOrderDigests: ENGINE_ORDER.map(engineId => digestRecord(authority.byEngine.get(engineId).map(row => row.workItemId), `shieldkit-labs/p2/gate-b/execution-contract/v3/schedule/${engineId}`)),
  };
}

function localBindings() {
  return {
    implementation: ['contract.mjs', 'lean-aggregate.mjs', 'fixtures.mjs', 'adapters.mjs', 'generate.mjs'].map(name => binding(`${PACKAGE_REL}/${name}`, { artifactId: `implementation:${name}` })),
    schemas: ['execution-contract.v3.schema.json', 'evidence-shape.v3.schema.json', 'manifest.v1.schema.json'].map(name => binding(`${PACKAGE_REL}/${name}`, { artifactId: `schema:${name}` })),
  };
}

/* These schemas are consumed by the executor-side reader but are frozen as
 * contract authority. They contain no executor implementation bytes. */
function artifactSchemas() {
  const base = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3';
  return ['raw-engine-observation.v3.schema.json', 'normalized-engine-result.v3.schema.json', 'cross-engine-summary.v3.schema.json', 'evidence-manifest.v3.schema.json', 'evidence-root.v3.schema.json', 'execution-claim.v3.schema.json']
    .map(name => binding(`${base}/${name}`, { artifactId: `evidence-schema:${name}` }));
}

export function buildContract() {
  const authority = authoritySurface();
  const contract = {
    schema: 'shieldkit-labs/p2/gate-b/cohort-execution/v3',
    contractId: 'execution-contract:gate-b-v3:attempt-001',
    status: 'frozen-unexecuted',
    evidenceClassification: 'contract-only-not-execution-evidence',
    executionAllowed: false,
    metricsAllowed: false,
    ranking: null,
    selection: null,
    execution: null,
    result: null,
    metric: null,
    inheritedEpoch: { epochId: 'execution-epoch:gate-b-v2', priorAttemptIndex: 0, nextAttemptIndex: 1, sourceEpochMutation: false, engineRecordMutation: false },
    attempt: {
      index: 1,
      retriesWithinAttempt: 0,
      authorization: null,
      authorizationPath: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-authorizations-v3/attempt-001.authorization.v3.json',
      claimPath: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-authorizations-v3/attempt-001.execution-claim.v3.json',
      outputRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-runs-v3/attempt-001',
      successRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-runs-v3/attempt-001/success',
      failureRoot: 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-execution-runs-v3/attempt-001/failure',
      durableFailureOnlyUntilComplete: true,
      partialResultReuse: false,
      atomicContainerCommit: 'scratch-full-validation-then-rename-whole-attempt',
      successPayloadCount: 26,
      successContainerFileCount: 28,
    },
    authorityBindings: externalBindings(),
    sourceBindings: localBindings(),
    artifactSchemas: artifactSchemas(),
    schedule: schedule(authority),
    obligationAccounting: {
      fixtureRowsPerEngine: 4732,
      totalTerminalObligations: 18928,
      preflightFixtureRows: 124,
      preflightTerminalObligations: 496,
      executableFixtureRows: 4608,
      executableTerminalObligations: 18432,
      rawRowsPerEngine: 4732,
      normalizedRowsPerEngine: 4732,
      metricCellsPerEngine: 70980,
      totalMetricCells: 283920,
      crossFixtureRows: 4732,
      crossMetricRows: 70980,
    },
    metricVocabulary: METRICS,
    leanAuthority: {
      primary: 'vmbconf-aggregate-corroboration-only',
      secondary: 'costprobe-per-item-verifyInput-and-six-metrics-only',
      skipPolicy: 'any-eligible-skip-or-malformed-costprobe-line-is-fail-closed-incomplete',
      aggregateListGrammar: 'lean-list-tostring-unquoted-ids-comma-single-space-v1',
    },
    evidenceBoundary: {
      componentAndScriptEngineOnly: true,
      outerTransactionOrTokenChecks: 'out-of-scope-not-agreement',
      bchnTxChecks: 'unsupported',
      fullPoolPolicy: 'not-claimed',
      ranking: null,
      selection: null,
    },
  };
  contract.contentDigest = digestRecord(omit(contract), ROOT_DOMAIN);
  return contract;
}

function schemaCheck(rel, value) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(readJson(`${PACKAGE_REL}/${rel}`));
  assert(validate(value), `${rel}: ${ajv.errorsText(validate.errors)}`);
}
/* validateEvidenceShape is intentionally exported as a complete semantic
 * gate.  It must therefore reject a shape-invalid object even when called
 * without the filesystem container validator.  These are pinned executor
 * schemas, read as static policy rather than canonical evidence payloads. */
function evidenceSchemaCheck(rel, value) {
  const schemaRel = 'research-lanes/bch-shielded-pool-design/p2/gate-b/cohort-executor-v3';
  componentFile(`${schemaRel}/${rel}`);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(readJson(`${schemaRel}/${rel}`));
  assert(validate(value), `${rel}: ${ajv.errorsText(validate.errors)}`);
}
function verifyDigest(record, value, domain, label) {
  assert(record?.algorithm === 'sha256' && record.canonicalization === CANONICALIZATION && record.frame === FRAME && record.domain === domain, `${label} digest metadata`);
  assert(record.value === digestRecord(value, domain).value, `${label} digest value`);
}

export function validateContract(candidate = readJson(`${PACKAGE_REL}/execution-contract.v3.json`)) {
  schemaCheck('execution-contract.v3.schema.json', candidate);
  const expected = buildContract();
  assert(JSON.stringify(canonicalize(candidate)) === JSON.stringify(canonicalize(expected)), 'contract differs from deterministic frozen authority');
  verifyDigest(candidate.contentDigest, omit(candidate), ROOT_DOMAIN, 'contract');
  return Object.freeze({ status: 'PASS', contractDigest: candidate.contentDigest.value, fixtureRowsPerEngine: 4732, obligations: 18928, metricCellsPerEngine: 70980 });
}

export const TERMINAL_STATUSES = Object.freeze(['observed', 'preflight-limit-unsupported', 'process-failure', 'timeout', 'parser-failure', 'engine-unsupported-incomplete', 'not-run-incomplete']);
export const METRIC_STATUSES = Object.freeze(['measured', 'measured-noncomparable', 'derived-common', 'derived-engine', 'not-reached', 'not-exposed', 'not-applicable', 'preflight-limit-unsupported']);
export const FAILURE_STAGES = Object.freeze(['accept', 'coefficient-range-check-before-arithmetic', 'unused-high-bit-check-before-numeric-decode', 'exact-extension-element-length-check-before-limb-decode', 'relation-check', 'inverse-relation-check', 'preflight-limit', 'process', 'timeout', 'parser', 'not-run-incomplete', 'outer-transaction-or-token']);

export const instantiateEvidenceDomain = (template, values) => template.replace(/<([A-Za-z]+)>/gu, (_, key) => {
  assert(Object.hasOwn(values, key), `missing digest domain ${key}`);
  return values[key];
});
export const evidenceAuthorityRows = () => authoritySurface();
export const metricValueDigest = metric => digestRecord({ metricId: metric.metricId, value: metric.value }, instantiateEvidenceDomain(EVIDENCE_DOMAINS.metricValue, { metricId: metric.metricId })).value;
const same = (left, right) => JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
const preflightFixture = fixture => Boolean(fixture.preflightLimitViolation?.scriptSig || fixture.preflightLimitViolation?.redeem);
const digest = (record, value, domainValue, label) => verifyDigest(record, value, domainValue, label);
const exact = (condition, label) => assert(condition, label);
const observedMetricStatuses = new Set(['measured', 'derived-common', 'derived-engine']);
export const deriveFixtureAgreement = ({ preflight, cells }) => {
  const comparable = cells.filter(cell => cell.comparable).map(cell => cell.observedVerdict);
  const hasIncomplete = cells.some(cell => ['not-run-incomplete', 'process-failure', 'timeout', 'parser-failure'].includes(cell.terminalStatus));
  const hasUnsupported = cells.some(cell => cell.terminalStatus === 'engine-unsupported-incomplete');
  return preflight ? 'preflight-unsupported'
    : hasIncomplete ? 'incomplete'
      : hasUnsupported || comparable.length !== ENGINE_ORDER.length ? 'not-comparable'
        : new Set(comparable).size === 1 ? 'agree' : 'disagree';
};
export const deriveMetricAgreement = ({ preflight, cells, terminalStatuses }) => {
  const comparable = cells.filter(cell => cell.comparable);
  const values = comparable.map(cell => cell.valueDigest);
  const hasIncomplete = cells.some(cell => cell.status === 'not-reached')
    || terminalStatuses.some(status => ['process-failure', 'timeout', 'parser-failure', 'not-run-incomplete'].includes(status));
  const hasUnsupported = cells.some(cell => cell.status === 'not-applicable')
    || terminalStatuses.some(status => status === 'engine-unsupported-incomplete');
  return preflight ? 'preflight-unsupported'
    : hasIncomplete ? 'incomplete'
      : hasUnsupported || comparable.length !== ENGINE_ORDER.length ? 'not-comparable'
        : new Set(values).size === 1 ? 'agree' : 'disagree';
};
export function assertObservedTerminalProjection(rawPayload, normalizedRow, label = 'raw/normalized terminal projection') {
  exact(normalizedRow.observed?.verdict === rawPayload?.verdict
    && normalizedRow.observed?.failureStage === rawPayload?.failureStage
    && normalizedRow.terminalStatus === rawPayload?.terminalStatus, label);
}
const engineMetric = (engineId, metricId, payload) => {
  const values = payload?.metrics;
  if (!values || typeof values !== 'object' || Array.isArray(values)) return undefined;
  const fields = {
    'engine:native': {},
    'engine:libauth': { vmCost: ['vmCost', 'operationCost'], opCost: ['opCost', 'operationCost'], stackMax: ['stackMax'], elementMax: ['elementMax'], opcodeHistogram: ['opcodeHistogram'], mulByteProduct: ['mulByteProduct'], divByteProduct: ['divByteProduct'], modByteProduct: ['modByteProduct'], resultPushBytes: ['resultPushBytes'], limits: ['limits'], headroom: ['headroom'] },
    'engine:bchn': { vmCost: ['operationCost'], opCost: ['operationCost'], limits: ['maximumOperationCost'], headroom: ['maximumOperationCost'] },
    'engine:leanbch': { vmCost: ['arithmeticCost'], opCost: ['nativeConsensus64OperationCost'], opcodeHistogram: ['opcodeHistogram'], mulByteProduct: ['mulByteProduct'], divByteProduct: ['divByteProduct'], modByteProduct: ['modByteProduct'], resultPushBytes: ['resultPushBytes'], stackMax: ['stackMax'], elementMax: ['elementMax'], limits: ['limits'], headroom: ['headroom'] },
  }[engineId];
  const key = (fields?.[metricId] ?? []).find(name => Object.hasOwn(values, name));
  if (!key) return undefined;
  if (engineId === 'engine:bchn' && metricId === 'limits') return { operationCost: values.maximumOperationCost, hashDigestIterations: values.maximumHashDigestIterations, signatureChecks: values.maximumSignatureCheckCount };
  if (engineId === 'engine:bchn' && metricId === 'headroom') return { operationCost: values.maximumOperationCost - values.operationCost, hashDigestIterations: values.maximumHashDigestIterations - values.hashDigestIterations, signatureChecks: values.maximumSignatureCheckCount - values.signatureCheckCount };
  return values[key];
};
const fixtureMetric = (fixture, metricId) => ({
  lockingBytes: fixture.byteBindings.sourceLockingBytecode.byteLength,
  unlockingBytes: fixture.byteBindings.unlockingBytecode.byteLength,
  sourceBytes: fixture.byteBindings.sourceOutputs.byteLength,
})[metricId];

function validateMetric(metric, { engineId, raw, rawRow, normalizedRow, fixture, ordinal, metricOrdinal }) {
  exact(metric.metricId === METRICS[metricOrdinal] && METRIC_STATUSES.includes(metric.status), `metric identity/status ${engineId}/${ordinal}/${metricOrdinal}`);
  digest(metric.contentDigest, omit(metric), instantiateEvidenceDomain(EVIDENCE_DOMAINS.metricCell, { engineId, batchOrdinal: raw.engineBatchOrdinal, workItemId: rawRow.workItemId, metricId: metric.metricId }), `metric digest ${engineId}/${ordinal}/${metric.metricId}`);
  const eligible = !preflightFixture(fixture) && normalizedRow.disposition === 'observed' && normalizedRow.terminalStatus === 'observed' && observedMetricStatuses.has(metric.status);
  exact(metric.comparable === eligible, `metric comparable projection ${engineId}/${ordinal}/${metric.metricId}`);
  if (['preflight-limit-unsupported', 'not-reached', 'not-exposed', 'not-applicable'].includes(metric.status)) {
    exact(metric.value === null && metric.provenance === null && typeof metric.reason === 'string' && metric.reason.length > 0, `unmeasured metric shape ${engineId}/${ordinal}/${metric.metricId}`);
    return;
  }
  exact(metric.value !== null && metric.provenance?.sourceArtifactDigest && metric.reason === null, `measured metric shape ${engineId}/${ordinal}/${metric.metricId}`);
  if (metric.metricId === 'verdict') {
    exact(metric.value === normalizedRow.observed.verdict && metric.provenance.sourceArtifactDigest === raw.contentDigest.value && metric.provenance.method === 'raw-observation-verdict-v3', `verdict projection ${engineId}/${ordinal}`);
  } else if (['lockingBytes', 'unlockingBytes', 'sourceBytes'].includes(metric.metricId)) {
    exact(metric.status === 'derived-common' && metric.provenance.sourceArtifactDigest === fixture.contentDigest.value && metric.provenance.method === 'frozen-fixture-byte-binding-v1' && same(metric.value, fixtureMetric(fixture, metric.metricId)), `fixture metric projection ${engineId}/${ordinal}/${metric.metricId}`);
  } else {
    const value = engineMetric(engineId, metric.metricId, rawRow.rawObservation?.payload);
    exact(metric.provenance.sourceArtifactDigest === raw.contentDigest.value && metric.provenance.method === 'raw-engine-metric-v3' && value !== undefined && same(metric.value, value), `raw metric projection ${engineId}/${ordinal}/${metric.metricId}`);
  }
}

function validateRowPair({ raw, normalized, rawRow, normalizedRow, fixture, work, engineId, ordinal }) {
  const expected = fixture.expected ?? fixture.caseEntry?.expected;
  for (const [label, row] of [['raw', rawRow], ['normalized', normalizedRow]]) exact(row?.workItemOrdinal === ordinal && row.workItemId === work.workItemId && row.fixtureKey === fixture.fixtureKey && row.terminalCellId === work.terminalCellId && row.fixtureRecordDigest === fixture.contentDigest.value, `${label} authority identity ${engineId}/${ordinal}`);
  exact(rawRow.disposition === normalizedRow.disposition, `raw/normalized disposition ${engineId}/${ordinal}`);
  digest(rawRow.rawRowDigest, omit(rawRow, 'rawRowDigest'), instantiateEvidenceDomain(EVIDENCE_DOMAINS.rawRow, { engineId, batchOrdinal: raw.engineBatchOrdinal, workItemId: rawRow.workItemId }), `raw row ${engineId}/${ordinal}`);
  if (rawRow.rawObservation !== null) digest(rawRow.rawObservation.rawObservationDigest, omit(rawRow.rawObservation, 'rawObservationDigest'), instantiateEvidenceDomain(EVIDENCE_DOMAINS.rawObservation, { engineId, batchOrdinal: raw.engineBatchOrdinal, workItemId: rawRow.workItemId }), `raw observation ${engineId}/${ordinal}`);
  digest(normalizedRow.contentDigest, omit(normalizedRow), instantiateEvidenceDomain(EVIDENCE_DOMAINS.normalizedRow, { engineId, batchOrdinal: raw.engineBatchOrdinal, workItemId: rawRow.workItemId }), `normalized row ${engineId}/${ordinal}`);
  exact(normalizedRow.expected?.verdict === expected.verdict && normalizedRow.expected?.stage === expected.stage, `corpus expected ${engineId}/${ordinal}`);
  exact(Array.isArray(normalizedRow.metrics) && normalizedRow.metrics.length === METRICS.length, `metric cardinality ${engineId}/${ordinal}`);
  const isPreflight = preflightFixture(fixture);
  if (isPreflight) {
    exact(rawRow.disposition === 'preflight-limit-unsupported' && rawRow.rawObservation === null && rawRow.preflightBinding?.kind === 'preflight-limit' && rawRow.preflightBinding.scriptSig === Boolean(fixture.preflightLimitViolation?.scriptSig) && rawRow.preflightBinding.redeem === Boolean(fixture.preflightLimitViolation?.redeem), `preflight raw ${engineId}/${ordinal}`);
    exact(normalizedRow.terminalStatus === 'preflight-limit-unsupported' && normalizedRow.rawObservationDigest === null && normalizedRow.observed?.verdict === null && normalizedRow.observed?.failureStage === 'preflight-limit', `preflight normalized ${engineId}/${ordinal}`);
    exact(normalizedRow.metrics.every(metric => metric.status === 'preflight-limit-unsupported'), `preflight metrics ${engineId}/${ordinal}`);
  } else if (rawRow.disposition === 'engine-unsupported-incomplete') {
    exact(engineId === 'engine:leanbch' && ['incomplete', 'failed'].includes(raw.status) && rawRow.rawObservation && rawRow.unsupportedBinding?.reason === 'lean-costprobe-skip' && rawRow.unsupportedBinding?.agreementEligible === false, `Lean unsupported raw ${ordinal}`);
    exact(normalizedRow.terminalStatus === 'engine-unsupported-incomplete' && normalizedRow.observed?.verdict === null && normalizedRow.observed?.failureStage === 'process' && same(normalizedRow.rawObservationDigest, rawRow.rawRowDigest) && normalizedRow.unsupportedBinding?.reason === 'lean-costprobe-skip' && normalizedRow.unsupportedBinding?.agreementEligible === false && normalizedRow.metrics.every(metric => metric.status === 'not-applicable'), `Lean unsupported normalized ${ordinal}`);
  } else if (rawRow.disposition === 'not-run-incomplete') {
    exact(['incomplete', 'failed', 'not-started'].includes(raw.status) && rawRow.rawObservation === null && rawRow.notRunBinding?.reason === 'prior-engine-batch-failure' && rawRow.notRunBinding?.agreementEligible === false, `not-run raw ${engineId}/${ordinal}`);
    exact(normalizedRow.terminalStatus === 'not-run-incomplete' && normalizedRow.observed?.verdict === null && normalizedRow.observed?.failureStage === 'not-run-incomplete' && normalizedRow.rawObservationDigest === null && normalizedRow.notRunBinding?.reason === 'prior-engine-batch-failure' && normalizedRow.metrics.every(metric => metric.status === 'not-reached'), `not-run normalized ${engineId}/${ordinal}`);
  } else {
    exact(rawRow.disposition === 'observed' && rawRow.rawObservation?.kind === 'structured' && rawRow.preflightBinding === null && rawRow.unsupportedBinding === null && rawRow.notRunBinding === null, `observed raw ${engineId}/${ordinal}`);
    exact(['observed', 'process-failure', 'timeout', 'parser-failure'].includes(normalizedRow.terminalStatus) && same(normalizedRow.rawObservationDigest, rawRow.rawRowDigest) && normalizedRow.unsupportedBinding === null && normalizedRow.notRunBinding === null, `observed normalized ${engineId}/${ordinal}`);
    /* A raw row is the sole observed-result authority.  In particular, do
     * not let a re-digested raw payload be relabelled as a normalized success
     * (or vice versa) merely because its verdict and stage still agree. */
    assertObservedTerminalProjection(rawRow.rawObservation.payload, normalizedRow, `raw observation terminal projection ${engineId}/${ordinal}`);
  }
  for (const [metricOrdinal, metric] of normalizedRow.metrics.entries()) validateMetric(metric, { engineId, raw, rawRow, normalizedRow, fixture, ordinal, metricOrdinal });
}

function engineMajorGrammar(statuses) {
  let current = false; let later = false;
  for (const status of statuses) {
    if (status === 'complete') exact(!current && !later, 'engine-major complete after interruption');
    else if (status === 'incomplete' || status === 'failed') { exact(!current && !later, 'engine-major multiple interruption'); current = true; }
    else if (status === 'not-started') later = true;
    else exact(false, `invalid engine status ${status}`);
  }
}

/**
 * Artifact status and endpoint lifecycle are deliberately distinct.  In
 * particular, a complete Lean vmbconf+CostProbe pair may still yield an
 * incomplete artifact when CostProbe reports a valid frozen SKIP.  Conversely
 * a secondary endpoint failure is represented after a complete primary.
 */
export function assertArtifactLifecycle(raw, label = 'artifact lifecycle') {
  const endpoints = raw?.lifecycle?.endpoints;
  exact(Array.isArray(endpoints) && endpoints.length > 0, `${label} endpoint array`);
  const states = endpoints.map(endpoint => endpoint.status);
  const allComplete = states.every(state => state === 'complete');
  if (raw.status === 'complete') {
    exact(allComplete, `${label} complete endpoints`);
    return;
  }
  if (raw.engineId === 'engine:leanbch' && raw.status === 'incomplete' && allComplete) return;
  let terminal = false;
  for (const state of states) {
    if (state === 'complete') exact(!terminal, `${label} complete after terminal`);
    else if (state === 'failed' || state === 'incomplete') { exact(!terminal, `${label} multiple terminal endpoints`); terminal = true; }
    else if (state === 'not-started') exact(terminal, `${label} not-started before terminal`);
    else exact(false, `${label} invalid endpoint state`);
  }
  exact(terminal, `${label} incomplete artifact requires endpoint terminal`);
}

/**
 * Full in-memory semantic authority check for v3 raw, normalized, and cross
 * artifacts. It is process-free and does not evaluate a BCH VM.
 */
export function validateEvidenceShape({ rawArtifacts, normalizedArtifacts, crossSummary }) {
  exact(Array.isArray(rawArtifacts) && Array.isArray(normalizedArtifacts), 'evidence artifact arrays');
  for (const raw of rawArtifacts) evidenceSchemaCheck('raw-engine-observation.v3.schema.json', raw);
  for (const normalized of normalizedArtifacts) evidenceSchemaCheck('normalized-engine-result.v3.schema.json', normalized);
  evidenceSchemaCheck('cross-engine-summary.v3.schema.json', crossSummary);
  const authority = authoritySurface();
  exact(Array.isArray(rawArtifacts) && rawArtifacts.length === 4 && Array.isArray(normalizedArtifacts) && normalizedArtifacts.length === 4, 'four raw and normalized artifacts');
  const rawByEngine = new Map(); const normalizedByEngine = new Map();
  for (const [batchOrdinal, engineId] of ENGINE_ORDER.entries()) {
    const raw = rawArtifacts[batchOrdinal]; const normalized = normalizedArtifacts[batchOrdinal]; const rows = authority.byEngine.get(engineId);
    exact(raw?.engineId === engineId && raw.engineBatchOrdinal === batchOrdinal && raw.shardIndex === 0 && raw.shardCount === 1 && raw.rows?.length === 4732, `raw identity/cardinality ${engineId}`);
    exact(normalized?.engineId === engineId && normalized.engineBatchOrdinal === batchOrdinal && normalized.shardIndex === 0 && normalized.shardCount === 1 && normalized.rows?.length === 4732 && normalized.metricCellCount === 70980 && normalized.status === raw.status && normalized.rawArtifactDigest === raw.contentDigest.value, `normalized identity/cardinality ${engineId}`);
    const order = rows.map(row => row.workItemId); const scheduleDomain = `shieldkit-labs/p2/gate-b/execution-contract/v3/schedule/${engineId}`;
    digest(raw.workItemOrderDigest, order, scheduleDomain, `raw schedule ${engineId}`); digest(normalized.workItemOrderDigest, order, scheduleDomain, `normalized schedule ${engineId}`);
    digest(raw.contentDigest, omit(raw), instantiateEvidenceDomain(EVIDENCE_DOMAINS.rawArtifact, { engineId, batchOrdinal }), `raw artifact ${engineId}`);
    digest(normalized.contentDigest, omit(normalized), instantiateEvidenceDomain(EVIDENCE_DOMAINS.normalizedArtifact, { engineId, batchOrdinal }), `normalized artifact ${engineId}`);
    assertArtifactLifecycle(raw, `raw ${engineId}`);
    let seenNotRun = false;
    for (let ordinal = 0; ordinal < 4732; ordinal += 1) {
      const fixture = authority.fixtureRoster.records[ordinal]; const work = rows[ordinal]; const rawRow = raw.rows[ordinal]; const normalizedRow = normalized.rows[ordinal];
      if (rawRow.disposition === 'not-run-incomplete') seenNotRun = true;
      else exact(!seenNotRun, `not-run must be a row suffix ${engineId}/${ordinal}`);
      validateRowPair({ raw, normalized, rawRow, normalizedRow, fixture: { ...fixture, expected: authority.cases.get(fixture.epochIdentity.caseKey).expected }, work, engineId, ordinal });
    }
    rawByEngine.set(engineId, raw); normalizedByEngine.set(engineId, normalized);
  }
  engineMajorGrammar(rawArtifacts.map(artifact => artifact.status));
  exact(crossSummary?.schema === 'shieldkit-labs/p2/gate-b/cohort-executor-v3/cross-engine-summary/v3' && crossSummary.fixtureRows?.length === 4732 && crossSummary.metricAgreementRows?.length === 70980, 'cross cardinality/schema');
  exact(JSON.stringify(crossSummary.rawArtifactDigests) === JSON.stringify(rawArtifacts.map(artifact => artifact.contentDigest.value)) && JSON.stringify(crossSummary.normalizedArtifactDigests) === JSON.stringify(normalizedArtifacts.map(artifact => artifact.contentDigest.value)), 'cross artifact digest arrays');
  digest(crossSummary.contentDigest, omit(crossSummary), EVIDENCE_DOMAINS.summary, 'cross summary');
  const fixtureStates = []; const metricStates = [];
  for (let fixtureOrdinal = 0; fixtureOrdinal < 4732; fixtureOrdinal += 1) {
    const fixture = authority.fixtureRoster.records[fixtureOrdinal]; const expected = authority.cases.get(fixture.epochIdentity.caseKey).expected; const row = crossSummary.fixtureRows[fixtureOrdinal];
    exact(row?.fixtureKey === fixture.fixtureKey && row.terminalCellId === authority.byEngine.get('engine:native')[fixtureOrdinal].terminalCellId && row.fixtureRecordDigest === fixture.contentDigest.value && row.expectedVerdict === expected.verdict && row.engines?.length === 4, `cross fixture authority ${fixtureOrdinal}`);
    const comparable = [];
    for (const [engineOrdinal, engineId] of ENGINE_ORDER.entries()) {
      const cell = row.engines[engineOrdinal]; const raw = rawByEngine.get(engineId).rows[fixtureOrdinal]; const normalized = normalizedByEngine.get(engineId).rows[fixtureOrdinal]; const eligible = !preflightFixture(fixture) && normalized.disposition === 'observed' && normalized.terminalStatus === 'observed' && normalized.observed.verdict !== null;
      exact(cell.engineId === engineId && cell.workItemId === normalized.workItemId && cell.terminalCellId === normalized.terminalCellId && cell.rawRowDigest === raw.rawRowDigest.value && cell.normalizedRowDigest === normalized.contentDigest.value && cell.terminalStatus === normalized.terminalStatus && cell.observedVerdict === normalized.observed.verdict && cell.comparable === eligible, `cross fixture cell ${fixtureOrdinal}/${engineId}`);
      if (eligible) comparable.push(cell.observedVerdict);
    }
    /* Agreement is a four-engine claim.  A three-engine consensus plus a
     * Lean SKIP is explicitly non-comparable, never agreement. */
    const derived = deriveFixtureAgreement({ preflight: preflightFixture(fixture), cells: row.engines });
    exact(row.agreementStatus === derived, `cross fixture agreement ${fixtureOrdinal}`); digest(row.contentDigest, omit(row), instantiateEvidenceDomain(EVIDENCE_DOMAINS.summaryFixture, { fixtureKey: fixture.fixtureKey }), `cross fixture digest ${fixtureOrdinal}`); fixtureStates.push(derived);
  }
  for (let cellOrdinal = 0; cellOrdinal < 70980; cellOrdinal += 1) {
    const fixtureOrdinal = Math.floor(cellOrdinal / METRICS.length); const metricOrdinal = cellOrdinal % METRICS.length; const fixture = authority.fixtureRoster.records[fixtureOrdinal]; const row = crossSummary.metricAgreementRows[cellOrdinal];
    exact(row?.fixtureKey === fixture.fixtureKey && row.metricOrdinal === metricOrdinal && row.metricId === METRICS[metricOrdinal] && row.cells?.length === 4, `cross metric identity ${cellOrdinal}`);
    const comparable = []; const valueDigests = [];
    for (const [engineOrdinal, engineId] of ENGINE_ORDER.entries()) {
      const raw = rawByEngine.get(engineId).rows[fixtureOrdinal]; const normalized = normalizedByEngine.get(engineId).rows[fixtureOrdinal]; const metric = normalized.metrics[metricOrdinal]; const cell = row.cells[engineOrdinal]; const eligible = !preflightFixture(fixture) && normalized.disposition === 'observed' && normalized.terminalStatus === 'observed' && observedMetricStatuses.has(metric.status);
      const value = eligible ? metricValueDigest(metric) : null;
      exact(cell.engineId === engineId && cell.workItemId === normalized.workItemId && cell.terminalCellId === normalized.terminalCellId && cell.rawRowDigest === raw.rawRowDigest.value && cell.normalizedRowDigest === normalized.contentDigest.value && cell.metricCellDigest === metric.contentDigest.value && cell.status === metric.status && cell.valueDigest === value && cell.comparable === eligible, `cross metric cell ${cellOrdinal}/${engineId}`);
      if (eligible) comparable.push(engineId); valueDigests.push(value);
    }
    exact(JSON.stringify(row.comparableEngineIds) === JSON.stringify(comparable) && JSON.stringify(row.incomparableEngineIds) === JSON.stringify(ENGINE_ORDER.filter(id => !comparable.includes(id))) && JSON.stringify(row.valueDigests) === JSON.stringify(valueDigests), `cross metric projections ${cellOrdinal}`);
    const derived = deriveMetricAgreement({ preflight: preflightFixture(fixture), cells: row.cells, terminalStatuses: ENGINE_ORDER.map(engineId => normalizedByEngine.get(engineId).rows[fixtureOrdinal].terminalStatus) });
    exact(row.agreementStatus === derived, `cross metric agreement ${cellOrdinal}`); digest(row.contentDigest, omit(row), instantiateEvidenceDomain(EVIDENCE_DOMAINS.summaryMetric, { fixtureKey: fixture.fixtureKey, metricId: METRICS[metricOrdinal] }), `cross metric digest ${cellOrdinal}`); metricStates.push(derived);
  }
  const eligibleFixtures = fixtureStates.filter(state => state !== 'preflight-unsupported'); const eligibleMetrics = metricStates.filter(state => state !== 'preflight-unsupported');
  const top = states => states.length === 0 ? 'not-started' : states.includes('incomplete') ? 'incomplete' : states.includes('disagree') ? 'disagreement' : 'complete-eligible-only';
  exact(crossSummary.verdictAgreement === top(eligibleFixtures) && crossSummary.metricCoverageAgreement === top(eligibleMetrics), 'cross top-level agreement');
  const statuses = [...rawArtifacts, ...normalizedArtifacts].map(artifact => artifact.status); const status = statuses.every(value => value === 'not-started') ? 'not-started' : statuses.some(value => value === 'failed') ? 'failed' : statuses.some(value => value === 'incomplete') ? 'incomplete' : 'complete';
  exact(crossSummary.status === status, 'cross status derivation');
  return Object.freeze({ status: 'PASS', rawRows: 18928, normalizedRows: 18928, metricCellsPerEngine: 70980 });
}

function completeClosure(dir, listed) {
  const actual = []; const dirs = [];
  const go = (current, relative = '') => {
    for (const name of fs.readdirSync(current).sort(byteSort)) {
      const file = path.join(current, name); const rel = relative ? `${relative}/${name}` : name; const st = fs.lstatSync(file);
      assert(!st.isSymbolicLink(), `manifest symlink ${rel}`);
      if (st.isDirectory()) { dirs.push(rel); go(file, rel); } else { assert(st.isFile() && (!Number.isInteger(st.nlink) || st.nlink === 1), `manifest nonregular ${rel}`); actual.push(rel); }
    }
  };
  go(dir); actual.sort(byteSort); dirs.sort(byteSort);
  const expected = [...listed].sort(byteSort); assert(JSON.stringify(actual) === JSON.stringify(expected), 'manifest file closure');
  const expectedDirs = new Set(); for (const rel of expected) { const parts = rel.split('/'); for (let i = 1; i < parts.length; i += 1) expectedDirs.add(parts.slice(0, i).join('/')); }
  assert(JSON.stringify(dirs) === JSON.stringify([...expectedDirs].sort(byteSort)), 'manifest directory closure');
}
export function validateManifest() {
  const manifest = readJson(`${PACKAGE_REL}/MANIFEST.json`);
  schemaCheck('manifest.v1.schema.json', manifest);
  verifyDigest(manifest.contentDigest, omit(manifest), 'shieldkit-labs/p2/gate-b/cohort-execution-v3/package-manifest/root', 'manifest');
  const prefix = `${PACKAGE_REL}/`;
  const listed = manifest.files.map(item => item.path);
  assert(manifest.coverage.listedPayloadCount === listed.length && new Set(listed).size === listed.length, 'manifest coverage');
  assert(JSON.stringify(listed) === JSON.stringify([...listed].sort(byteSort)), 'manifest order');
  completeClosure(here, ['MANIFEST.json', 'SHA256SUMS', ...listed.map(item => item.slice(prefix.length))]);
  for (const item of manifest.files) { const body = bytes(item.path); assert(body.length === item.byteLength && sha(body) === item.rawSha256, `manifest bytes ${item.path}`); }
  const sums = Buffer.from([[sha(bytes(`${PACKAGE_REL}/MANIFEST.json`)), `${PACKAGE_REL}/MANIFEST.json`], ...manifest.files.map(item => [item.rawSha256, item.path])].map(row => row.join('  ')).join('\n') + '\n', 'utf8');
  assert(bytes(`${PACKAGE_REL}/SHA256SUMS`).equals(sums), 'checksum envelope');
  return Object.freeze({ status: 'PASS', packageFiles: listed.length });
}

export const contractPaths = Object.freeze({ here, workspace, packageRel: PACKAGE_REL, freezeRel, v2Rel, retryRel, accountingRel });
