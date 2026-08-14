import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

import { arithmeticCaseKey, campaignCountsForDegree, canonicalize, contentDigestFor, sha256, trackOrderForDescriptor, validateArithmeticRun } from '../algebra-component/algebra-component-validation.mjs';

const load = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const schema = load('./equal-relation-arithmetic-run.v1.schema.json');
const engineSchema = load('./equal-relation-arithmetic-engine-result.v1.schema.json');
const metricSchema = load('./equal-relation-arithmetic-metric-report.v1.schema.json');
const summarySchema = load('./equal-relation-arithmetic-cross-engine-summary.v1.schema.json');
const campaign = load('./equal-relation-arithmetic-campaign.v1.json');
const descriptor = load('../algebra-component/descriptors/m89-d2-x2-plus-1.v1.json');
const corpusBytes = readFileSync(new URL('../reference/m89-corpus.json', import.meta.url));
const corpus = JSON.parse(corpusBytes);
const profileBytes = readFileSync(new URL('../../profiles/bch-current-2026-08-08.json', import.meta.url));
const engineSchemaBytes = readFileSync(new URL('./equal-relation-arithmetic-engine-result.v1.schema.json', import.meta.url));
const metricSchemaBytes = readFileSync(new URL('./equal-relation-arithmetic-metric-report.v1.schema.json', import.meta.url));
const summarySchemaBytes = readFileSync(new URL('./equal-relation-arithmetic-cross-engine-summary.v1.schema.json', import.meta.url));
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validateSchema = ajv.compile(schema);
const validateEngineSchema = ajv.compile(engineSchema);
const validateMetricSchema = ajv.compile(metricSchema);
const validateSummarySchema = ajv.compile(summarySchema);
const metrics = ['verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes', 'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct', 'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits', 'headroom'];
const engines = ['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch'];
const tempRoot = mkdtempSync(join(tmpdir(), 'shieldkit-gate-b0-run-test-'));
after(() => rmSync(tempRoot, { recursive: true, force: true }));

const put = (relativePath, bytes) => {
  const path = join(tempRoot, relativePath);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, bytes);
  return sha256(bytes);
};
const digestText = (text) => sha256(Buffer.from(text));
const fixture = (entry) => {
  const caseKey = arithmeticCaseKey(entry);
  return {
    caseKey,
    fixtureDigest: digestText(`fixture:${caseKey}`),
    transactionDigest: digestText(`transaction:${caseKey}`),
    sourceOutputsDigest: digestText(`source:${caseKey}`),
  };
};

const descriptorBytes = Buffer.from(`${JSON.stringify(descriptor)}\n`);
const campaignBytes = Buffer.from(`${JSON.stringify(campaign)}\n`);
const descriptorFileDigest = put('inputs/descriptor.json', descriptorBytes);
const campaignFileDigest = put('inputs/campaign.json', campaignBytes);
put('profiles/bch-current-2026-08-08.json', profileBytes);
const artifactSchemaBindings = [
  { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', path: 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json', sha256: put('p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json', engineSchemaBytes) },
  { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', path: 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json', sha256: put('p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json', metricSchemaBytes) },
  { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1', path: 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json', sha256: put('p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json', summarySchemaBytes) },
];

const stream = (text) => ({ text, sha256: text === null ? null : sha256(Buffer.from(text, 'utf8')), byteLength: text === null ? 0 : Buffer.byteLength(text, 'utf8') });
const makeEngineArtifact = (engineId, corpusDigest) => ({
  schema: 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1',
  engineId,
  corpusDigest,
  execution: ['engine:bchn', 'engine:leanbch'].includes(engineId)
    ? { status: 'measured', mode: 'external', entrypoint: { kind: 'argv', argv: ['adapter', engineId], modulePath: null }, implementationDigest: digestText(`implementation:${engineId}`), stdin: stream(`${engineId}:stdin\n`), stdout: stream(`${engineId}:stdout\n`), stderr: stream(`${engineId}:stderr\n`), evidenceBoundary: 'gate-b0-primitive-evidence-only' }
    : { status: 'measured', mode: 'in-process', entrypoint: { kind: 'module', argv: null, modulePath: `p2/${engineId.slice(7)}.mjs` }, implementationDigest: digestText(`implementation:${engineId}`), stdin: stream(null), stdout: stream(null), stderr: stream(null), evidenceBoundary: 'gate-b0-primitive-evidence-only' },
  cases: corpus.cases.map((entry) => ({ ...fixture(entry), verdict: entry.expected.verdict, rawObservation: { engineId, observedVerdict: entry.expected.verdict } })),
});

const metricCell = ({ engineId, entry, metricId, rawDigest }) => {
  const wire = fixture(entry);
  const exposed = metricId === 'verdict'
    || engineId === 'engine:libauth'
    || (engineId === 'engine:bchn' && metricId === 'opCost');
  const common = ['lockingBytes', 'unlockingBytes', 'sourceBytes'].includes(metricId);
  const early = engineId === 'engine:leanbch' && entry.expected.verdict === 'reject' && metricId !== 'verdict';
  if (early) return { engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status: 'not-reached', value: null, provenance: null, reason: 'engine did not reach this metric phase for the declared reject' };
  if (exposed) return { engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status: 'measured', value: metricId === 'verdict' ? entry.expected.verdict : `${metricId}:${wire.caseKey}`, provenance: { sourceArtifactDigest: rawDigest, method: 'raw-engine-result' }, reason: null };
  if (common) return { engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status: 'derived-common', value: `${metricId}:${wire.caseKey}`, provenance: { sourceArtifactDigest: wire.fixtureDigest, method: 'shared-byte-fixture' }, reason: null };
  return { engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status: 'not-exposed', value: null, provenance: null, reason: 'this engine does not expose this metric surface' };
};

const makeArtifacts = () => {
  const corpusDigest = put('artifacts/corpus.json', corpusBytes);
  const raw = new Map();
  for (const engineId of engines) raw.set(engineId, put(`artifacts/${engineId.slice(7)}-result.json`, Buffer.from(`${JSON.stringify(makeEngineArtifact(engineId, corpusDigest))}\n`)));
  const cells = engines.flatMap((engineId) => corpus.cases.flatMap((entry) => metrics.map((metricId) => metricCell({ engineId, entry, metricId, rawDigest: raw.get(engineId) }))));
  const metricReport = { schema: 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', corpusDigest, cells };
  const metricReportDigest = put('artifacts/metric-report.json', Buffer.from(`${JSON.stringify(metricReport)}\n`));
  const cellMap = new Map(cells.map((cell) => [`${cell.engineId}|${cell.caseKey}|${cell.metricId}`, cell]));
  const summary = {
    schema: 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1',
    corpusDigest,
    verdictAgreement: true,
    metricCoverageAgreement: true,
    cases: corpus.cases.map((entry) => ({ ...fixture(entry), expectedVerdict: entry.expected.verdict, engineVerdicts: engines.map((engineId) => ({ engineId, verdict: entry.expected.verdict })) })),
    metricAgreements: corpus.cases.flatMap((entry) => metrics.map((metricId) => {
      const caseKey = arithmeticCaseKey(entry);
      const exposed = engines.map((engineId) => cellMap.get(`${engineId}|${caseKey}|${metricId}`)).filter((cell) => cell.status === 'measured' || cell.status === 'derived-engine');
      return exposed.length >= 2
        ? { caseKey, metricId, status: 'agree', comparableEngineIds: exposed.map((cell) => cell.engineId), valueDigest: sha256(canonicalize(exposed[0].value)) }
        : { caseKey, metricId, status: 'not-comparable', comparableEngineIds: exposed.map((cell) => cell.engineId), valueDigest: null };
    })),
  };
  const summaryDigest = put('artifacts/cross-engine-summary.json', Buffer.from(`${JSON.stringify(summary)}\n`));
  return { corpusDigest, raw, metricReportDigest, summaryDigest, metricReport, summary };
};

const engineNames = ['native', 'libauth', 'bchn', 'leanbch'];
const toolchainRows = engineNames.map((name, index) => {
  const sourceCommit = `${String(index + 1)}${'a'.repeat(39)}`;
  const sourceStatusPath = `toolchains/${name}/source-status.json`;
  const lockfilePath = `toolchains/${name}/lockfile.txt`;
  const buildManifestPath = `toolchains/${name}/build.txt`;
  const commandPath = `toolchains/${name}/command.txt`;
  const dirty = name === 'leanbch';
  return {
    engineId: `engine:${name}`,
    sourceCommit,
    sourceStatusPath,
    sourceStatusDigest: put(sourceStatusPath, Buffer.from(`${JSON.stringify({ primarySourceCommit: sourceCommit, dirty })}\n`)),
    lockfilePath,
    lockfileDigest: put(lockfilePath, Buffer.from(`${name}-lock\n`)),
    buildManifestPath,
    buildDigest: put(buildManifestPath, Buffer.from(`${name}-build\n`)),
    commandPath,
    commandDigest: put(commandPath, Buffer.from(`${name}-command\n`)),
    dirty,
  };
});

const makeRun = () => {
  const artifacts = makeArtifacts();
  const trackOrder = trackOrderForDescriptor(descriptor.contentDigest.value);
  const artifactRows = [
    ['corpus', artifacts.corpusDigest, 'content-addressed-corpus'],
    ['native-result', artifacts.raw.get('engine:native'), 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1'],
    ['libauth-result', artifacts.raw.get('engine:libauth'), 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1'],
    ['bchn-result', artifacts.raw.get('engine:bchn'), 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1'],
    ['leanbch-result', artifacts.raw.get('engine:leanbch'), 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1'],
    ['metric-report', artifacts.metricReportDigest, 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1'],
    ['cross-engine-summary', artifacts.summaryDigest, 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1'],
  ];
  const run = {
    schema: 'shieldkit-labs/p2-gate-b/equal-relation-arithmetic-run/v1', runId: 'gate-b0-run:m89-shakedown-v1', runMode: 'non-ranking-harness-shakedown',
    trackId: trackOrder[0], trackOrder, trackPosition: 0, cohortEpochId: null, status: 'measured-component-only',
    contentDigest: { algorithm: 'sha256-jcs-omit-contentDigest', value: '0'.repeat(64) }, selection: 'none', tupleRef: null, evidenceClassification: 'gate-b0-primitive-evidence-only',
    descriptorBinding: { path: 'inputs/descriptor.json', fileDigest: descriptorFileDigest, contentDigest: descriptor.contentDigest.value },
    campaignBinding: { path: 'inputs/campaign.json', fileDigest: campaignFileDigest, contentDigest: campaign.contentDigest.value },
    hostProfileBinding: { path: 'profiles/bch-current-2026-08-08.json', sha256: sha256(profileBytes), profileRef: 'profile:bch-current-2026-08-08' },
    corpus: { seedHex: '0123456789abcdef', generator: 'sha256-counter-rejection-v2', digest: artifacts.corpusDigest, counts: campaignCountsForDegree(campaign, 2) },
    toolchains: structuredClone(toolchainRows),
    artifacts: artifactRows.map(([kind, digest, artifactSchema]) => ({ artifactId: `artifact:${kind}`, kind, artifactSchema, path: `artifacts/${kind === 'corpus' ? 'corpus' : kind}.json`, sha256: digest })),
    artifactSchemaBindings: structuredClone(artifactSchemaBindings),
    engines: engines.map((engineId) => ({ engineId, status: 'measured', rawArtifactDigest: artifacts.raw.get(engineId), metricIds: [...metrics] })),
    crossEngineSummary: { verdictAgreement: true, metricCoverageAgreement: true, summaryArtifactDigest: artifacts.summaryDigest },
  };
  run.contentDigest.value = contentDigestFor(run);
  return run;
};

const refreshArtifactBinding = (run, kind) => {
  const artifact = run.artifacts.find((item) => item.kind === kind);
  artifact.sha256 = sha256(readFileSync(join(tempRoot, artifact.path)));
  if (kind === 'cross-engine-summary') run.crossEngineSummary.summaryArtifactDigest = artifact.sha256;
  const engineId = ({ 'native-result': 'engine:native', 'libauth-result': 'engine:libauth', 'bchn-result': 'engine:bchn', 'leanbch-result': 'engine:leanbch' })[kind];
  if (engineId) run.engines.find((item) => item.engineId === engineId).rawArtifactDigest = artifact.sha256;
  run.contentDigest.value = contentDigestFor(run);
};

test('artifact schemas require explicit metric value/provenance or explicit unavailable status', () => {
  const run = makeRun();
  assert.equal(validateSchema(run), true, JSON.stringify(validateSchema.errors));
  assert.equal(validateEngineSchema(JSON.parse(readFileSync(join(tempRoot, 'artifacts/native-result.json'), 'utf8'))), true, JSON.stringify(validateEngineSchema.errors));
  assert.equal(validateMetricSchema(JSON.parse(readFileSync(join(tempRoot, 'artifacts/metric-report.json'), 'utf8'))), true, JSON.stringify(validateMetricSchema.errors));
  assert.equal(validateSummarySchema(JSON.parse(readFileSync(join(tempRoot, 'artifacts/cross-engine-summary.json'), 'utf8'))), true, JSON.stringify(validateSummarySchema.errors));

  const report = JSON.parse(readFileSync(join(tempRoot, 'artifacts/metric-report.json'), 'utf8'));
  const unavailable = structuredClone(report.cells.find((cell) => cell.status === 'not-exposed'));
  unavailable.value = 1;
  assert.equal(validateMetricSchema({ schema: report.schema, corpusDigest: report.corpusDigest, cells: [unavailable] }), false);

  const measured = structuredClone(report.cells.find((cell) => cell.status === 'measured'));
  measured.provenance = null;
  assert.equal(validateMetricSchema({ schema: report.schema, corpusDigest: report.corpusDigest, cells: [measured] }), false);
});

test('run validator accepts byte-bound four-engine accounting with explicit non-exposure', () => {
  const run = makeRun();
  assert.deepEqual(validateArithmeticRun(run, descriptor, campaign, { rootDir: tempRoot }), []);
});

test('fabricated metricIds-only completeness and artifact substitution fail closed', () => {
  const run = makeRun();
  const reportPath = join(tempRoot, 'artifacts/metric-report.json');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.cells.pop();
  writeFileSync(reportPath, `${JSON.stringify(report)}\n`);
  assert.ok(validateArithmeticRun(run, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('metric-report digest mismatch') || error.includes('four-engine by case by metric accounting')));

  const restored = makeRun();
  const enginePath = join(tempRoot, 'artifacts/native-result.json');
  const result = JSON.parse(readFileSync(enginePath, 'utf8'));
  result.cases[0].transactionDigest = 'f'.repeat(64);
  writeFileSync(enginePath, `${JSON.stringify(result)}\n`);
  assert.ok(validateArithmeticRun(restored, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('native digest mismatch') || error.includes('summary fixture digest mismatch')));
});

test('cross-engine summary rejects a false overlap agreement even when every metricId is listed', () => {
  const run = makeRun();
  const summaryPath = join(tempRoot, 'artifacts/cross-engine-summary.json');
  const summary = JSON.parse(readFileSync(summaryPath, 'utf8'));
  const agreement = summary.metricAgreements.find((item) => item.metricId === 'verdict');
  agreement.valueDigest = '0'.repeat(64);
  writeFileSync(summaryPath, `${JSON.stringify(summary)}\n`);
  assert.ok(validateArithmeticRun(run, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('cross-engine-summary digest mismatch') || error.includes('overlapping exposed metric disagreement')));
});

test('diagnostic rejection-path values remain byte-bound but noncomparable', () => {
  const disagreement = makeRun();
  const caseKey = arithmeticCaseKey(corpus.cases.find((entry) => entry.expected.verdict === 'reject'));
  const reportPath = join(tempRoot, 'artifacts/metric-report.json');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  const bchnOpCost = report.cells.find((cell) => cell.engineId === 'engine:bchn' && cell.caseKey === caseKey && cell.metricId === 'opCost');
  bchnOpCost.value = 'diagnostic-reject-path-value';
  writeFileSync(reportPath, `${JSON.stringify(report)}\n`);
  refreshArtifactBinding(disagreement, 'metric-report');
  assert.ok(validateArithmeticRun(disagreement, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('overlapping exposed metric disagreement')));

  const noncomparable = makeRun();
  const accurateReport = JSON.parse(readFileSync(reportPath, 'utf8'));
  const accurateCell = accurateReport.cells.find((cell) => cell.engineId === 'engine:bchn' && cell.caseKey === caseKey && cell.metricId === 'opCost');
  accurateCell.status = 'measured-noncomparable';
  accurateCell.value = 'diagnostic-reject-path-value';
  assert.equal(validateMetricSchema(accurateReport), true, JSON.stringify(validateMetricSchema.errors));
  writeFileSync(reportPath, `${JSON.stringify(accurateReport)}\n`);
  refreshArtifactBinding(noncomparable, 'metric-report');
  const summaryPath = join(tempRoot, 'artifacts/cross-engine-summary.json');
  const summary = JSON.parse(readFileSync(summaryPath, 'utf8'));
  const agreement = summary.metricAgreements.find((item) => item.caseKey === caseKey && item.metricId === 'opCost');
  agreement.status = 'not-comparable';
  agreement.comparableEngineIds = ['engine:libauth'];
  agreement.valueDigest = null;
  writeFileSync(summaryPath, `${JSON.stringify(summary)}\n`);
  refreshArtifactBinding(noncomparable, 'cross-engine-summary');
  assert.deepEqual(validateArithmeticRun(noncomparable, descriptor, campaign, { rootDir: tempRoot }), []);

  const verdict = structuredClone(accurateCell);
  verdict.metricId = 'verdict';
  assert.equal(validateMetricSchema({ schema: accurateReport.schema, corpusDigest: accurateReport.corpusDigest, cells: [verdict] }), false);
});

test('execution logs, schema files, and every metric-cell fixture digest are byte-bound', () => {
  const logMismatch = makeRun();
  const bchnPath = join(tempRoot, 'artifacts/bchn-result.json');
  const bchn = JSON.parse(readFileSync(bchnPath, 'utf8'));
  bchn.execution.stdout.text = 'tampered stdout\n';
  writeFileSync(bchnPath, `${JSON.stringify(bchn)}\n`);
  refreshArtifactBinding(logMismatch, 'bchn-result');
  assert.ok(validateArithmeticRun(logMismatch, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('external stdout digest or byte length mismatch')));

  const fixtureMismatch = makeRun();
  const reportPath = join(tempRoot, 'artifacts/metric-report.json');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  report.cells.find((cell) => cell.status === 'not-exposed').fixtureDigest = 'f'.repeat(64);
  writeFileSync(reportPath, `${JSON.stringify(report)}\n`);
  refreshArtifactBinding(fixtureMismatch, 'metric-report');
  assert.ok(validateArithmeticRun(fixtureMismatch, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('run metric fixture digest mismatch')));

  const schemaSubstitution = makeRun();
  schemaSubstitution.artifactSchemaBindings[0].sha256 = '0'.repeat(64);
  schemaSubstitution.contentDigest.value = contentDigestFor(schemaSubstitution);
  assert.ok(validateArithmeticRun(schemaSubstitution, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('artifact schema shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1 digest mismatch')));

  const duplicateSchema = makeRun();
  duplicateSchema.artifactSchemaBindings[2].schemaId = duplicateSchema.artifactSchemaBindings[0].schemaId;
  duplicateSchema.contentDigest.value = contentDigestFor(duplicateSchema);
  assert.ok(validateArithmeticRun(duplicateSchema, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('artifact schema binding roster drift')));

  const missingSchema = makeRun();
  missingSchema.artifactSchemaBindings.pop();
  missingSchema.contentDigest.value = contentDigestFor(missingSchema);
  assert.equal(validateSchema(missingSchema), false);
  assert.ok(validateArithmeticRun(missingSchema, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('artifact schema binding roster drift')));
});

test('run mode, track order, descriptor binding, selection, and Lean-only whole-engine unsupported remain fail-closed', () => {
  const wrongOrder = makeRun();
  wrongOrder.trackOrder.reverse();
  wrongOrder.contentDigest.value = contentDigestFor(wrongOrder);
  assert.ok(validateArithmeticRun(wrongOrder, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('track order')));

  const wrongDescriptor = makeRun();
  wrongDescriptor.descriptorBinding.contentDigest = 'f'.repeat(64);
  wrongDescriptor.contentDigest.value = contentDigestFor(wrongDescriptor);
  assert.ok(validateArithmeticRun(wrongDescriptor, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('descriptor digest')));

  const selection = makeRun();
  selection.selection = 'selected';
  selection.contentDigest.value = contentDigestFor(selection);
  assert.equal(validateSchema(selection), false);

  const unsupported = makeRun();
  unsupported.engines.find((item) => item.engineId === 'engine:bchn').status = 'explicit-unsupported';
  unsupported.contentDigest.value = contentDigestFor(unsupported);
  assert.ok(validateArithmeticRun(unsupported, descriptor, campaign, { rootDir: tempRoot }).some((error) => error.includes('only LeanBCH')));
});
