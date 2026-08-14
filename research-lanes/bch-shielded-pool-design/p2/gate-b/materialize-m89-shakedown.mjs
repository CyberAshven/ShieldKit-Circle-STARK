#!/usr/bin/env node
/**
 * Mechanical Gate-B0 materializer for the M89 canonical-schoolbook shakedown.
 *
 * This module is deliberately boring: it turns one runner report into the
 * seven content-addressed run artifacts. Imported helpers never run engines;
 * the CLI runs the frozen shakedown only when --write is explicitly used.
 */

import { execFileSync } from 'node:child_process';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';
import { buildM89ShakedownReport } from './run-m89-shakedown.mjs';
import {
  arithmeticCaseKey,
  campaignCountsForDegree,
  canonicalize,
  contentDigestFor,
  sha256,
  trackOrderForDescriptor,
  validateArithmeticRun,
} from '../algebra-component/algebra-component-validation.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const P2_ROOT = resolve(HERE, '..');
const LANE_ROOT = resolve(P2_ROOT, '..');
const REPO_ROOT = resolve(LANE_ROOT, '../..');
export const M89_OFFICIAL_RUN = 'p2/gate-b/runs/m89-d2-schoolbook-shakedown-v1';
export const M89_RUN_ID = 'gate-b0-run:m89-d2-schoolbook-shakedown-v1';
export const METRICS = Object.freeze([
  'verdict', 'lockingBytes', 'unlockingBytes', 'sourceBytes',
  'opcodeHistogram', 'mulByteProduct', 'divByteProduct', 'modByteProduct',
  'resultPushBytes', 'vmCost', 'opCost', 'stackMax', 'elementMax', 'limits',
  'headroom',
]);
export const ENGINES = Object.freeze(['engine:native', 'engine:libauth', 'engine:bchn', 'engine:leanbch']);

const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));
const bytes = (value) => Buffer.isBuffer(value) ? value : Buffer.from(value);
const jsonBytes = (value) => Buffer.from(`${canonicalize(value)}\n`, 'utf8');
const digest = (value) => sha256(bytes(value));
const fileBytes = (path) => readFileSync(path);
const put = (root, path, value) => {
  const target = join(root, path);
  mkdirSync(dirname(target), { recursive: true });
  const data = bytes(value);
  writeFileSync(target, data);
  return digest(data);
};
const git = (repo, args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
const gitRaw = (repo, args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
const sourceCommit = (repo) => {
  const head = git(repo, ['rev-parse', 'HEAD']);
  if (!/^[0-9a-f]{40,64}$/u.test(head)) throw new Error(`invalid git HEAD for ${repo}`);
  return head;
};
const gitDirty = (repo) => gitRaw(repo, ['status', '--porcelain=v1']) !== '';
const gitOutputDigest = (repo, args) => digest(gitRaw(repo, args));
const fileDigestInRepo = (repo, path) => {
  const absolute = resolve(repo, path);
  if (!existsSync(absolute)) throw new Error(`required provenance file is missing: ${absolute}`);
  return { path, sha256: digest(fileBytes(absolute)) };
};
const repoSnapshot = (repo, relevantPaths) => ({
  repo, head: sourceCommit(repo), headTree: git(repo, ['rev-parse', 'HEAD^{tree}']),
  statusText: gitRaw(repo, ['status', '--porcelain=v1']),
  statusSha256: gitOutputDigest(repo, ['status', '--porcelain=v1']),
  diffSha256: gitOutputDigest(repo, ['diff', '--no-ext-diff']),
  relevantFiles: relevantPaths.map((path) => fileDigestInRepo(repo, path)),
});

const sourcePath = (root, suffix) => resolve(root, suffix);
const INPUTS = Object.freeze({
  descriptor: sourcePath(P2_ROOT, 'algebra-component/descriptors/m89-d2-x2-plus-1.v1.json'),
  campaign: sourcePath(P2_ROOT, 'gate-b/equal-relation-arithmetic-campaign.v1.json'),
  corpus: sourcePath(P2_ROOT, 'reference/m89-corpus.json'),
  profile: sourcePath(LANE_ROOT, 'profiles/bch-current-2026-08-08.json'),
  runSchema: sourcePath(P2_ROOT, 'gate-b/equal-relation-arithmetic-run.v1.schema.json'),
  engineSchema: sourcePath(P2_ROOT, 'gate-b/equal-relation-arithmetic-engine-result.v1.schema.json'),
  metricSchema: sourcePath(P2_ROOT, 'gate-b/equal-relation-arithmetic-metric-report.v1.schema.json'),
  summarySchema: sourcePath(P2_ROOT, 'gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json'),
});

const fixtureDigestFor = (entry, item) => digest(canonicalize({
  caseKey: arithmeticCaseKey(entry),
  relationId: entry.relationId,
  categoryId: entry.categoryId,
  caseIndex: entry.caseIndex,
  vectorAttempt: entry.vectorAttempt,
  sourceLockingHex: item.artifacts.sourceLockingHex,
  unlockingHex: item.artifacts.unlockingHex,
  transactionHex: item.artifacts.transactionHex,
  sourceOutputsHex: item.artifacts.sourceOutputsHex,
  inputIndex: 0,
}));

const fixtureWire = (entry, item) => ({
  caseKey: arithmeticCaseKey(entry),
  fixtureDigest: fixtureDigestFor(entry, item),
  transactionDigest: item.artifacts.transactionSha256,
  sourceOutputsDigest: item.artifacts.sourceOutputsSha256,
});
const externalStream = (text) => ({
  text: text ?? '',
  sha256: digest(text ?? ''),
  byteLength: Buffer.byteLength(text ?? '', 'utf8'),
});
const inProcessExecution = (modulePath, implementationDigest) => ({
  status: 'measured', mode: 'in-process',
  entrypoint: { kind: 'module', argv: null, modulePath },
  implementationDigest, stdin: { text: null, sha256: null, byteLength: 0 },
  stdout: { text: null, sha256: null, byteLength: 0 },
  stderr: { text: null, sha256: null, byteLength: 0 },
  evidenceBoundary: 'gate-b0-primitive-evidence-only',
});
const externalExecution = (argv, implementationDigest, stdin, stdout, stderr) => ({
  status: 'measured', mode: 'external',
  entrypoint: { kind: 'argv', argv, modulePath: null },
  implementationDigest, stdin: externalStream(stdin), stdout: externalStream(stdout),
  stderr: externalStream(stderr), evidenceBoundary: 'gate-b0-primitive-evidence-only',
});

const valueCell = (engineId, item, metricId, status, value, rawDigest, reason = null, method = 'raw-engine-result') => {
  const wire = fixtureWire(item._entry ?? item.entry, item);
  if (status === 'derived-common') return {
    engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status,
    value, provenance: { sourceArtifactDigest: wire.fixtureDigest, method }, reason: null,
  };
  if (status === 'not-reached' || status === 'not-exposed' || status === 'not-applicable') return {
    engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status,
    value: null, provenance: null, reason,
  };
  return {
    engineId, caseKey: wire.caseKey, fixtureDigest: wire.fixtureDigest, metricId, status,
    value, provenance: { sourceArtifactDigest: rawDigest, method }, reason: null,
  };
};

const rawLimits = (x) => x === null || x === undefined ? null : ({
  operationCost: x.maximumOperationCost,
  hashDigestIterations: x.maximumHashDigestIterations,
  signatureCheckCount: x.maximumSignatureCheckCount,
});
const rawHeadroom = (metrics, limits) => (metrics === null || limits === null) ? null : ({
  operationCost: limits.operationCost - metrics.operationCost,
  hashDigestIterations: limits.hashDigestIterations - metrics.hashDigestIterations,
  signatureCheckCount: limits.signatureCheckCount - metrics.signatureCheckCount,
});
const has = (x) => x !== null && x !== undefined;
const rejectStatus = (accepted) => accepted ? 'measured' : 'measured-noncomparable';
const observedVerdictFor = (engineId, item) => {
  if (engineId === 'engine:native') {
    if (item.native?.verdict === 'accept' || item.native?.verdict === 'reject') return item.native.verdict;
  } else {
    const observation = engineId === 'engine:libauth'
      ? item.libauth
      : engineId === 'engine:bchn'
        ? item.bchn
        : item.leanbch;
    if (observation?.accepted === true) return 'accept';
    if (observation?.accepted === false) return 'reject';
  }
  throw new Error(`${engineId} has no explicit per-case verdict for ${item.id}`);
};

const metricCellsFor = (engineId, item, rawDigest, entry = item._entry ?? item.entry) => {
  item = { ...item, _entry: entry };
  const accepted = item.expected.verdict === 'accept';
  const common = {
    lockingBytes: item.artifacts.sourceLockingBytes,
    unlockingBytes: item.artifacts.unlockingBytes,
    sourceBytes: item.artifacts.sourceOutputsBytes,
  };
  const cells = [];
  for (const metricId of METRICS) {
    if (Object.hasOwn(common, metricId)) {
      cells.push(valueCell(engineId, item, metricId, 'derived-common', common[metricId], rawDigest, null, 'shared-p2sh32-fixture-wire'));
      continue;
    }
    if (metricId === 'verdict') {
      cells.push(valueCell(engineId, item, metricId, 'measured', observedVerdictFor(engineId, item), rawDigest, null, 'raw-engine-verdict'));
      continue;
    }
    if (engineId === 'engine:native') {
      cells.push(valueCell(engineId, item, metricId, 'not-applicable', null, rawDigest, 'native reference evaluator exposes no VM byte or cost metric'));
      continue;
    }
    if (engineId === 'engine:libauth') {
      const x = item.libauth;
      const traceValues = {
        opcodeHistogram: x.opcodeHistogram, mulByteProduct: x.mulByteProduct,
        divByteProduct: x.divByteProduct, modByteProduct: x.modByteProduct,
        resultPushBytes: x.resultPushBytes, stackMax: x.stackMaximums,
        elementMax: x.elementMax,
      };
      if (Object.hasOwn(traceValues, metricId) && has(traceValues[metricId])) {
        cells.push(valueCell(engineId, item, metricId, 'measured', traceValues[metricId], rawDigest, null, 'libauth-standard-vm-trace-derived-metric'));
      } else if (metricId === 'vmCost' && has(x.rawMetrics?.arithmeticCost)) {
        cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), x.rawMetrics.arithmeticCost, rawDigest, null, 'libauth-standard-vm-arithmetic-cost'));
      } else if (metricId === 'opCost' && has(x.rawMetrics?.operationCost)) {
        cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), x.rawMetrics.operationCost, rawDigest, null, 'libauth-standard-vm-op-cost'));
      } else if (metricId === 'limits' && has(rawLimits(x.rawMetrics))) {
        cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), rawLimits(x.rawMetrics), rawDigest, null, 'libauth-standard-vm-limits'));
      } else if (metricId === 'headroom' && has(rawHeadroom(x.rawMetrics, rawLimits(x.rawMetrics)))) {
        cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), rawHeadroom(x.rawMetrics, rawLimits(x.rawMetrics)), rawDigest, null, 'libauth-standard-vm-headroom'));
      } else {
        cells.push(valueCell(engineId, item, metricId, 'not-exposed', null, rawDigest, 'Libauth does not expose this normalized metric surface'));
      }
      continue;
    }
    if (engineId === 'engine:bchn') {
      const x = item.bchn?.metrics;
      const present = has(x);
      if (metricId === 'opCost' && present && has(x.operationCost)) cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), x.operationCost, rawDigest, null, 'bchn-standard-vm-exposed-op-cost'));
      else if (metricId === 'limits' && present) cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), { operationCost: x.maximumOperationCost, hashDigestIterations: x.maximumHashDigestIterations, signatureCheckCount: x.maximumSignatureCheckCount }, rawDigest, null, 'bchn-standard-vm-exposed-limits'));
      else if (metricId === 'headroom' && present) cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), rawHeadroom({ operationCost: x.operationCost, hashDigestIterations: x.hashDigestIterations, signatureCheckCount: x.signatureCheckCount }, { operationCost: x.maximumOperationCost, hashDigestIterations: x.maximumHashDigestIterations, signatureCheckCount: x.maximumSignatureCheckCount }), rawDigest, null, 'bchn-standard-vm-derived-headroom'));
      else cells.push(valueCell(engineId, item, metricId, 'not-exposed', null, rawDigest, 'BCHN adapter does not expose this normalized metric surface'));
      continue;
    }
    const x = item.leanbch;
    if (metricId === 'vmCost' && has(x?.rawMetrics?.arithmeticCost)) cells.push(valueCell(engineId, item, metricId, rejectStatus(accepted), x.rawMetrics.arithmeticCost, rawDigest, null, 'leanbch-costprobe-arithmetic-cost'));
    else if (metricId === 'opCost' && accepted && has(x?.derivedStandard192OperationCost)) cells.push(valueCell(engineId, item, metricId, 'derived-engine', x.derivedStandard192OperationCost, rawDigest, null, 'leanbch-costprobe-raw-five-standard-192'));
    else if (metricId === 'opCost' && !accepted && has(x?.derivedStandard192OperationCost)) cells.push(valueCell(engineId, item, metricId, 'measured-noncomparable', x.derivedStandard192OperationCost, rawDigest, null, 'leanbch-costprobe-reject-diagnostic'));
    else cells.push(valueCell(engineId, item, metricId, x?.status === 'unsupported-reject-metrics' ? 'not-reached' : 'not-exposed', null, rawDigest, x?.status === 'unsupported-reject-metrics' ? 'CostProbe explicitly skipped reject metrics' : 'LeanBCH does not expose this normalized metric surface'));
  }
  return cells;
};

const engineExecution = (engineId, report) => {
  if (engineId === 'engine:native') return inProcessExecution('p2/reference/m89-corpus.mjs', digest(fileBytes(sourcePath(P2_ROOT, 'reference/m89-corpus.mjs'))));
  if (engineId === 'engine:libauth') return inProcessExecution('p2/gate-b/m89-shakedown-fixture.mjs', digest(fileBytes(sourcePath(P2_ROOT, 'gate-b/m89-shakedown-fixture.mjs'))));
  if (engineId === 'engine:bchn') {
    const x = report.engines.bchn;
    if (!/^[0-9a-f]{64}$/u.test(x.binarySha256 ?? '')) throw new Error('BCHN report lacks a content-pinned binary digest');
    return externalExecution(x.argv ?? [], x.binarySha256, x.stdinText ?? '', x.stdoutText ?? '', x.stderrText ?? '');
  }
  // The two Lean subprocesses are retained in rawObservation/toolchain
  // records. The engine execution binding is the reproducible stdout-only
  // runner command, whose exact JSON stdout is bound once here.
  const runnerSource = fileBytes(sourcePath(P2_ROOT, 'gate-b/run-m89-shakedown.mjs'));
  return externalExecution(
    ['node', 'research-lanes/bch-shielded-pool-design/p2/gate-b/run-m89-shakedown.mjs'],
    digest(runnerSource), '', `${JSON.stringify(report, null, 2)}\n`, '',
  );
};

const rawObservationFor = (engineId, item, report) => {
  if (engineId === 'engine:native') return { reportCase: item.native, expected: item.expected, fixtureArtifacts: item.artifacts };
  if (engineId === 'engine:libauth') return { reportCase: item.libauth, policyBoundary: item.policyBoundary, fixtureArtifacts: item.artifacts };
  if (engineId === 'engine:bchn') {
    const process = report.engines.bchn;
    return {
      reportCase: item.bchn,
      rawExternal: item.bchn?.rawExternal,
      processDigests: {
        executablePath: process.executablePath,
        argv: process.argv,
        childStatus: process.childStatus,
        binarySha256: process.binarySha256,
        stdinSha256: process.stdinSha256,
        stdoutSha256: process.stdoutSha256,
        stderrSha256: process.stderrSha256,
      },
    };
  }
  const cost = report.engines.leanbchCostprobe;
  const vm = report.engines.leanbchVmbconf;
  return {
    reportCase: item.leanbch,
    costProbeProcess: { executablePath: cost.executablePath, argv: cost.argv, childStatus: cost.childStatus, binarySha256: cost.binarySha256, stdinSha256: cost.stdinSha256, stdoutSha256: cost.stdoutSha256, stderrSha256: cost.stderrSha256 },
    vmbconfAggregate: { oracle: vm.oracle, passed: vm.passed, total: vm.total, rejectedValid: vm.rejectedValid, acceptedInvalid: vm.acceptedInvalid, standardTrue: vm.standardTrue, standardFalse: vm.standardFalse, standardIdListLimit: vm.standardIdListLimit, standardTrueIdsTruncated: vm.standardTrueIdsTruncated, standardFalseIdsTruncated: vm.standardFalseIdsTruncated },
    vmbconfProcessDigests: { executablePath: vm.executablePath, argv: vm.argv, childStatus: vm.childStatus, binarySha256: vm.binarySha256, stdinSha256: vm.stdinSha256, stdoutSha256: vm.stdoutSha256, stderrSha256: vm.stderrSha256 },
  };
};

const buildEngineArtifact = (engineId, report, corpusDigest, reportByKey) => {
  const execution = engineExecution(engineId, report);
  const rawRows = report.cases.map((item) => {
    const entry = reportByKey.get(item.id);
    const wire = fixtureWire(entry, item);
    const observed = observedVerdictFor(engineId, item);
    return {
      ...wire,
      verdict: observed,
      rawObservation: rawObservationFor(engineId, item, report),
    };
  });
  return {
    schema: 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', engineId,
    corpusDigest, execution, cases: rawRows,
  };
};

const buildSummary = (corpusDigest, corpusCases, engineRows, metricCells) => {
  const cases = corpusCases.map(({ entry, item }) => {
    const wire = fixtureWire(entry, item);
    return { ...wire, expectedVerdict: entry.expected.verdict, engineVerdicts: ENGINES.map((engineId) => ({ engineId, verdict: engineRows.get(engineId).get(wire.caseKey).verdict })) };
  });
  const metricAgreements = corpusCases.flatMap(({ entry, item }) => METRICS.map((metricId) => {
    const caseKey = arithmeticCaseKey(entry);
    const exposed = ENGINES.map((engineId) => metricCells.get(`${engineId}|${caseKey}|${metricId}`)).filter((cell) => cell.status === 'measured' || cell.status === 'derived-engine');
    if (exposed.length < 2) return { caseKey, metricId, status: 'not-comparable', comparableEngineIds: exposed.map((cell) => cell.engineId), valueDigest: null };
    const first = canonicalize(exposed[0].value);
    if (!exposed.every((cell) => canonicalize(cell.value) === first)) throw new Error(`exposed metric disagreement at ${caseKey}/${metricId}`);
    return { caseKey, metricId, status: 'agree', comparableEngineIds: exposed.map((cell) => cell.engineId), valueDigest: digest(first) };
  }));
  return {
    schema: 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1', corpusDigest,
    verdictAgreement: cases.every((row) => row.engineVerdicts.every((x) => x.verdict === row.expectedVerdict)),
    metricCoverageAgreement: metricAgreements.every((x) => x.status === 'agree' || x.status === 'not-comparable'),
    cases, metricAgreements,
  };
};

const toolchainRecord = (root, engineId, repo, dirty, command, binarySha256 = null, {
  adapterRepo = null,
  adapterRelevantPaths = [],
  relevantPaths = [],
  binaryDigests = {},
  additionalCommands = [],
  buildCommands = [],
  workingDirectory = repo,
} = {}) => {
  if ((engineId === 'engine:bchn' || engineId === 'engine:leanbch') && !/^[0-9a-f]{64}$/u.test(binarySha256 ?? '')) throw new Error(`${engineId} has no content-pinned binary digest`);
  for (const [name, value] of Object.entries(binaryDigests)) if (!/^[0-9a-f]{64}$/u.test(value ?? '')) throw new Error(`${engineId} has no content-pinned ${name} binary digest`);
  const name = engineId.slice('engine:'.length);
  const commit = sourceCommit(repo);
  const statusPath = `toolchains/${name}/source-status.json`;
  const lockPath = `toolchains/${name}/lock-snapshot.json`;
  const buildPath = `toolchains/${name}/build-record.json`;
  const commandPath = `toolchains/${name}/command-record.json`;
  const primarySnapshot = repoSnapshot(repo, relevantPaths);
  const adapterSnapshot = adapterRepo === null ? null : repoSnapshot(adapterRepo, adapterRelevantPaths);
  const rootSnapshot = repoSnapshot(REPO_ROOT, [
    'package.json',
    'package-lock.json',
    'research-lanes/bch-shielded-pool-design/p2/algebra-component/algebra-component-validation.mjs',
    'research-lanes/bch-shielded-pool-design/p2/gate-b/materialize-m89-shakedown.mjs',
    'research-lanes/bch-shielded-pool-design/p2/gate-b/run-m89-shakedown.mjs',
    'research-lanes/bch-shielded-pool-design/p2/gate-b/m89-shakedown-fixture.mjs',
    'research-lanes/bch-shielded-pool-design/p2/bch-kernels/m89-kernel.mjs',
  ]);
  const status = {
    recordType: 'source-status', engineId, sourceRoot: repo, primarySourceCommit: commit,
    dirty, primarySnapshot, rootDirtySourceManifest: rootSnapshot,
    ...(adapterSnapshot === null ? {} : { adapterSnapshot }),
  };
  const lock = { recordType: 'lock-snapshot', engineId, sourceCommit: commit, packageLock: fileDigestInRepo(REPO_ROOT, 'package-lock.json'), packageJson: fileDigestInRepo(REPO_ROOT, 'package.json'), primarySnapshot, adapterSnapshot, binarySha256, binaryDigests };
  const build = { recordType: 'build-record', engineId, sourceCommit: commit, binarySha256, binaryDigests, buildStatus: 'measured-or-in-process', sourceSnapshot: primarySnapshot, adapterSnapshot, buildCommands, executionCommand: command, reproducibleInputs: ['descriptor', 'campaign', 'corpus', 'fixture-kernel'] };
  const commandRecord = { recordType: 'command-record', engineId, argv: command, additionalCommands, workingDirectory, stdoutOnlyRunner: 'research-lanes/bch-shielded-pool-design/p2/gate-b/run-m89-shakedown.mjs', exactCommand: command.join(' '), environment: { standardMode: true, evidenceBoundary: 'isolated-synthetic-one-input-p2sh32-component-fixture-only' } };
  return {
    row: { engineId, sourceCommit: commit, sourceStatusPath: statusPath, sourceStatusDigest: put(root, statusPath, jsonBytes(status)), lockfilePath: lockPath, lockfileDigest: put(root, lockPath, jsonBytes(lock)), buildManifestPath: buildPath, buildDigest: put(root, buildPath, jsonBytes(build)), commandPath, commandDigest: put(root, commandPath, jsonBytes(commandRecord)), dirty },
  };
};

const ensureInputs = (root) => {
  const descriptor = readJson(INPUTS.descriptor);
  const campaign = readJson(INPUTS.campaign);
  const corpus = readJson(INPUTS.corpus);
  const descriptorFileDigest = put(root, 'inputs/descriptor.json', fileBytes(INPUTS.descriptor));
  const campaignFileDigest = put(root, 'inputs/campaign.json', fileBytes(INPUTS.campaign));
  put(root, 'profiles/bch-current-2026-08-08.json', fileBytes(INPUTS.profile));
  put(root, 'p2/gate-b/equal-relation-arithmetic-run.v1.schema.json', fileBytes(INPUTS.runSchema));
  put(root, 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json', fileBytes(INPUTS.engineSchema));
  put(root, 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json', fileBytes(INPUTS.metricSchema));
  put(root, 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json', fileBytes(INPUTS.summarySchema));
  return { descriptor, campaign, corpus, descriptorFileDigest, campaignFileDigest };
};

export const buildM89OfficialRun = (report, { rootDir = null, gitRepositories = {} } = {}) => {
  if (!report || report.status !== 'measured-component-only-pass') throw new Error(`materializer requires measured-component-only-pass; got ${report?.status}`);
  if (!rootDir) throw new Error('materializer requires an explicit target root; refusing implicit writes');
  const temp = rootDir;
  const inputs = ensureInputs(temp);
  const corpusDigest = put(temp, 'artifacts/corpus.json', fileBytes(INPUTS.corpus));
  const corpusCases = inputs.corpus.cases.map((entry) => {
    const matches = report.cases.filter((item) => item.relationId === entry.relationId && item.categoryId === entry.categoryId && item.caseIndex === entry.caseIndex && item.vectorAttempt === entry.vectorAttempt);
    if (matches.length !== 1) throw new Error(`report/corpus coordinate bijection failure for ${arithmeticCaseKey(entry)} (${matches.length})`);
    return { entry, item: matches[0] };
  });
  if (report.cases.length !== corpusCases.length) throw new Error(`report has ${report.cases.length} rows for ${corpusCases.length} corpus cases`);
  const reportByKey = new Map(report.cases.map((item) => [item.id, inputs.corpus.cases.find((entry) => entry.relationId === item.relationId && entry.categoryId === item.categoryId && entry.caseIndex === item.caseIndex && entry.vectorAttempt === item.vectorAttempt)]));
  const raw = new Map();
  for (const engineId of ENGINES) raw.set(engineId, buildEngineArtifact(engineId, report, corpusDigest, reportByKey));
  const rawBytes = new Map();
  for (const engineId of ENGINES) rawBytes.set(engineId, jsonBytes(raw.get(engineId)));
  const rawDigest = new Map(ENGINES.map((engineId) => [engineId, put(temp, `artifacts/${engineId.slice(7)}-result.json`, rawBytes.get(engineId))]));
  const metricCells = new Map();
  for (const engineId of ENGINES) for (const { entry, item } of corpusCases) for (const cell of metricCellsFor(engineId, item, rawDigest.get(engineId), entry)) metricCells.set(`${cell.engineId}|${cell.caseKey}|${cell.metricId}`, cell);
  const metricReport = { schema: 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', corpusDigest, cells: [...metricCells.values()] };
  const metricReportDigest = put(temp, 'artifacts/metric-report.json', jsonBytes(metricReport));
  const engineRows = new Map(ENGINES.map((engineId) => [engineId, new Map(raw.get(engineId).cases.map((row) => [row.caseKey, row]))]));
  const summary = buildSummary(corpusDigest, corpusCases, engineRows, metricCells);
  const summaryDigest = put(temp, 'artifacts/cross-engine-summary.json', jsonBytes(summary));
  const nativeRepo = REPO_ROOT;
  const runnerCommand = ['node', 'research-lanes/bch-shielded-pool-design/p2/gate-b/run-m89-shakedown.mjs'];
  const bchnRepo = gitRepositories.bchn ?? '/home/toorik/Projects/BCH/bchn-src';
  const bchnAdapterRepo = gitRepositories.bchnAdapter ?? '/home/toorik/Projects/BCH/bch-conformance';
  const leanRepo = gitRepositories.leanbch ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH';
  const toolchains = [
    toolchainRecord(temp, 'engine:native', gitRepositories.native ?? nativeRepo, gitDirty(gitRepositories.native ?? nativeRepo), runnerCommand, null, {
      workingDirectory: nativeRepo,
      relevantPaths: ['package.json', 'package-lock.json', 'research-lanes/bch-shielded-pool-design/p2/reference/m89.mjs', 'research-lanes/bch-shielded-pool-design/p2/reference/m89-corpus.mjs', 'research-lanes/bch-shielded-pool-design/p2/reference/m89-corpus.json', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/algebra-component-validation.mjs', 'research-lanes/bch-shielded-pool-design/p2/gate-b/materialize-m89-shakedown.mjs', 'research-lanes/bch-shielded-pool-design/p2/gate-b/run-m89-shakedown.mjs'],
    }).row,
    toolchainRecord(temp, 'engine:libauth', gitRepositories.libauth ?? nativeRepo, gitDirty(gitRepositories.libauth ?? nativeRepo), runnerCommand, null, {
      workingDirectory: nativeRepo,
      relevantPaths: ['package.json', 'package-lock.json', 'research-lanes/bch-shielded-pool-design/p2/reference/m89.mjs', 'research-lanes/bch-shielded-pool-design/p2/reference/m89-corpus.json', 'research-lanes/bch-shielded-pool-design/p2/algebra-component/algebra-component-validation.mjs', 'research-lanes/bch-shielded-pool-design/p2/gate-b/materialize-m89-shakedown.mjs', 'research-lanes/bch-shielded-pool-design/p2/gate-b/run-m89-shakedown.mjs', 'research-lanes/bch-shielded-pool-design/p2/gate-b/m89-shakedown-fixture.mjs', 'research-lanes/bch-shielded-pool-design/p2/bch-kernels/m89-kernel.mjs'],
    }).row,
    toolchainRecord(temp, 'engine:bchn', bchnRepo, gitDirty(bchnRepo) || gitDirty(bchnAdapterRepo), report.engines.bchn?.argv ?? [], report.engines.bchn?.binarySha256 ?? null, {
      adapterRepo: bchnAdapterRepo,
      adapterRelevantPaths: ['legs/bchn/README.md', 'legs/bchn/build.sh', 'legs/bchn/bchn-leg.cpp'],
      relevantPaths: ['CMakeLists.txt', 'README.md', 'src/script/interpreter.cpp'],
      buildCommands: [['bash', 'legs/bchn/build.sh']],
      workingDirectory: bchnAdapterRepo,
    }).row,
    toolchainRecord(temp, 'engine:leanbch', leanRepo, gitDirty(leanRepo), report.engines.leanbchCostprobe?.argv ?? [], report.engines.leanbchCostprobe?.binarySha256 ?? null, {
      relevantPaths: ['lake-manifest.json', 'lakefile.toml', 'lean-toolchain', 'LeanBCH/VM/Extended.lean', 'conformance/CostProbe.lean', 'conformance/Runner.lean', 'tooling/manifest.json'],
      binaryDigests: { costprobe: report.engines.leanbchCostprobe?.binarySha256 ?? null, vmbconf: report.engines.leanbchVmbconf?.binarySha256 ?? null },
      additionalCommands: [report.engines.leanbchVmbconf?.argv ?? []],
      buildCommands: [['/home/toorik/.elan/bin/lake', 'build', 'costprobe', 'vmbconf']],
      workingDirectory: leanRepo,
    }).row,
  ];
  const artifactRows = [
    ['corpus', 'content-addressed-corpus', 'artifacts/corpus.json', corpusDigest],
    ['native-result', 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', 'artifacts/native-result.json', rawDigest.get('engine:native')],
    ['libauth-result', 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', 'artifacts/libauth-result.json', rawDigest.get('engine:libauth')],
    ['bchn-result', 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', 'artifacts/bchn-result.json', rawDigest.get('engine:bchn')],
    ['leanbch-result', 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', 'artifacts/leanbch-result.json', rawDigest.get('engine:leanbch')],
    ['metric-report', 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', 'artifacts/metric-report.json', metricReportDigest],
    ['cross-engine-summary', 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1', 'artifacts/cross-engine-summary.json', summaryDigest],
  ].map(([kind, artifactSchema, path, sha256Value]) => ({ artifactId: `artifact:${kind}`, kind, artifactSchema, path, sha256: sha256Value }));
  const descriptor = inputs.descriptor;
  const campaign = inputs.campaign;
  const trackOrder = trackOrderForDescriptor(descriptor.contentDigest.value);
  const run = {
    schema: 'shieldkit-labs/p2-gate-b/equal-relation-arithmetic-run/v1', runId: M89_RUN_ID,
    runMode: 'non-ranking-harness-shakedown', trackId: 'track:canonical-schoolbook', trackOrder, trackPosition: 1,
    cohortEpochId: null, status: 'measured-component-only', contentDigest: { algorithm: 'sha256-jcs-omit-contentDigest', value: '0'.repeat(64) },
    selection: 'none', tupleRef: null, evidenceClassification: 'gate-b0-primitive-evidence-only',
    descriptorBinding: { path: 'inputs/descriptor.json', fileDigest: inputs.descriptorFileDigest, contentDigest: descriptor.contentDigest.value },
    campaignBinding: { path: 'inputs/campaign.json', fileDigest: inputs.campaignFileDigest, contentDigest: campaign.contentDigest.value },
    hostProfileBinding: { path: 'profiles/bch-current-2026-08-08.json', sha256: digest(fileBytes(INPUTS.profile)), profileRef: 'profile:bch-current-2026-08-08' },
    corpus: { seedHex: '0123456789abcdef', generator: 'sha256-counter-rejection-v2', digest: corpusDigest, counts: campaignCountsForDegree(campaign, 2) },
    toolchains, artifacts: artifactRows,
    artifactSchemaBindings: [
      { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-engine-result/v1', path: 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json', sha256: digest(fileBytes(INPUTS.engineSchema)) },
      { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-metric-report/v1', path: 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json', sha256: digest(fileBytes(INPUTS.metricSchema)) },
      { schemaId: 'shieldkit-labs/p2-gate-b/arithmetic-cross-engine-summary/v1', path: 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json', sha256: digest(fileBytes(INPUTS.summarySchema)) },
    ],
    engines: ENGINES.map((engineId) => ({ engineId, status: 'measured', rawArtifactDigest: rawDigest.get(engineId), metricIds: [...METRICS] })),
    crossEngineSummary: { verdictAgreement: summary.verdictAgreement, metricCoverageAgreement: summary.metricCoverageAgreement, summaryArtifactDigest: summaryDigest },
  };
  run.contentDigest.value = contentDigestFor(run);
  return { run, artifacts: { corpus: inputs.corpus, native: raw.get('engine:native'), libauth: raw.get('engine:libauth'), bchn: raw.get('engine:bchn'), leanbch: raw.get('engine:leanbch'), metricReport, crossEngineSummary: summary }, descriptor, campaign };
};

export const materializeM89Shakedown = (report, targetDir) => {
  if (!targetDir) throw new Error('targetDir is required');
  const target = resolve(targetDir);
  if (existsSync(target)) throw new Error(`refusing to overwrite existing run directory: ${target}`);
  mkdirSync(dirname(target), { recursive: true });
  const staging = mkdtempSync(join(dirname(target), `.${basename(target)}.staging-`));
  try {
    const built = buildM89OfficialRun(report, { rootDir: staging });
    put(staging, 'run.json', jsonBytes(built.run));
    verifyM89Shakedown(staging);
    renameSync(staging, target);
    return built.run;
  } finally {
    if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
  }
};

const loadSchemas = (root) => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  return {
    run: ajv.compile(readJson(join(root, 'p2/gate-b/equal-relation-arithmetic-run.v1.schema.json'))),
    engine: ajv.compile(readJson(join(root, 'p2/gate-b/equal-relation-arithmetic-engine-result.v1.schema.json'))),
    metric: ajv.compile(readJson(join(root, 'p2/gate-b/equal-relation-arithmetic-metric-report.v1.schema.json'))),
    summary: ajv.compile(readJson(join(root, 'p2/gate-b/equal-relation-arithmetic-cross-engine-summary.v1.schema.json'))),
  };
};
export const verifyM89Shakedown = (targetDir) => {
  const run = readJson(join(targetDir, 'run.json'));
  const descriptor = readJson(join(targetDir, 'inputs/descriptor.json'));
  const campaign = readJson(join(targetDir, 'inputs/campaign.json'));
  const schemas = loadSchemas(targetDir);
  const schemaErrors = [];
  if (!schemas.run(run)) schemaErrors.push(`run: ${JSON.stringify(schemas.run.errors)}`);
  for (const engineId of ['native', 'libauth', 'bchn', 'leanbch']) {
    const value = readJson(join(targetDir, `artifacts/${engineId}-result.json`));
    if (!schemas.engine(value)) schemaErrors.push(`${engineId}: ${JSON.stringify(schemas.engine.errors)}`);
  }
  for (const [name, path] of [['metric', 'artifacts/metric-report.json'], ['summary', 'artifacts/cross-engine-summary.json']]) {
    const value = readJson(join(targetDir, path));
    if (!schemas[name](value)) schemaErrors.push(`${name}: ${JSON.stringify(schemas[name].errors)}`);
  }
  const semanticErrors = validateArithmeticRun(run, descriptor, campaign, { rootDir: targetDir });
  if (schemaErrors.length || semanticErrors.length) throw new Error([...schemaErrors, ...semanticErrors].join('\n'));
  return { run, schemaErrors: [], semanticErrors: [] };
};

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const official = resolve(LANE_ROOT, M89_OFFICIAL_RUN);
  const args = new Set(process.argv.slice(2));
  if (args.has('--write')) {
    const report = buildM89ShakedownReport();
    materializeM89Shakedown(report, official);
    process.stdout.write(`${JSON.stringify(verifyM89Shakedown(official).run)}\n`);
  } else {
    if (!existsSync(join(official, 'run.json'))) throw new Error(`official run absent; use --write explicitly: ${official}`);
    verifyM89Shakedown(official);
    process.stdout.write(`verified ${official}\n`);
  }
}
