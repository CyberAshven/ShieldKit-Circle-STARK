#!/usr/bin/env node
/**
 * M89 Gate-B0 stdout-only cross-engine shakedown.
 *
 * This measures only the isolated synthetic one-input P2SH32 component
 * fixture. It is non-ranking and selection-free; full transaction-policy
 * admission is deliberately not inferred from the standard VM flag.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import {
  M89_CORPUS,
  buildM89ShakedownFixture,
  evaluateM89ShakedownCase,
} from './m89-shakedown-fixture.mjs';
import { evaluateCase as evaluateNativeCase } from '../reference/m89-corpus.mjs';

export const M89_RUN_DEFAULTS = Object.freeze({
  bchnLeg: process.env.BCHN_LEG
    ?? '/home/toorik/Projects/BCH/bch-conformance/legs/bchn/bchn-leg',
  leanCostprobe: process.env.LEANBCH_COSTPROBE
    ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/costprobe',
  leanVmbconf: process.env.LEANBCH_VMBCONF
    ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/vmbconf',
  timeoutMs: 120_000,
  leanHashRate: 192,
});

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sha256File = (path) => sha256(readFileSync(path));

export const rawFiveMetrics = (metrics) => ({
  evaluatedInstructionCount: metrics.evaluatedInstructionCount,
  signatureCheckCount: metrics.signatureCheckCount,
  hashDigestIterations: metrics.hashDigestIterations,
  arithmeticCost: metrics.arithmeticCost,
  stackPushedBytes: metrics.stackPushedBytes,
});

/** BCH-2026 standard op-cost derivation from the five raw VM metrics. */
export const deriveStandardOperationCost = (metrics, hashRate = 192) => (
  metrics.evaluatedInstructionCount * 100
  + metrics.signatureCheckCount * 26_000
  + metrics.hashDigestIterations * hashRate
  + metrics.arithmeticCost
  + metrics.stackPushedBytes
);

const expectedAccepted = (entry) => entry.expected.verdict === 'accept';
const metricEqual = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const acceptedRows = (rows) => rows.filter(({ entry }) => expectedAccepted(entry));
const rejectedRows = (rows) => rows.filter(({ entry }) => !expectedAccepted(entry));

const parseJsonLines = (stdout) => {
  const parsed = new Map();
  const errors = [];
  for (const line of stdout.split('\n')) {
    if (!line.startsWith('{')) continue;
    try {
      const item = JSON.parse(line);
      if (typeof item.ident !== 'string') errors.push('JSON row missing ident');
      else if (parsed.has(item.ident)) errors.push(`duplicate ident ${item.ident}`);
      else parsed.set(item.ident, item);
    } catch (error) {
      errors.push(String(error));
    }
  }
  return { parsed, errors };
};

export const parseBchnStdout = (stdout) => parseJsonLines(stdout);

export const parseLeanCostprobeStdout = (stdout) => {
  const parsed = new Map();
  const errors = [];
  for (const line of stdout.split('\n')) {
    const parts = line.trim().split(/\s+/u);
    if (parts[0] === 'METRICS' && parts.length === 9) {
      const [, id, verdict, instr, sigchecks, hashiters, arith, pushed, opCost] = parts;
      if (parsed.has(id)) errors.push(`duplicate ident ${id}`);
      else parsed.set(id, {
        status: 'measured',
        accepted: verdict === '1',
        rawMetrics: {
          evaluatedInstructionCount: Number(instr),
          signatureCheckCount: Number(sigchecks),
          hashDigestIterations: Number(hashiters),
          arithmeticCost: Number(arith),
          stackPushedBytes: Number(pushed),
        },
        nativeConsensus64OperationCost: Number(opCost),
      });
    } else if (parts[0] === 'SKIP' && parts.length >= 3) {
      const id = parts[1];
      if (parsed.has(id)) errors.push(`duplicate ident ${id}`);
      else parsed.set(id, {
        status: 'unsupported-reject-metrics', accepted: null, rawMetrics: null,
        nativeConsensus64OperationCost: null, reason: parts.slice(2).join(' '),
      });
    }
  }
  return {
    oracle: stdout.match(/^ORACLE (.+)$/mu)?.[1] ?? null,
    parsed,
    errors,
  };
};

const parseIdList = (stdout, label) => {
  const match = stdout.match(new RegExp(`^${label}: \\[(.*)\\]$`, 'mu'));
  if (match === null || match[1].trim() === '') return [];
  return match[1].split(', ').filter(Boolean);
};

export const parseVmbconfStdout = (stdout) => {
  const pass = stdout.match(/^PASS (\d+) \/ (\d+)$/mu);
  const rejectedValid = stdout.match(/^REJECTED-VALID (\d+):/mu);
  const acceptedInvalid = stdout.match(/^ACCEPTED-INVALID (\d+):/mu);
  const standard = stdout.match(/^STD-TRUE (\d+) STD-FALSE (\d+)$/mu);
  const standardTrue = standard === null ? null : Number(standard[1]);
  const standardFalse = standard === null ? null : Number(standard[2]);
  const standardTrueIds = parseIdList(stdout, 'STD-TRUE-IDS');
  const standardFalseIds = parseIdList(stdout, 'STD-FALSE-IDS');
  const standardIdListLimit = 200;
  return Object.freeze({
    oracle: stdout.match(/^ORACLE (.+)$/mu)?.[1] ?? null,
    passed: pass === null ? null : Number(pass[1]),
    total: pass === null ? null : Number(pass[2]),
    rejectedValid: rejectedValid === null ? null : Number(rejectedValid[1]),
    acceptedInvalid: acceptedInvalid === null ? null : Number(acceptedInvalid[1]),
    standardTrue,
    standardFalse,
    standardTrueIds,
    standardFalseIds,
    standardIdListLimit,
    standardTrueIdsTruncated: standardTrue !== null && standardTrue > standardTrueIds.length,
    standardFalseIdsTruncated: standardFalse !== null && standardFalse > standardFalseIds.length,
  });
};

export const buildExternalProcessEvidence = ({
  path, args = [], input = '', childStatus = null, stdout = '', stderr = '',
}) => ({
  executablePath: path,
  argv: [path, ...args],
  childStatus,
  stdinSha256: sha256(input),
  stdinBytes: Buffer.byteLength(input),
  stdoutText: stdout,
  stdoutSha256: sha256(stdout),
  stdoutBytes: Buffer.byteLength(stdout),
  stderrText: stderr,
  stderrSha256: sha256(stderr),
  stderrBytes: Buffer.byteLength(stderr),
});

const runProcess = ({ path, args, input, timeoutMs }) => {
  if (!existsSync(path)) return {
    status: 'blocked', error: `binary missing: ${path}`, parsed: new Map(), parseErrors: [],
    binarySha256: null, ...buildExternalProcessEvidence({ path, args, input }),
  };
  const child = spawnSync(path, args, { encoding: 'utf8', input, timeout: timeoutMs });
  const stdout = child.stdout ?? '';
  const stderr = child.stderr ?? '';
  return {
    ...buildExternalProcessEvidence({ path, args, input, childStatus: child.status, stdout, stderr }),
    status: child.status === 0 ? 'measured' : 'blocked',
    error: child.status === 0 ? null : `${path} exit=${child.status}: ${stderr.trim()}`,
    binarySha256: sha256File(path),
  };
};

const processReport = (process) => ({
  executablePath: process.executablePath ?? null,
  argv: process.argv ?? [],
  childStatus: process.childStatus ?? null,
  stdinSha256: process.stdinSha256 ?? null,
  stdinBytes: process.stdinBytes ?? null,
  stdoutText: process.stdoutText ?? '',
  stdoutSha256: process.stdoutSha256 ?? null,
  stdoutBytes: process.stdoutBytes ?? null,
  stderrText: process.stderrText ?? '',
  stderrSha256: process.stderrSha256 ?? null,
  stderrBytes: process.stderrBytes ?? null,
});

const runBchn = (rows, options) => {
  const inputRows = rows.map(({ entry, fixture }) => [
    fixture.fixtureId,
    'ShieldKit-LABS M89 Gate-B0 P2SH32 component', '', '',
    fixture.transactionHex, fixture.sourceOutputsHex, 0,
  ]);
  const process = runProcess({
    path: options.bchnLeg,
    args: ['--mode', 'standard'],
    input: `${JSON.stringify(inputRows)}\n`,
    timeoutMs: options.timeoutMs,
  });
  const parsed = parseBchnStdout(process.stdoutText ?? '');
  const complete = process.status === 'measured'
    && parsed.errors.length === 0
    && parsed.parsed.size === rows.length
    && rows.every(({ fixture }) => parsed.parsed.has(fixture.fixtureId));
  return Object.freeze({
    ...process,
    status: complete ? 'measured' : 'blocked',
    error: complete ? null : (process.error ?? `BCHN parsed ${parsed.parsed.size}/${rows.length}`),
    rows: parsed.parsed,
    parseErrors: parsed.errors,
  });
};

const runLeanCostprobe = (rows, options) => {
  const input = rows.map(({ entry, fixture }) => (
    `KERNEL ${fixture.fixtureId} ${fixture.transactionHex} ${fixture.sourceOutputsHex} 0`
  )).join('\n');
  const process = runProcess({
    path: options.leanCostprobe, args: [], input: `${input}\n`, timeoutMs: options.timeoutMs,
  });
  const parsed = parseLeanCostprobeStdout(process.stdoutText ?? '');
  const complete = process.status === 'measured'
    && parsed.errors.length === 0
    && parsed.parsed.size === rows.length
    && rows.every(({ fixture }) => parsed.parsed.has(fixture.fixtureId));
  return Object.freeze({
    ...process,
    status: complete ? 'measured' : 'blocked',
    error: complete ? null : (process.error ?? `costprobe parsed ${parsed.parsed.size}/${rows.length}`),
    oracle: parsed.oracle,
    rows: parsed.parsed,
    parseErrors: parsed.errors,
  });
};

const runVmbconf = (rows, options) => {
  const input = rows.map(({ entry, fixture }) => (
    `${expectedAccepted(entry) ? 1 : 0} ${fixture.fixtureId} ${fixture.transactionHex} ${fixture.sourceOutputsHex} 0`
  )).join('\n');
  const process = runProcess({
    path: options.leanVmbconf, args: [], input: `${input}\n`, timeoutMs: options.timeoutMs,
  });
  const parsed = parseVmbconfStdout(process.stdoutText ?? '');
  const complete = process.status === 'measured'
    && parsed.passed === rows.length && parsed.total === rows.length
    && parsed.rejectedValid === 0 && parsed.acceptedInvalid === 0
    && parsed.standardTrue !== null && parsed.standardFalse !== null
    && parsed.standardTrue + parsed.standardFalse === rows.length;
  return Object.freeze({
    ...process,
    status: complete ? 'measured' : 'blocked',
    error: complete ? null : (process.error ?? 'vmbconf did not provide complete verdict/standard coverage'),
    ...parsed,
  });
};

const buildRows = (corpus) => corpus.cases.map((entry) => {
  const fixture = buildM89ShakedownFixture(entry);
  const libauth = evaluateM89ShakedownCase(entry);
  const native = evaluateNativeCase(entry);
  return Object.freeze({ entry, fixture, native, libauth });
});

const bchnRow = (bchn, row) => {
  const external = bchn.rows.get(row.fixture.fixtureId);
  if (external === undefined) return {
    status: bchn.status, accepted: null, errorClass: null, nativeError: null,
    metrics: null, metricComparability: 'unavailable', rawExternal: null,
  };
  const accepted = external.outcome === 'accept';
  return {
    status: 'measured', accepted, errorClass: external.error_class,
    nativeError: external.native_error,
    metrics: {
      operationCost: external.op_cost,
      maximumOperationCost: external.op_cost_limit,
      hashDigestIterations: external.hash_iters,
      maximumHashDigestIterations: external.hash_iters_limit,
      signatureCheckCount: external.sig_checks,
      maximumSignatureCheckCount: external.sig_checks_limit,
    },
    metricComparability: accepted ? 'accepted-exposed-metrics' : 'reject-verdict-only-metrics-not-comparable',
    rawExternal: external,
  };
};

const leanRow = (lean, row, hashRate) => {
  const external = lean.rows.get(row.fixture.fixtureId);
  if (external === undefined) return {
    status: lean.status, accepted: null, rawMetrics: null,
    nativeConsensus64OperationCost: null, derivedStandard192OperationCost: null,
    metricComparability: 'unavailable',
  };
  if (external.status !== 'measured') return {
    ...external, derivedStandard192OperationCost: null,
    metricComparability: 'unsupported-reject-metrics-not-comparable',
  };
  return {
    ...external,
    derivedStandard192OperationCost: deriveStandardOperationCost(external.rawMetrics, hashRate),
    metricComparability: expectedAccepted(row.entry)
      ? 'accepted-raw-five-comparable' : 'reject-verdict-only-metrics-not-comparable',
  };
};

const caseReport = (row, bchn, lean, hashRate) => {
  const { entry, fixture, native, libauth } = row;
  const bchnResult = bchnRow(bchn, row);
  const leanResult = leanRow(lean, row, hashRate);
  const libauthRawFive = rawFiveMetrics(libauth.rawMetrics);
  const libauthExposed = {
    operationCost: libauth.rawMetrics.operationCost,
    hashDigestIterations: libauth.rawMetrics.hashDigestIterations,
    signatureCheckCount: libauth.rawMetrics.signatureCheckCount,
  };
  const expected = expectedAccepted(entry);
  return {
    id: fixture.fixtureId,
    relationId: entry.relationId,
    categoryId: entry.categoryId,
    caseIndex: entry.caseIndex,
    vectorAttempt: entry.vectorAttempt,
    expected: { verdict: entry.expected.verdict, stage: entry.expected.stage },
    native: { accepted: native.verdict === 'accept', verdict: native.verdict, stage: native.stage },
    artifacts: {
      sourceLockingHex: fixture.sourceLockingHex,
      sourceLockingBytes: fixture.sourceLockingBytes,
      sourceLockingSha256: sha256(Buffer.from(fixture.sourceLockingHex, 'hex')),
      unlockingHex: fixture.unlockingHex,
      unlockingBytes: fixture.unlockingBytes,
      unlockingSha256: fixture.wrapperDigestSha256,
      transactionHex: fixture.transactionHex,
      transactionBytes: fixture.transactionHex.length / 2,
      transactionSha256: fixture.transactionDigestSha256,
      sourceOutputsHex: fixture.sourceOutputsHex,
      sourceOutputsBytes: fixture.sourceOutputsHex.length / 2,
      sourceOutputsSha256: fixture.sourceOutputsDigestSha256,
      redeemHash256Hex: fixture.redeemHash256Hex,
      redeemDigestSha256: fixture.redeemDigestSha256,
      redeemBytes: fixture.redeemBytes,
    },
    policyBoundary: {
      standardVmRules: libauth.standardVmRules,
      fullTransactionPolicy: 'not-evaluated',
      evidenceBoundary: 'isolated-synthetic-one-input-p2sh32-component-only',
    },
    libauth: {
      accepted: libauth.accepted, error: libauth.error,
      rawFiveMetrics: libauthRawFive,
      rawMetrics: libauth.rawMetrics,
      exposed: libauthExposed,
      traceLength: libauth.traceLength,
      opcodeHistogram: libauth.opcodeHistogram,
      mulByteProduct: libauth.mulByteProduct,
      divByteProduct: libauth.divByteProduct,
      modByteProduct: libauth.modByteProduct,
      resultPushBytes: libauth.resultPushBytes,
      arithmeticCounts: libauth.arithmeticCounts,
      standardnessByteSizes: libauth.standardnessByteSizes,
      stackMaximums: libauth.stackMaximums,
      elementMax: libauth.elementMax,
    },
    bchn: bchnResult,
    leanbch: leanResult,
    comparisons: {
      nativeExpected: (native.verdict === 'accept') === expected,
      libauthExpected: libauth.accepted === expected,
      bchnExpected: bchnResult.accepted === null ? null : bchnResult.accepted === expected,
      leanExpected: leanResult.accepted === null ? null : leanResult.accepted === expected,
      leanRawFiveMatchesLibauth: expected && leanResult.rawMetrics !== null
        ? metricEqual(leanResult.rawMetrics, libauthRawFive) : null,
      leanStandardOpCostMatchesLibauth: expected && leanResult.derivedStandard192OperationCost !== null
        ? leanResult.derivedStandard192OperationCost === libauthExposed.operationCost : null,
      bchnExposedMatchesLibauth: expected && bchnResult.metrics !== null
        ? bchnResult.metrics.operationCost === libauthExposed.operationCost
          && bchnResult.metrics.hashDigestIterations === libauthExposed.hashDigestIterations
          && bchnResult.metrics.signatureCheckCount === libauthExposed.signatureCheckCount : null,
    },
  };
};

export const buildM89ShakedownReport = ({
  corpus = M89_CORPUS,
  runExternal = true,
  options = M89_RUN_DEFAULTS,
} = {}) => {
  const rows = buildRows(corpus);
  const bchn = runExternal ? runBchn(rows, options) : { status: 'not-run', rows: new Map(), error: null };
  const lean = runExternal ? runLeanCostprobe(rows, options) : { status: 'not-run', rows: new Map(), error: null };
  const vmbconf = runExternal ? runVmbconf(rows, options) : { status: 'not-run', error: null };
  const cases = rows.map((row) => caseReport(row, bchn, lean, options.leanHashRate));
  const accepted = cases.filter(({ expected }) => expected.verdict === 'accept');
  const rejected = cases.filter(({ expected }) => expected.verdict === 'reject');
  const blockers = [bchn, lean, vmbconf].filter(({ status }) => status === 'blocked').map(({ error }) => error);
  const libauthAll = cases.every(({ comparisons }) => comparisons.libauthExpected);
  const nativeAll = cases.every(({ comparisons }) => comparisons.nativeExpected);
  const bchnAll = bchn.status === 'measured' && cases.every(({ comparisons }) => comparisons.bchnExpected === true);
  // vmbconf is the authoritative full Lean verdict surface. CostProbe is a
  // metrics probe; its reject rows may be SKIP/null and never replace vmbconf.
  const leanAll = vmbconf.status === 'measured';
  const leanCostAcceptedVerdicts = accepted.every(({ comparisons }) => comparisons.leanExpected === true);
  const acceptedLeanRaw = accepted.every(({ comparisons }) => comparisons.leanRawFiveMatchesLibauth === true);
  const acceptedLeanOp = accepted.every(({ comparisons }) => comparisons.leanStandardOpCostMatchesLibauth === true);
  const acceptedBchnMetrics = accepted.every(({ comparisons }) => comparisons.bchnExposedMatchesLibauth === true);
  const status = !runExternal ? 'not-run'
    : blockers.length > 0 ? 'blocked'
      : nativeAll && libauthAll && bchnAll && leanAll && leanCostAcceptedVerdicts && acceptedLeanRaw && acceptedLeanOp && acceptedBchnMetrics
        ? 'measured-component-only-pass' : 'measured-component-only-fail';
  return {
    schema: 'shieldkit-labs/p2/m89-gate-b0-shakedown-run/v1',
    status,
    selection: 'none',
    evidenceBoundary: 'isolated-synthetic-one-input-p2sh32-component-fixture-only; non-ranking; no full-transaction-policy qualification',
    standardVmRules: 'Libauth/BCHN/LeanBCH standard VM mode where exposed; not a full transaction-policy verdict',
    fullTransactionPolicy: 'not-evaluated',
    corpus: { totalCases: cases.length, expectedAccepted: accepted.length, expectedRejected: rejected.length },
    verdictAgreement: {
      nativeAllExpected: nativeAll,
      libauthAllExpected: libauthAll,
      bchnAllExpected: bchnAll,
      leanAllExpected: leanAll,
      leanCostprobeAcceptedRowsExpected: leanCostAcceptedVerdicts,
      vmbconfFullVerdictCoverage: vmbconf.status === 'measured',
    },
    metricCoverage: {
      acceptedRows: accepted.length,
      rejectedRows: rejected.length,
      leanRawFiveComparedAcceptedRows: accepted.filter(({ leanbch }) => leanbch.rawMetrics !== null).length,
      bchnExposedComparedAcceptedRows: accepted.filter(({ bchn: item }) => item.metrics !== null).length,
      leanCostprobeUnsupportedOrSkippedRejectRows: rejected.filter(({ leanbch }) => leanbch.accepted === null).length,
      rejectMetricsPolicy: 'unsupported-or-reject metrics are retained but never used as pass/fail comparisons',
    },
    engines: {
      native: { status: 'measured', cases: cases.length },
      libauth: { status: 'measured', cases: cases.length, mode: 'standard-vm-rules' },
      bchn: { status: bchn.status, ...processReport(bchn), binarySha256: bchn.binarySha256 ?? null, error: bchn.error ?? null },
      leanbchCostprobe: { status: lean.status, hashRate: options.leanHashRate, oracle: lean.oracle ?? null, ...processReport(lean), binarySha256: lean.binarySha256 ?? null, error: lean.error ?? null },
      leanbchVmbconf: { status: vmbconf.status, ...processReport(vmbconf), binarySha256: vmbconf.binarySha256 ?? null, error: vmbconf.error ?? null, oracle: vmbconf.oracle ?? null, passed: vmbconf.passed ?? null, total: vmbconf.total ?? null, rejectedValid: vmbconf.rejectedValid ?? null, acceptedInvalid: vmbconf.acceptedInvalid ?? null, standardTrue: vmbconf.standardTrue ?? null, standardFalse: vmbconf.standardFalse ?? null, standardTrueIds: vmbconf.standardTrueIds ?? [], standardFalseIds: vmbconf.standardFalseIds ?? [], standardIdListLimit: vmbconf.standardIdListLimit ?? 200, standardTrueIdsTruncated: vmbconf.standardTrueIdsTruncated ?? null, standardFalseIdsTruncated: vmbconf.standardFalseIdsTruncated ?? null },
    },
    aggregateComparisons: { acceptedLeanRawFive: acceptedLeanRaw, acceptedLeanStandardOpCost: acceptedLeanOp, acceptedLeanCostprobeVerdicts: leanCostAcceptedVerdicts, acceptedBchnExposedMetrics: acceptedBchnMetrics },
    blockers,
    cases,
  };
};

const isMain = process.argv[1] !== undefined
  && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const report = buildM89ShakedownReport();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.status === 'blocked' || report.status === 'measured-component-only-fail') process.exitCode = 1;
}
