#!/usr/bin/env node
/**
 * Deterministic cross-engine runner for the complete neutral-M31 base corpus.
 *
 * This is evidence for these isolated Script relations only. It does not claim
 * a complete base gate, extension field, AIR, proof verifier, or covenant.
 */

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';

import {
  M31_FULL_BASE_CASES,
  M31_FULL_BASE_CORPUS_SHA256,
  encodeFullBaseTransactionFixture,
  evaluateFullBaseCase,
  materializeFullBaseCase,
  rawInputHexForFullBaseCase,
} from './base-suite.mjs';
import { rawMetricProjection } from './m31-kernel.mjs';

const bchnLeg = process.env.BCHN_LEG
  ?? '/home/toorik/Projects/BCH/bch-conformance/legs/bchn/bchn-leg';
const leanCostprobe = process.env.LEANBCH_COSTPROBE
  ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/costprobe';
const leanVmbconf = process.env.LEANBCH_VMBCONF
  ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/vmbconf';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sha256File = (path) => sha256(readFileSync(path));
const rawMetrics = (metrics) => rawMetricProjection(metrics);

const operationCounts = (rows) => Object.fromEntries([...new Set(rows.map(({ entry }) => entry.operation))]
  .sort()
  .map((operation) => {
    const group = rows.filter(({ entry }) => entry.operation === operation);
    return [operation, {
      cases: group.length,
      expectedAccept: group.filter(({ entry }) => entry.accepted).length,
      expectedReject: group.filter(({ entry }) => !entry.accepted).length,
      libauthVerdictsMatch: group.every(({ entry, libauth }) => libauth.accepted === entry.accepted),
    }];
  }));

const rows = M31_FULL_BASE_CASES.map((entry) => {
  const fixture = materializeFullBaseCase(entry);
  const libauth = evaluateFullBaseCase(entry);
  return Object.freeze({
    entry,
    fixture,
    libauth,
    wires: encodeFullBaseTransactionFixture(entry),
    rawInputHex: rawInputHexForFullBaseCase(entry),
  });
});

const runBchn = () => {
  if (!existsSync(bchnLeg)) return { status: 'blocked', error: `BCHN leg missing: ${bchnLeg}`, rows: new Map() };
  const pack = rows.map(({ entry, wires }) => [
    entry.id,
    'ShieldKit-LABS M31 base-operation relation',
    '',
    '',
    wires.transactionHex,
    wires.sourceOutputsHex,
    0,
  ]);
  const child = spawnSync(bchnLeg, ['--mode', 'standard'], {
    encoding: 'utf8', input: `${JSON.stringify(pack)}\n`, timeout: 30_000,
  });
  const parsed = new Map();
  const parseErrors = [];
  for (const line of (child.stdout ?? '').trim().split('\n')) {
    if (!line.startsWith('{')) continue;
    try {
      const item = JSON.parse(line);
      if (typeof item.ident === 'string') parsed.set(item.ident, item);
    } catch (error) {
      parseErrors.push(String(error));
    }
  }
  const complete = child.status === 0 && parsed.size === rows.length && parseErrors.length === 0;
  return {
    status: complete ? 'measured' : 'blocked',
    error: complete ? null : `BCHN --mode standard exit=${child.status}; parsed=${parsed.size}/${rows.length}; ${(child.stderr ?? '').trim()}`,
    rows: parsed,
    binarySha256: sha256File(bchnLeg),
    stdoutSha256: sha256(child.stdout ?? ''),
    stderrSha256: sha256(child.stderr ?? ''),
  };
};

const parseCostprobe = (stdout) => {
  const parsed = new Map();
  for (const line of stdout.trim().split('\n')) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] === 'METRICS' && parts.length === 9) {
      const [, id, verdict, instr, sigchecks, hashiters, arith, pushed, opCost] = parts;
      parsed.set(id, {
        status: 'measured', accepted: verdict === '1',
        metrics: {
          evaluatedInstructionCount: Number(instr), signatureCheckCount: Number(sigchecks),
          hashDigestIterations: Number(hashiters), arithmeticCost: Number(arith),
          stackPushedBytes: Number(pushed), operationCost: Number(opCost),
        },
      });
    } else if (parts[0] === 'SKIP' && parts.length >= 3) {
      parsed.set(parts[1], { status: 'unsupported-reject-metrics', accepted: null, metrics: null, reason: parts.slice(2).join(' ') });
    }
  }
  return parsed;
};

const runLeanCost = () => {
  if (!existsSync(leanCostprobe)) return { status: 'blocked', error: `LeanBCH costprobe missing: ${leanCostprobe}`, rows: new Map() };
  const input = rows.map(({ entry, wires }) => `KERNEL ${entry.id} ${wires.transactionHex} ${wires.sourceOutputsHex} 0`).join('\n');
  const child = spawnSync(leanCostprobe, [], { encoding: 'utf8', input: `${input}\n`, timeout: 30_000 });
  const parsed = parseCostprobe(child.stdout ?? '');
  const complete = child.status === 0 && parsed.size === rows.length;
  return {
    status: complete ? 'measured-partial' : 'blocked',
    error: complete ? null : `costprobe exit=${child.status}; parsed=${parsed.size}/${rows.length}: ${(child.stderr ?? '').trim()}`,
    rows: parsed,
    binarySha256: sha256File(leanCostprobe),
    stdoutSha256: sha256(child.stdout ?? ''),
    stderrSha256: sha256(child.stderr ?? ''),
  };
};

const runVmbconf = () => {
  if (!existsSync(leanVmbconf)) return { status: 'blocked', error: `LeanBCH vmbconf missing: ${leanVmbconf}` };
  const input = rows.map(({ entry, wires }) => `${entry.accepted ? 1 : 0} ${entry.id} ${wires.transactionHex} ${wires.sourceOutputsHex} 0`).join('\n');
  const child = spawnSync(leanVmbconf, [], { encoding: 'utf8', input: `${input}\n`, timeout: 30_000 });
  const stdout = child.stdout ?? '';
  const pass = stdout.match(/^PASS (\d+) \/ (\d+)$/m);
  const rejectedValid = stdout.match(/^REJECTED-VALID (\d+): (.+)$/m);
  const acceptedInvalid = stdout.match(/^ACCEPTED-INVALID (\d+): (.+)$/m);
  const standard = stdout.match(/^STD-TRUE (\d+) STD-FALSE (\d+)$/m);
  const complete = child.status === 0 && pass !== null && Number(pass[2]) === rows.length;
  return {
    status: complete ? 'measured' : 'blocked',
    error: complete ? null : `vmbconf exit=${child.status}: ${(child.stderr ?? '').trim()}`,
    oracle: stdout.match(/^ORACLE (.+)$/m)?.[1] ?? null,
    passed: pass === null ? null : Number(pass[1]),
    total: pass === null ? null : Number(pass[2]),
    rejectedValid: rejectedValid === null ? null : Number(rejectedValid[1]),
    acceptedInvalid: acceptedInvalid === null ? null : Number(acceptedInvalid[1]),
    standardTrue: standard === null ? null : Number(standard[1]),
    standardFalse: standard === null ? null : Number(standard[2]),
    binarySha256: sha256File(leanVmbconf),
    stdoutSha256: sha256(stdout),
    stderrSha256: sha256(child.stderr ?? ''),
  };
};

const bchn = runBchn();
const leanCost = runLeanCost();
const vmbconf = runVmbconf();

const relationProjection = (entry) => Object.fromEntries(Object.entries(entry)
  .filter(([key, value]) => !key.startsWith('raw') && key !== 'decoderSignByteMutationOrdinal' && typeof value !== 'object')
  .map(([key, value]) => [key, typeof value === 'bigint' ? value.toString() : value]));

const caseReports = rows.map(({ entry, fixture, libauth, wires, rawInputHex }) => {
  const bchnRow = bchn.rows.get(entry.id);
  const leanRow = leanCost.rows.get(entry.id) ?? {
    status: leanCost.status === 'blocked' ? 'blocked' : 'unsupported', accepted: null, metrics: null,
  };
  const bchnAccepted = bchnRow === undefined ? null : bchnRow.outcome === 'accept';
  const bchnMetrics = bchnRow === undefined ? null : {
    operationCost: bchnRow.op_cost,
    maximumOperationCost: bchnRow.op_cost_limit,
    hashDigestIterations: bchnRow.hash_iters,
    maximumHashDigestIterations: bchnRow.hash_iters_limit,
    signatureCheckCount: bchnRow.sig_checks,
    maximumSignatureCheckCount: bchnRow.sig_checks_limit,
  };
  return {
    id: entry.id,
    operation: entry.operation,
    expectedAccepted: entry.accepted,
    expectedRelation: relationProjection(entry),
    rawInputHex,
    standardMode: true,
    ruleEpoch: 'BCH-2026',
    artifacts: {
      lockingHex: libauth.lockingHex,
      lockingBytes: fixture.lockingBytecode.length,
      lockingSha256: libauth.lockingDigestSha256,
      unlockingHex: libauth.unlockingHex,
      unlockingBytes: fixture.unlockingBytecode.length,
      unlockingSha256: libauth.unlockingDigestSha256,
      transactionHex: wires.transactionHex,
      transactionBytes: wires.transactionHex.length / 2,
      transactionSha256: wires.transactionDigestSha256,
      sourceOutputsHex: wires.sourceOutputsHex,
      sourceOutputsBytes: wires.sourceOutputsHex.length / 2,
      sourceOutputsSha256: wires.sourceOutputsDigestSha256,
    },
    libauth: { accepted: libauth.accepted, error: libauth.error, metrics: libauth.metrics },
    bchn: bchnRow === undefined ? { status: bchn.status, accepted: null, metrics: null } : {
      status: 'measured', accepted: bchnAccepted, errorClass: bchnRow.error_class,
      nativeError: bchnRow.native_error, metrics: bchnMetrics,
      metricSupport: entry.accepted ? 'exposed-accept-metrics' : 'verdict-only-reject-metrics-not-comparable',
    },
    leanbchCost: leanRow,
    verdictAgreement: {
      libauthExpected: libauth.accepted === entry.accepted,
      bchnExpected: bchnAccepted === null ? null : bchnAccepted === entry.accepted,
      leanCostExpected: leanRow.accepted === null ? null : leanRow.accepted === entry.accepted,
    },
  };
});

const libauthAll = caseReports.every(({ verdictAgreement }) => verdictAgreement.libauthExpected);
const bchnAll = bchn.status === 'measured' && caseReports.every(({ verdictAgreement }) => verdictAgreement.bchnExpected === true);
const vmbconfAll = vmbconf.status === 'measured'
  && vmbconf.passed === rows.length && vmbconf.total === rows.length
  && vmbconf.rejectedValid === 0 && vmbconf.acceptedInvalid === 0;
const leanMetricRows = caseReports.filter(({ leanbchCost }) => leanbchCost.status === 'measured');
const leanUnsupportedRows = caseReports.filter(({ leanbchCost }) => leanbchCost.status !== 'measured');
const leanMeasuredAgreement = leanMetricRows.every(({ libauth, leanbchCost }) => (
  leanbchCost.accepted === libauth.accepted
  && JSON.stringify(leanbchCost.metrics) === JSON.stringify(rawMetrics(libauth.metrics))
));
const leanCoverage = leanCost.status === 'measured-partial' && caseReports.every((row) => (
  (row.leanbchCost.status === 'measured'
    && row.leanbchCost.accepted === row.libauth.accepted
    && JSON.stringify(row.leanbchCost.metrics) === JSON.stringify(rawMetrics(row.libauth.metrics)))
  || (row.leanbchCost.status === 'unsupported-reject-metrics'
    && row.expectedAccepted === false
    && row.libauth.accepted === false)
));

const counts = operationCounts(rows);
for (const [operation, count] of Object.entries(counts)) {
  const group = caseReports.filter((row) => row.operation === operation);
  count.bchnVerdictsMatch = bchn.status === 'measured' && group.every(({ verdictAgreement }) => verdictAgreement.bchnExpected === true);
  count.leanMeasuredMetricRows = group.filter(({ leanbchCost }) => leanbchCost.status === 'measured').length;
  count.leanMetricUnsupportedOrBlocked = group.length - count.leanMeasuredMetricRows;
}

const blockers = [
  ...(bchn.status === 'measured' ? [] : [bchn.error]),
  ...(vmbconf.status === 'measured' ? [] : [vmbconf.error]),
  ...(leanCost.status === 'blocked' ? [leanCost.error] : []),
].filter((value) => value !== null && value !== undefined);
const completeNeutralBasePass = libauthAll && bchnAll && vmbconfAll && leanMeasuredAgreement && leanCoverage;
const libauthCorpusSha256 = sha256(JSON.stringify(caseReports.map((row) => ({
  id: row.id,
  accepted: row.libauth.accepted,
  error: row.libauth.error,
  metrics: row.libauth.metrics,
}))));

const report = {
  schema: 'shieldkit-labs/p2/m31-base-cross-engine-run/v2',
  status: completeNeutralBasePass ? 'measured-neutral-base-corpus' : 'failed-or-blocked',
  standardMode: true,
  firstAttempt: true,
  corpus: {
    sourceSha256: M31_FULL_BASE_CORPUS_SHA256,
    deterministicGenerator: 'SplitMix64',
    seedHex: '0123456789abcdef',
    totalCases: rows.length,
  },
  evidenceBoundary: 'Canonical fixed4 decoding and isolated neutral-M31 add, subtract, negate, multiply, square, and inverse-hint relations only; no extension, Circle domain, hash, AIR, proof, covenant, deployment, or full-transaction qualification claim.',
  caseCountsByOperation: counts,
  verdictAgreement: {
    expectedCaseCount: rows.length,
    libauthAllExpected: libauthAll,
    bchnStandardAllExpected: bchnAll,
    vmbconfAllExpected: vmbconfAll,
    leanCostMeasuredRowsMatchLibauthRawMetrics: leanMeasuredAgreement,
    leanCostCoverageComplete: leanCoverage,
  },
  metricSupport: {
    libauth: { status: 'measured', fields: ['evaluatedInstructionCount', 'signatureCheckCount', 'hashDigestIterations', 'arithmeticCost', 'stackPushedBytes', 'operationCost'], cases: rows.length },
    bchn: { status: bchn.status, exposedFields: ['signatureCheckCount', 'hashDigestIterations', 'operationCost'], acceptedRows: rows.filter(({ entry }) => entry.accepted).length, rejectGap: 'BCHN leg rejection counters are verdict-only and not treated as comparable metrics.' },
    leanbchCostprobe: { status: leanCost.status, measuredRows: leanMetricRows.length, unsupportedOrBlockedRows: leanUnsupportedRows.length, fieldsWhenMeasured: ['evaluatedInstructionCount', 'signatureCheckCount', 'hashDigestIterations', 'arithmeticCost', 'stackPushedBytes', 'operationCost'] },
    vmbconf: { status: vmbconf.status, role: 'all expected verdicts; no per-case cost metrics' },
  },
  engines: {
    libauth: { status: 'measured', version: '3.1.0-next.8', mode: 'standard BCH-2026', cases: rows.length, corpusSha256: libauthCorpusSha256 },
    bchn: { status: bchn.status, mode: 'standard', error: bchn.error ?? null, binarySha256: bchn.binarySha256 ?? null, stdoutSha256: bchn.stdoutSha256 ?? null, stderrSha256: bchn.stderrSha256 ?? null },
    leanbchCostprobe: { status: leanCost.status, error: leanCost.error ?? null, binarySha256: leanCost.binarySha256 ?? null, stdoutSha256: leanCost.stdoutSha256 ?? null, stderrSha256: leanCost.stderrSha256 ?? null },
    vmbconf: { status: vmbconf.status, error: vmbconf.error ?? null, oracle: vmbconf.oracle ?? null, passed: vmbconf.passed ?? null, total: vmbconf.total ?? null, rejectedValid: vmbconf.rejectedValid ?? null, acceptedInvalid: vmbconf.acceptedInvalid ?? null, standardTrue: vmbconf.standardTrue ?? null, standardFalse: vmbconf.standardFalse ?? null, binarySha256: vmbconf.binarySha256 ?? null, stdoutSha256: vmbconf.stdoutSha256 ?? null, stderrSha256: vmbconf.stderrSha256 ?? null },
  },
  blockers,
  cases: caseReports,
};

if (process.argv.includes('--summary')) {
  console.log(JSON.stringify({
    schema: report.schema,
    status: report.status,
    firstAttempt: report.firstAttempt,
    corpus: report.corpus,
    evidenceBoundary: report.evidenceBoundary,
    caseCountsByOperation: report.caseCountsByOperation,
    verdictAgreement: report.verdictAgreement,
    metricSupport: report.metricSupport,
    engines: report.engines,
    blockers: report.blockers,
  }, null, 2));
} else {
  console.log(JSON.stringify(report, null, 2));
}

if (!completeNeutralBasePass) process.exitCode = 1;
