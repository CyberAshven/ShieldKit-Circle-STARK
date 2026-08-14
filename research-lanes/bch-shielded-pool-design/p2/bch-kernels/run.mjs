#!/usr/bin/env node
/** Emit deterministic Libauth, BCHN, and LeanBCH evidence for the M31 multiply control. */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

import { classifyBound, decompose, measureRun } from '/home/toorik/Projects/ZK-Proofs/LeanBCH/optimizer/cost.mjs';

import {
  M31_KERNEL_CASES,
  bytesToHex,
  encodeM31,
  encodeM31MulTransactionFixture,
  evaluateM31Mul,
  materializeM31Case,
  rawMetricProjection,
} from './m31-kernel.mjs';

const leanCostprobe = process.env.LEANBCH_COSTPROBE
  ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/costprobe';
const leanVmbconf = process.env.LEANBCH_VMBCONF
  ?? '/home/toorik/Projects/ZK-Proofs/LeanBCH/.lake/build/bin/vmbconf';
const bchnLeg = process.env.BCHN_LEG
  ?? '/home/toorik/Projects/BCH/bch-conformance/legs/bchn/bchn-leg';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha256File = (path) => sha256(readFileSync(path));
const sameRawMetrics = (left, right) => JSON.stringify(rawMetricProjection(left)) === JSON.stringify(rawMetricProjection(right));

const rawElement = (entry, key, rawKey) => entry[rawKey] ?? encodeM31(entry[key]);

const rows = M31_KERNEL_CASES.map((entry) => {
  const fixture = materializeM31Case(entry);
  return {
    entry,
    fixture,
    libauth: evaluateM31Mul(fixture),
    wires: encodeM31MulTransactionFixture(fixture),
    inputHex: {
      a: bytesToHex(rawElement(entry, 'a', 'rawA')),
      b: bytesToHex(rawElement(entry, 'b', 'rawB')),
      product: bytesToHex(rawElement(entry, 'product', 'rawProduct')),
    },
  };
});

const primary = rows.find(({ entry }) => entry.id === 'm31-product-boundary');
if (primary === undefined) throw new Error('missing m31-product-boundary');

const runBchn = () => {
  if (!existsSync(bchnLeg)) return { status: 'blocked', error: `BCHN leg missing: ${bchnLeg}`, rows: new Map() };
  const pack = rows.map(({ entry, wires }) => [
    entry.id,
    'ShieldKit-LABS M31 fixed4 multiplication control',
    '',
    '',
    wires.transactionHex,
    wires.sourceOutputsHex,
    0,
  ]);
  const child = spawnSync(bchnLeg, ['--mode', 'standard'], {
    encoding: 'utf8',
    input: `${JSON.stringify(pack)}\n`,
    timeout: 30_000,
  });
  const parsed = new Map();
  for (const line of (child.stdout ?? '').trim().split('\n')) {
    if (!line.startsWith('{')) continue;
    const item = JSON.parse(line);
    parsed.set(item.ident, item);
  }
  const complete = child.status === 0 && parsed.size === rows.length;
  return {
    status: complete ? 'measured' : 'blocked',
    error: complete ? null : `BCHN leg exit=${child.status}; parsed=${parsed.size}/${rows.length}; ${(child.stderr ?? '').trim()}`,
    rows: parsed,
    stdoutSha256: sha256(child.stdout ?? ''),
    stderrSha256: sha256(child.stderr ?? ''),
    binarySha256: sha256File(bchnLeg),
  };
};

const parseLeanCostRows = (stdout) => {
  const parsed = new Map();
  for (const line of stdout.trim().split('\n')) {
    const parts = line.split(' ');
    if (parts[0] === 'METRICS' && parts.length === 9) {
      const [, id, verdict, instr, sigchecks, hashiters, arith, pushed, opCost] = parts;
      parsed.set(id, {
        status: 'measured',
        accepted: verdict === '1',
        metrics: {
          evaluatedInstructionCount: Number(instr),
          signatureCheckCount: Number(sigchecks),
          hashDigestIterations: Number(hashiters),
          arithmeticCost: Number(arith),
          stackPushedBytes: Number(pushed),
          operationCost: Number(opCost),
        },
      });
    } else if (parts[0] === 'SKIP' && parts.length >= 3) {
      parsed.set(parts[1], { status: 'unsupported-reject-metrics', accepted: null, metrics: null, reason: parts.slice(2).join(' ') });
    }
  }
  return parsed;
};

const runLean = () => {
  const input = rows.map(({ entry, wires }) => `KERNEL ${entry.id} ${wires.transactionHex} ${wires.sourceOutputsHex} 0`).join('\n');
  let cost;
  if (!existsSync(leanCostprobe)) {
    cost = { status: 'blocked', error: `costprobe missing: ${leanCostprobe}`, rows: new Map() };
  } else {
    const child = spawnSync(leanCostprobe, [], { encoding: 'utf8', input: `${input}\n`, timeout: 30_000 });
    const parsed = parseLeanCostRows(child.stdout ?? '');
    cost = {
      status: child.status === 0 ? 'measured-partial' : 'blocked',
      error: child.status === 0 ? null : `costprobe exit=${child.status}: ${(child.stderr ?? '').trim()}`,
      rows: parsed,
      stdoutSha256: sha256(child.stdout ?? ''),
      binarySha256: sha256File(leanCostprobe),
    };
  }

  const verdictInput = rows.map(({ entry, wires }) => `${entry.accepted ? 1 : 0} ${entry.id} ${wires.transactionHex} ${wires.sourceOutputsHex} 0`).join('\n');
  let verdict;
  if (!existsSync(leanVmbconf)) {
    verdict = { status: 'blocked', error: `vmbconf missing: ${leanVmbconf}` };
  } else {
    const child = spawnSync(leanVmbconf, [], { encoding: 'utf8', input: `${verdictInput}\n`, timeout: 30_000 });
    const match = (child.stdout ?? '').match(/^PASS (\d+) \/ (\d+)$/m);
    const oracle = (child.stdout ?? '').match(/^ORACLE (.+)$/m)?.[1] ?? null;
    const standard = (child.stdout ?? '').match(/^STD-TRUE (\d+) STD-FALSE (\d+)$/m);
    verdict = {
      status: child.status === 0 && match !== null ? 'measured' : 'blocked',
      error: child.status === 0 && match !== null ? null : `vmbconf exit=${child.status}: ${(child.stderr ?? '').trim()}`,
      oracle,
      passed: match === null ? null : Number(match[1]),
      total: match === null ? null : Number(match[2]),
      standardTrue: standard === null ? null : Number(standard[1]),
      standardFalse: standard === null ? null : Number(standard[2]),
      stdoutSha256: sha256(child.stdout ?? ''),
      binarySha256: sha256File(leanVmbconf),
    };
  }
  return { cost, verdict };
};

const bchn = runBchn();
const leanbch = runLean();
const looseDiagnostic = measureRun(primary.fixture.lockingBytecode, primary.fixture.unlockingBytecode);

const caseReports = rows.map(({ entry, libauth, wires, inputHex }) => {
  const bchnRow = bchn.rows.get(entry.id);
  const leanCost = leanbch.cost.rows.get(entry.id);
  return {
    id: entry.id,
    inputHex,
    expectedAccepted: entry.accepted,
    lockingHex: libauth.lockingHex,
    unlockingHex: libauth.unlockingHex,
    transactionHex: wires.transactionHex,
    sourceOutputsHex: wires.sourceOutputsHex,
    libauth: {
      accepted: libauth.accepted,
      error: libauth.error,
      metrics: libauth.metrics,
    },
    bchn: bchnRow === undefined ? null : {
      accepted: bchnRow.outcome === 'accept',
      errorClass: bchnRow.error_class,
      nativeError: bchnRow.native_error,
      operationCost: bchnRow.op_cost,
      maximumOperationCost: bchnRow.op_cost_limit,
      hashDigestIterations: bchnRow.hash_iters,
      maximumHashDigestIterations: bchnRow.hash_iters_limit,
      signatureCheckCount: bchnRow.sig_checks,
      maximumSignatureCheckCount: bchnRow.sig_checks_limit,
    },
    leanbchCost: leanCost ?? null,
  };
});

const libauthPass = caseReports.every((row) => row.libauth.accepted === row.expectedAccepted);
const bchnPass = bchn.status === 'measured'
  && caseReports.every((row) => row.bchn?.accepted === row.expectedAccepted);
const leanVerdictPass = leanbch.verdict.status === 'measured'
  && leanbch.verdict.passed === rows.length
  && leanbch.verdict.total === rows.length;
const primaryLean = leanbch.cost.rows.get(primary.entry.id);
const primaryBchn = bchn.rows.get(primary.entry.id);
const primaryRawAgreement = primaryLean?.status === 'measured'
  && primaryLean.accepted === primary.libauth.accepted
  && sameRawMetrics(primaryLean.metrics, primary.libauth.metrics);
const primaryBchnAgreement = primaryBchn !== undefined
  && (primaryBchn.outcome === 'accept') === primary.libauth.accepted
  && primaryBchn.op_cost === primary.libauth.metrics.operationCost
  && primaryBchn.hash_iters === primary.libauth.metrics.hashDigestIterations
  && primaryBchn.sig_checks === primary.libauth.metrics.signatureCheckCount;
const crossEnginePass = libauthPass && bchnPass && leanVerdictPass && primaryRawAgreement && primaryBchnAgreement;

const report = {
  schema: 'shieldkit-labs/p2/m31-bch-kernel-run/v2',
  status: crossEnginePass ? 'measured-partial' : 'failed-or-blocked',
  candidateId: 'field:m31-base-control',
  primitive: 'canonical-fixed-4-byte-le-m31-multiply',
  standardMode: true,
  locking: {
    hex: primary.libauth.lockingHex,
    bytes: primary.libauth.lockingHex.length / 2,
    sha256: primary.libauth.lockingDigestSha256,
  },
  primaryBoundaryFixture: {
    aHex: 'feffff7f',
    bHex: 'feffff7f',
    productHex: '01000000',
    unlockingHex: primary.libauth.unlockingHex,
    unlockingBytes: primary.libauth.unlockingHex.length / 2,
    unlockingSha256: primary.libauth.unlockingDigestSha256,
    ...primary.wires,
    metrics: primary.libauth.metrics,
  },
  crossEngine: {
    status: crossEnginePass ? 'pass-for-this-multiply-control' : 'fail-or-blocked',
    libauthAllCasesMatch: libauthPass,
    bchnAllCasesMatch: bchnPass,
    leanbchAllVerdictsMatch: leanVerdictPass,
    primaryLibauthLeanRawMetricsMatch: primaryRawAgreement,
    primaryLibauthBchnExposedMetricsMatch: primaryBchnAgreement,
  },
  engines: {
    libauth: { status: 'measured', version: '3.1.0-next.8', standard: true, accepted: primary.libauth.accepted, metrics: primary.libauth.metrics },
    bchn: {
      status: bchn.status,
      version: '864c53ee34924cca6c6b6d96607ff2cedcdccf02',
      mode: 'standard',
      error: bchn.error,
      binarySha256: bchn.binarySha256 ?? null,
      stdoutSha256: bchn.stdoutSha256 ?? null,
      primary: primaryBchn ?? null,
    },
    leanbch: {
      status: leanbch.verdict.status,
      version: 'ba8e7730e35c6d0bb5d4fa6fbce717073304c71c',
      verdict: { ...leanbch.verdict, binarySha256: leanbch.verdict.binarySha256 ?? null },
      cost: {
        status: leanbch.cost.status,
        error: leanbch.cost.error,
        binarySha256: leanbch.cost.binarySha256 ?? null,
        stdoutSha256: leanbch.cost.stdoutSha256 ?? null,
        primary: primaryLean ?? null,
      },
    },
  },
  diagnostics: {
    looseLibauthOptimizerAdapter: {
      status: 'diagnostic-only-not-evidence',
      metrics: {
        evaluatedInstructionCount: looseDiagnostic.instr,
        signatureCheckCount: looseDiagnostic.sigChecks,
        hashDigestIterations: looseDiagnostic.hashIters,
        arithmeticCost: looseDiagnostic.arith,
        stackPushedBytes: looseDiagnostic.push,
        operationCost: looseDiagnostic.opCost,
      },
      decomposition: decompose(looseDiagnostic),
      bound: classifyBound(primary.fixture.unlockingBytecode.length, looseDiagnostic.opCost),
    },
  },
  cases: caseReports,
  evidenceBoundary: 'Measured isolated standard-mode multiplication/codec control only. No extension, Circle, hash, AIR, proof, covenant, deployment, or complete-transaction qualification claim.',
};

if (process.argv.includes('--summary')) {
  console.log(JSON.stringify({
    schema: report.schema,
    status: report.status,
    candidateId: report.candidateId,
    primitive: report.primitive,
    caseCount: report.cases.length,
    lockingBytes: report.locking.bytes,
    unlockingBytes: report.primaryBoundaryFixture.unlockingBytes,
    operationCost: report.primaryBoundaryFixture.metrics.operationCost,
    operationCostHeadroom: report.primaryBoundaryFixture.metrics.limits.operationCostHeadroom,
    crossEngine: report.crossEngine,
  }, null, 2));
} else {
  console.log(JSON.stringify(report, null, 2));
}

if (!crossEnginePass) process.exitCode = 1;
