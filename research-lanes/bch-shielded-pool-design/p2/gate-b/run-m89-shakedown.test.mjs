import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';

import {
  buildM89ShakedownReport,
  buildExternalProcessEvidence,
  deriveStandardOperationCost,
  parseBchnStdout,
  parseLeanCostprobeStdout,
  parseVmbconfStdout,
} from './run-m89-shakedown.mjs';

const digest = (text) => createHash('sha256').update(text).digest('hex');

test('standard op-cost derivation is pinned to the five raw metrics and hash rate', () => {
  const raw = {
    evaluatedInstructionCount: 360,
    signatureCheckCount: 0,
    hashDigestIterations: 11,
    arithmeticCost: 187,
    stackPushedBytes: 1699,
  };
  assert.equal(deriveStandardOperationCost(raw, 192), 39998);
  assert.equal(deriveStandardOperationCost(raw, 64), 38590);
});

test('external process evidence retains exact argv, stdin, stdout/stderr text and recomputable digests', () => {
  const evidence = buildExternalProcessEvidence({
    path: '/opt/bchn-leg',
    args: ['--mode', 'standard'],
    input: '{"id":"m89"}\n',
    childStatus: 0,
    stdout: 'OUT\n',
    stderr: 'ERR\n',
  });
  assert.deepEqual(evidence.argv, ['/opt/bchn-leg', '--mode', 'standard']);
  assert.equal(evidence.executablePath, '/opt/bchn-leg');
  assert.equal(evidence.childStatus, 0);
  assert.equal(evidence.stdinSha256, digest('{"id":"m89"}\n'));
  assert.equal(evidence.stdinBytes, Buffer.byteLength('{"id":"m89"}\n'));
  assert.equal(evidence.stdoutText, 'OUT\n');
  assert.equal(evidence.stdoutSha256, digest('OUT\n'));
  assert.equal(evidence.stderrText, 'ERR\n');
  assert.equal(evidence.stderrSha256, digest('ERR\n'));
});

test('external parsers retain complete rows and STD-TRUE/FALSE coverage', () => {
  const bchn = parseBchnStdout(`${JSON.stringify({
    ident: 'm89-gate-b0:mac:valid:0:v0', outcome: 'accept', error_class: 0,
    native_error: '', op_cost: 39998, op_cost_limit: 569600,
    hash_iters: 11, hash_iters_limit: 356, sig_checks: 0, sig_checks_limit: 17,
  })}\n`);
  assert.equal(bchn.errors.length, 0);
  assert.equal(bchn.parsed.size, 1);
  assert.equal(bchn.parsed.get('m89-gate-b0:mac:valid:0:v0').op_cost, 39998);

  const lean = parseLeanCostprobeStdout('ORACLE reject\nMETRICS m89-gate-b0:mac:valid:0:v0 1 360 0 11 187 1699 38590\n');
  assert.equal(lean.errors.length, 0);
  assert.equal(lean.oracle, 'reject');
  assert.deepEqual(lean.parsed.get('m89-gate-b0:mac:valid:0:v0').rawMetrics, {
    evaluatedInstructionCount: 360,
    signatureCheckCount: 0,
    hashDigestIterations: 11,
    arithmeticCost: 187,
    stackPushedBytes: 1699,
  });
  assert.equal(lean.parsed.get('m89-gate-b0:mac:valid:0:v0').nativeConsensus64OperationCost, 38590);

  const vmbconf = parseVmbconfStdout([
    'ORACLE reject',
    'PASS 2 / 2',
    'REJECTED-VALID 0: []',
    'ACCEPTED-INVALID 0: []',
    'STD-TRUE 2 STD-FALSE 0',
    'STD-TRUE-IDS: [m89-gate-b0:a, m89-gate-b0:b]',
    'STD-FALSE-IDS: []',
  ].join('\n'));
  assert.deepEqual(vmbconf, {
    oracle: 'reject',
    passed: 2,
    total: 2,
    rejectedValid: 0,
    acceptedInvalid: 0,
    standardTrue: 2,
    standardFalse: 0,
    standardTrueIds: ['m89-gate-b0:a', 'm89-gate-b0:b'],
    standardFalseIds: [],
    standardIdListLimit: 200,
    standardTrueIdsTruncated: false,
    standardFalseIdsTruncated: false,
  });

  const truncated = parseVmbconfStdout([
    'PASS 201 / 201',
    'REJECTED-VALID 0: []',
    'ACCEPTED-INVALID 0: []',
    'STD-TRUE 201 STD-FALSE 0',
    `STD-TRUE-IDS: [${Array.from({ length: 200 }, (_, index) => `id-${index}`).join(', ')}]`,
    'STD-FALSE-IDS: []',
  ].join('\n'));
  assert.equal(truncated.standardIdListLimit, 200);
  assert.equal(truncated.standardTrueIds.length, 200);
  assert.equal(truncated.standardTrueIdsTruncated, true);
  assert.equal(truncated.standardFalseIdsTruncated, false);
});

test('stdout-only report helpers preserve native/libauth coverage without external execution', () => {
  const report = buildM89ShakedownReport({ runExternal: false });
  assert.equal(report.status, 'not-run');
  assert.deepEqual(report.corpus, { totalCases: 266, expectedAccepted: 206, expectedRejected: 60 });
  assert.equal(report.verdictAgreement.nativeAllExpected, true);
  assert.equal(report.verdictAgreement.libauthAllExpected, true);
  assert.equal(report.verdictAgreement.vmbconfFullVerdictCoverage, false);
  assert.equal(report.standardVmRules.includes('standard VM'), true);
  assert.equal(report.fullTransactionPolicy, 'not-evaluated');
  assert.equal(report.selection, 'none');
  assert.equal(report.cases.length, 266);
  const rejected = report.cases.find(({ expected }) => expected.verdict === 'reject');
  assert.equal(rejected.comparisons.bchnExpected, null);
  assert.equal(rejected.comparisons.leanRawFiveMatchesLibauth, null);
  assert.equal(rejected.comparisons.bchnExposedMatchesLibauth, null);
});
