#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

import { M31_MODULUS } from '../research-lanes/bch-shielded-pool-design/p2/reference/m31.mjs';

import { utf8 } from '../src/circle-fri/bytes.mjs';

import {
  BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES,
  createBchCircleFriQueryFixture,
  encodeBchCircleFriQueryP2sh32TransactionFixture,
  evaluateBchCircleFriQueryP2sh32,
  materializeBchCircleFriQueryP2sh32,
} from '../src/circle-fri/bch-query-kernel.mjs';

import {
  encodeCircleFriQueryProof,
  proveCircleFriQueries,
} from '../src/circle-fri/query-proof.mjs';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export const QUERY_KAT_PARAMETERS = Object.freeze({
  logDegreeBound: 6,
  logBlowup: 3,
  queryCount: 1,
});

export const QUERY_KAT_CONTEXT = utf8('ShieldKit Circle-FRI BCH query component v1');

export const buildQueryKat = () => {
  let state = 0x626368n;
  const coefficients = Array.from({ length: 1 << QUERY_KAT_PARAMETERS.logDegreeBound }, () => {
    state = (state * 6_364_136_223_846_793_005n + 1_442_695_040_888_963_407n) & ((1n << 64n) - 1n);
    return (state >> 13n) % M31_MODULUS;
  });
  const proof = proveCircleFriQueries({
    coefficients,
    logBlowup: QUERY_KAT_PARAMETERS.logBlowup,
    queryCount: QUERY_KAT_PARAMETERS.queryCount,
    protocolContext: QUERY_KAT_CONTEXT,
  });
  const fixture = createBchCircleFriQueryFixture({
    proof,
    expected: QUERY_KAT_PARAMETERS,
    protocolContext: QUERY_KAT_CONTEXT,
  });
  const materialized = materializeBchCircleFriQueryP2sh32(fixture);
  const evaluation = evaluateBchCircleFriQueryP2sh32(fixture);
  const wires = encodeBchCircleFriQueryP2sh32TransactionFixture(fixture);
  const proofBytes = encodeCircleFriQueryProof(proof);
  return Object.freeze({ coefficients, proof, fixture, materialized, evaluation, wires, proofBytes });
};

export const queryKatSummary = (kat) => Object.freeze({
  kind: kat.fixture.kind,
  transcriptDerivationIncluded: kat.fixture.transcriptDerivationIncluded,
  parameters: QUERY_KAT_PARAMETERS,
  initialQueryIndex: kat.fixture.initialQueryIndex,
  proof: Object.freeze({
    bytes: kat.proofBytes.length,
    sha256: sha256(kat.proofBytes),
  }),
  p2sh32: Object.freeze({
    sourceLockingBytes: kat.materialized.lockingBytecode.length,
    redeemBytes: kat.materialized.redeemBytecode.length,
    operandUnlockingBytes: kat.materialized.operandUnlockingBytecode.length,
    unlockingBytes: kat.materialized.unlockingBytecode.length,
    transactionBytes: kat.wires.transactionHex.length / 2,
    sourceOutputsBytes: kat.wires.sourceOutputsHex.length / 2,
    redeemSha256: sha256(kat.materialized.redeemBytecode),
    unlockingSha256: sha256(kat.materialized.unlockingBytecode),
    transactionSha256: kat.wires.transactionDigestSha256,
    sourceOutputsSha256: kat.wires.sourceOutputsDigestSha256,
    functionDefinitionCodeBytes: BCH_CIRCLE_FRI_QUERY_FUNCTION_CODE_BYTES,
  }),
  libauthBch2026Standard: Object.freeze({
    accepted: kat.evaluation.accepted,
    error: kat.evaluation.error,
    metrics: kat.evaluation.metrics,
  }),
});

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const kat = buildQueryKat();
  const mode = process.argv[2] ?? '--summary';
  if (mode === '--bchn-vector') {
    process.stdout.write(`${JSON.stringify([[
      'circle-fri-query-kat-v1',
      'ShieldKit Circle-FRI authenticated query component',
      '',
      '',
      kat.wires.transactionHex,
      kat.wires.sourceOutputsHex,
      0,
    ]])}\n`);
  } else if (mode === '--lean-vector') {
    process.stdout.write(`1 circle-fri-query-kat-v1 ${kat.wires.transactionHex} ${kat.wires.sourceOutputsHex} 0\n`);
  } else if (mode === '--summary') {
    process.stdout.write(`${JSON.stringify(queryKatSummary(kat), null, 2)}\n`);
  } else {
    throw new TypeError(`unknown mode: ${mode}`);
  }
}
