import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { validateContract } from './validate.mjs';

test('PoolActionFv2 falsifier contract is row-complete and execution-free', () => {
  const result = validateContract();
  assert.deepEqual(result, {
    retained: 57,
    additive: 16,
    total: 73,
    groupCounts: {
      POSITIVES: 12,
      NETWORK_NEGATIVES: 4,
      TXCONTEXT_TOKEN_NEGATIVES: 9,
      LOCK_NEGATIVES: 7,
      PROOF_SESSION_NEGATIVES: 18,
      PARSER_NEGATIVES: 4,
      SPLICES: 3
    },
    classificationCounts: {
      KEEP_UNCHANGED: 5,
      KEEP_RETARGETED: 35,
      SPLIT_REQUIRED: 10,
      DEFER_VM_TIER: 6,
      HISTORICAL_CONTROL_ONLY: 1
    },
    materialized: 0,
    executed: 0
  });
});

test('network and full-script repairs retain their exact non-physical semantics', () => {
  const contract = JSON.parse(fs.readFileSync(new URL('./contract.v2.json', import.meta.url), 'utf8'));
  const runtimeNetwork = contract.rows.find((row) => row.familyId === 'RF-NET-RUNTIME-SELECTION-MISMATCH');
  assert.match(runtimeNetwork.layer, /never physical-chain identity/);
  assert.equal(runtimeNetwork.dependencyGate, 'N,R,C');
  const fullScript = contract.rows.find((row) => row.familyId === 'F2-CARRIER-SESSION-ROOTS');
  assert.match(fullScript.layer, /same payload under different full script bytes/);
  assert.match(fullScript.minStableVariants, /preserving extracted payload/);
});
