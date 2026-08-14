import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import Ajv2020 from 'ajv/dist/2020.js';
import { binToHex } from '@bitauth/libauth';

import {
  decodePoolActionFv1Statement,
  decodePoolStateFv1,
  decodeTxContextFv1,
  encodePoolActionFv1Statement,
  encodePoolStateFv1,
  encodeTxContextFv1,
  hexToBytes,
  projectPoolActionJsonStatement,
} from './codec/index.mjs';
import {
  proofFreeDepositFixture,
  proofFreeWithdrawalFixture,
} from './oracle/fixtures.mjs';
import { verifyPoolActionFv1Semantic } from './oracle/pool-action-fv1-oracle.mjs';
import { buildDeterministicProofFreeShell } from './shell/shell.mjs';

const statementSchema = JSON.parse(readFileSync(new URL('../spec/pool-action-fv1.schema.json', import.meta.url)));
const ajv = new Ajv2020({ strict: true, allErrors: true });
const validateStatementSchema = ajv.compile(statementSchema);

for (const [name, makeFixture] of [
  ['deposit', proofFreeDepositFixture],
  ['withdrawal', proofFreeWithdrawalFixture],
]) {
  test(`P1 ${name} crosses schema, oracle, codecs, projection, and Libauth shell without selecting crypto`, () => {
    const fixture = makeFixture();
    assert.equal(validateStatementSchema(fixture.statement), true, JSON.stringify(validateStatementSchema.errors));
    const semantic = verifyPoolActionFv1Semantic(fixture);
    assert.deepEqual(semantic, {
      ok: true,
      proofFree: true,
      actionKind: fixture.statement.actionKind,
      carrierCount: 1,
    });

    for (const stateHex of [fixture.statement.stateInput.stateHex, fixture.statement.stateOutput.stateHex]) {
      const decodedState = decodePoolStateFv1(stateHex);
      assert.equal(binToHex(encodePoolStateFv1(decodedState)), stateHex);
    }

    const contextBytes = encodeTxContextFv1(fixture.statement.transactionContext);
    assert.deepEqual(decodeTxContextFv1(contextBytes), fixture.statement.transactionContext);

    let payoutDigestCalls = 0;
    const projection = projectPoolActionJsonStatement(fixture.statement, {
      // Test-only opaque adapter output. It is neither a protocol digest choice
      // nor evidence that a payout digest has been cryptographically checked.
      digestPayoutLock: () => {
        payoutDigestCalls += 1;
        return new Uint8Array(32).fill(0xa5);
      },
    });
    assert.equal(payoutDigestCalls, name === 'withdrawal' ? 1 : 0);
    const statementBytes = encodePoolActionFv1Statement(projection);
    assert.deepEqual(decodePoolActionFv1Statement(statementBytes), projection);

    const shell = buildDeterministicProofFreeShell({
      action: fixture.statement.actionKind,
      carrierCount: 1,
      oldStateCommitment: hexToBytes(fixture.statement.stateInput.stateHex),
      newStateCommitment: hexToBytes(fixture.statement.stateOutput.stateHex),
    });
    assert.equal(shell.checks.cashTokenConservation, true);
    assert.equal(shell.checks.predecessorBundleByteEquality, true);
    assert.equal(
      binToHex(shell.structures.sourceOutputs[0].token.nft.commitment),
      fixture.statement.stateInput.stateHex,
    );
    assert.equal(
      binToHex(shell.structures.transaction.outputs[0].token.nft.commitment),
      fixture.statement.stateOutput.stateHex,
    );
    assert.equal(shell.checks.scriptExecution, 'not-run-proof-and-signature-placeholders');
  });
}

