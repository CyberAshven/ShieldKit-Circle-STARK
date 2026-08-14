import assert from 'node:assert/strict';
import test from 'node:test';

import { binToHex, encodeTransactionOutputs } from '@bitauth/libauth';

import {
  MAX_STANDARD_TRANSACTION_BYTES,
  MAX_UNLOCKING_BYTECODE_BYTES,
  buildDeterministicProofFreeShell,
  maximumProofBearingUnlockEnvelope,
} from './shell.mjs';

const u64le = (value) => {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), true);
  return bytes;
};

const state = ({ sequence, deposits, withdrawals, noteOctet, nullifierOctet }) => {
  const bytes = new Uint8Array(128);
  bytes.set([0x50, 0x41, 0x46, 0x31, 0x01, 0x00, 0x00, 0x00], 0);
  bytes.set(u64le(sequence), 8);
  bytes.set(u64le(deposits), 16);
  bytes.set(u64le(withdrawals), 24);
  bytes.fill(0x55, 32, 64);
  bytes.fill(noteOctet, 64, 96);
  bytes.fill(nullifierOctet, 96, 128);
  return bytes;
};

const DEPOSIT_OLD = state({ sequence: 0, deposits: 0, withdrawals: 0, noteOctet: 0x66, nullifierOctet: 0x77 });
const DEPOSIT_NEW = state({ sequence: 1, deposits: 1, withdrawals: 0, noteOctet: 0x68, nullifierOctet: 0x77 });
const WITHDRAWAL_OLD = state({ sequence: 1, deposits: 1, withdrawals: 0, noteOctet: 0x68, nullifierOctet: 0x77 });
const WITHDRAWAL_NEW = state({ sequence: 2, deposits: 1, withdrawals: 1, noteOctet: 0x68, nullifierOctet: 0x79 });

const fixture = (action, carrierCount, includeChange = false, proofUnlockingLengths) => (
  buildDeterministicProofFreeShell({
    action,
    carrierCount,
    includeChange,
    proofUnlockingLengths,
    oldStateCommitment: action === 'DEPOSIT' ? DEPOSIT_OLD : WITHDRAWAL_OLD,
    newStateCommitment: action === 'DEPOSIT' ? DEPOSIT_NEW : WITHDRAWAL_NEW,
  })
);

test('empty shells preserve exact roles, predecessor bundle, tokens, and satoshis', () => {
  for (const action of ['DEPOSIT', 'WITHDRAWAL']) {
    for (const carrierCount of [1, 2, 5, 9]) {
      for (const includeChange of [false, true]) {
        const shell = fixture(action, carrierCount, includeChange);
        assert.equal(shell.status, 'proof-free-size-fixture-not-a-valid-spend');
        assert.equal(shell.checks.canonicalTransactionRoundTrip, true);
        assert.equal(shell.checks.canonicalSourceOutputsRoundTrip, true);
        assert.equal(shell.checks.predecessorBundleByteEquality, true);
        assert.equal(shell.checks.monetaryConservation, true);
        assert.equal(shell.checks.cashTokenConservation, true);
        assert.equal(shell.structures.transaction.inputs.length, carrierCount + 2);
        assert.equal(shell.structures.sourceOutputs.length, carrierCount + 2);
        assert.equal(shell.roleMap.inputs[0].role, 'STATE');
        assert.equal(shell.roleMap.inputs.at(-1).role, action === 'DEPOSIT' ? 'DEPOSIT_FUNDING' : 'FEE_FUNDING');
        assert.equal(shell.roleMap.outputs[0].role, 'STATE_SUCCESSOR');
        if (action === 'WITHDRAWAL') {
          assert.equal(shell.roleMap.outputs[carrierCount + 1].role, 'PAYOUT');
        } else {
          assert.equal(shell.roleMap.outputs.some(({ role }) => role === 'PAYOUT'), false);
        }
        if (includeChange) assert.equal(shell.roleMap.outputs.at(-1).role, 'TRANSPARENT_CHANGE');

        const stateInputToken = shell.structures.sourceOutputs[0].token;
        const stateOutputToken = shell.structures.transaction.outputs[0].token;
        assert.equal(stateInputToken.amount, 0n);
        assert.equal(stateOutputToken.amount, 0n);
        assert.equal(stateInputToken.nft.capability, 'mutable');
        assert.equal(stateOutputToken.nft.capability, 'mutable');
        assert.equal(stateInputToken.nft.commitment.length, 128);
        assert.equal(stateOutputToken.nft.commitment.length, 128);
        assert.deepEqual(stateInputToken.category, stateOutputToken.category);

        const predecessorBundle = encodeTransactionOutputs(shell.structures.predecessorTransaction.outputs);
        const consumedBundle = encodeTransactionOutputs(shell.structures.sourceOutputs.slice(0, carrierCount + 1));
        assert.equal(binToHex(predecessorBundle), binToHex(consumedBundle));
        assert.equal(shell.structures.transaction.inputs[0].outpointIndex, 0);
        for (let ordinal = 0; ordinal < carrierCount; ordinal += 1) {
          assert.equal(shell.structures.transaction.inputs[ordinal + 1].outpointIndex, ordinal + 1);
          assert.deepEqual(
            shell.structures.transaction.inputs[ordinal + 1].outpointTransactionHash,
            shell.structures.transaction.inputs[0].outpointTransactionHash,
          );
        }
      }
    }
  }
});

test('known-answer shell serialization is stable', () => {
  const deposit = fixture('DEPOSIT', 1, false);
  const withdrawal = fixture('WITHDRAWAL', 1, false);
  assert.deepEqual(
    {
      transactionBytes: deposit.accounting.transactionBytes,
      sourceOutputsBytes: deposit.accounting.sourceOutputsBytes,
      transactionSha256: deposit.digests.transactionSha256,
      sourceOutputsSha256: deposit.digests.sourceOutputsSha256,
    },
    {
      transactionBytes: 491,
      sourceOutputsBytes: 286,
      transactionSha256: 'f423d8b69f977ba851f1a8740688b7e47c24b9d61d6e33880f3d1933e2a0b8ed',
      sourceOutputsSha256: '988dcf076902efe3ecf73a00fe601ee800fc86a6a973dd1550ad114252715212',
    },
  );
  assert.deepEqual(
    {
      transactionBytes: withdrawal.accounting.transactionBytes,
      sourceOutputsBytes: withdrawal.accounting.sourceOutputsBytes,
      transactionSha256: withdrawal.digests.transactionSha256,
      sourceOutputsSha256: withdrawal.digests.sourceOutputsSha256,
    },
    {
      transactionBytes: 525,
      sourceOutputsBytes: 286,
      transactionSha256: '4ef34df759cffac7cc5934b890806430cdd4ad4781f372f447ce559628a95588',
      sourceOutputsSha256: 'ba36793b7b9c3c486f5180aac644abf87684b6adfe6b9cb3126ecb53a3ce636b',
    },
  );
});

test('proof-bearing unlocking envelope is exact for each deterministic topology', () => {
  for (const action of ['DEPOSIT', 'WITHDRAWAL']) {
    for (const carrierCount of [1, 2, 5, 8, 9, 12]) {
      const oldStateCommitment = action === 'DEPOSIT' ? DEPOSIT_OLD : WITHDRAWAL_OLD;
      const newStateCommitment = action === 'DEPOSIT' ? DEPOSIT_NEW : WITHDRAWAL_NEW;
      const envelope = maximumProofBearingUnlockEnvelope({
        action,
        carrierCount,
        oldStateCommitment,
        newStateCommitment,
      });
      assert.ok(envelope.aggregateUnlockingBytes >= 0);
      assert.ok(envelope.transactionBytes <= MAX_STANDARD_TRANSACTION_BYTES);
      assert.ok(envelope.transactionHeadroomBytes >= 0);
      assert.equal(envelope.allocation.length, carrierCount + 1);
      assert.ok(envelope.allocation.every((length) => length >= 1));
      assert.ok(envelope.allocation.every((length) => length <= MAX_UNLOCKING_BYTECODE_BYTES));
      assert.equal(
        envelope.allocation.reduce((sum, length) => sum + length, 0),
        envelope.aggregateUnlockingBytes,
      );

      const proofInputCount = carrierCount + 1;
      if (envelope.aggregateUnlockingBytes === proofInputCount * MAX_UNLOCKING_BYTECODE_BYTES) {
        assert.equal(envelope.limitingRule, 'per-input-10000-byte-limit');
      } else {
        assert.equal(envelope.limitingRule, '100000-byte-standard-transaction-limit');
        assert.equal(envelope.transactionBytes, MAX_STANDARD_TRANSACTION_BYTES);
      }
    }
  }
});

test('shell rejects zero carriers, malformed state, and unlocking overflow', () => {
  assert.throws(() => fixture('DEPOSIT', 0), /carrierCount/);
  assert.throws(() => buildDeterministicProofFreeShell({
    action: 'DEPOSIT',
    carrierCount: 1,
    oldStateCommitment: new Uint8Array(128),
    newStateCommitment: DEPOSIT_NEW,
  }), /magic/);
  assert.throws(() => fixture('WITHDRAWAL', 1, false, [10_001, 0]), /proofUnlockingLengths\[0\]/);
});
