import test from 'node:test';
import assert from 'node:assert/strict';
import { PoolActionSemanticError, verifyPoolActionFv1Semantic } from './pool-action-fv1-oracle.mjs';
import { cloneFixture, proofFreeDepositFixture, proofFreeWithdrawalFixture } from './fixtures.mjs';

const accepts = (fixture) => assert.equal(verifyPoolActionFv1Semantic(fixture).ok, true);
const rejects = (vectorId, fixture, mutate, code) => {
  const candidate = cloneFixture(fixture); mutate(candidate);
  assert.throws(() => verifyPoolActionFv1Semantic(candidate), (error) => error instanceof PoolActionSemanticError && error.code === code, vectorId);
};

test('proof-free semantic fixtures: deposit and withdrawal accepted only with injected facts', () => {
  accepts(proofFreeDepositFixture()); accepts(proofFreeWithdrawalFixture());
  const missing = proofFreeDepositFixture(); missing.facts = {};
  assert.throws(() => verifyPoolActionFv1Semantic(missing), /injected adapter or explicit true fact/);
});

test('frozen semantic mutation vectors', () => {
  rejects('vector:semantic:action-selector', proofFreeDepositFixture(), ({ statement }) => { statement.actionKind = 'TRANSFER'; }, 'ERR_ACTION_SELECTOR');
  rejects('vector:semantic:cross-network', proofFreeDepositFixture(), ({ statement }) => { statement.networkId = 'regtest'; }, 'ERR_POOL_OR_NETWORK');
  rejects('vector:semantic:cross-pool', proofFreeDepositFixture(), ({ statement }) => { statement.poolInstanceIdHex = 'aa'.repeat(32); }, 'ERR_POOL_OR_NETWORK');
  rejects('vector:semantic:deposit-nullifier-root', proofFreeDepositFixture(), ({ statement }) => { const h = statement.stateOutput.stateHex; statement.stateOutput.stateHex = `${h.slice(0, 192)}${'ee'.repeat(32)}`; statement.transactionContext.outputs[0].token.commitmentHex = statement.stateOutput.stateHex; }, 'ERR_NOTE_OR_NULLIFIER');
  rejects('vector:semantic:note-insertion-path', proofFreeDepositFixture(), ({ facts }) => { facts.noteAppend = false; }, 'ERR_WITNESS_RESULT');
  rejects('vector:semantic:note-membership-path', proofFreeWithdrawalFixture(), ({ facts }) => { facts.noteMembership = false; }, 'ERR_WITNESS_RESULT');
  rejects('vector:semantic:nullifier-nonmembership', proofFreeWithdrawalFixture(), ({ facts }) => { facts.nullifierNonMembership = false; }, 'ERR_WITNESS_RESULT');
  rejects('vector:semantic:nullifier-insertion', proofFreeWithdrawalFixture(), ({ facts }) => { facts.nullifierInsertion = false; }, 'ERR_WITNESS_RESULT');
  rejects('vector:semantic:owner-secret', proofFreeWithdrawalFixture(), ({ facts }) => { facts.authorization = false; }, 'ERR_WITNESS_RESULT');
  rejects('vector:semantic:state-counter', proofFreeWithdrawalFixture(), ({ statement }) => { const b = Buffer.from(statement.stateOutput.stateHex, 'hex'); b.writeBigUInt64LE(3n, 8); statement.stateOutput.stateHex = b.toString('hex'); statement.transactionContext.outputs[0].token.commitmentHex = statement.stateOutput.stateHex; }, 'ERR_STATE_COUNTER');
  rejects('vector:semantic:state-reserved', proofFreeDepositFixture(), ({ statement }) => { const b = Buffer.from(statement.stateInput.stateHex, 'hex'); b.writeUInt16LE(1, 6); statement.stateInput.stateHex = b.toString('hex'); statement.transactionContext.inputs[0].sourceToken.commitmentHex = statement.stateInput.stateHex; }, 'ERR_STATE_CODEC_OR_INVARIANT');
  rejects('vector:semantic:ticket-value', proofFreeDepositFixture(), ({ statement }) => { statement.ticketSats = '1'; }, 'ERR_TICKET_VALUE');
});

test('frozen transaction/topology mutation vectors', () => {
  rejects('vector:transaction:carrier-value', proofFreeDepositFixture(), ({ statement }) => { statement.transactionContext.outputs[1].valueSats = '999'; }, 'ERR_TOPOLOGY_OR_CARRIER');
  rejects('vector:transaction:deposit-payout', proofFreeDepositFixture(), ({ statement }) => { statement.payout = {}; }, 'ERR_PAYOUT');
  rejects('vector:transaction:extra-input', proofFreeDepositFixture(), ({ statement }) => { statement.transactionContext.inputs.push({ ...statement.transactionContext.inputs[2], index: 3 }); }, 'ERR_NO_IGNORED_CONTEXT');
  rejects('vector:transaction:extra-output', proofFreeDepositFixture(), ({ statement }) => { statement.transactionContext.outputs.push({ ...statement.transactionContext.outputs[1], index: 2, role: 'VERIFIER_CARRIER_SUCCESSOR' }); }, 'ERR_NO_IGNORED_CONTEXT');
  rejects('vector:transaction:fee-cap', proofFreeDepositFixture(), ({ statement }) => { statement.fee.feeSats = '10001'; }, 'ERR_FEE_POLICY');
  rejects('vector:transaction:fee-input', proofFreeWithdrawalFixture(), ({ statement }) => { statement.transactionContext.inputs[2].sourceToken.categoryHex = 'aa'.repeat(32); }, 'ERR_FEE_POLICY');
  rejects('vector:transaction:funding-sighash-mode', proofFreeWithdrawalFixture(), ({ statement }) => { statement.fee.externalAuthorizationMode = 'bch-sighash-none'; }, 'ERR_FEE_POLICY');
  rejects('vector:transaction:input-order', proofFreeDepositFixture(), ({ statement }) => { statement.transactionContext.inputs[0].index = 1; }, 'ERR_INPUT_OUTPUT_ORDER');
  rejects('vector:transaction:output-order', proofFreeWithdrawalFixture(), ({ statement }) => { statement.transactionContext.outputs[2].index = 3; }, 'ERR_INPUT_OUTPUT_ORDER');
  rejects('vector:transaction:payout-value', proofFreeWithdrawalFixture(), ({ statement }) => { statement.payout.amountSats = '1'; }, 'ERR_PAYOUT');
  rejects('vector:transaction:state-token-amount', proofFreeDepositFixture(), ({ statement }) => { statement.transactionContext.inputs[0].sourceToken.amount = '1'; }, 'ERR_STATE_TOKEN');
  rejects('vector:transaction:statement-context-disagreement', proofFreeDepositFixture(), ({ statement }) => { statement.stateInput.sourceValueSats = '2'; }, 'ERR_STATEMENT_CONTEXT');
});

test('StatementCoherenceFv1 independently rejects high-value duplicated-field mutations', () => {
  const cases = [
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'state successor value',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.stateOutput.valueSats = '1'; },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'state successor locking bytecode',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.stateOutput.lockingBytecodeHex = '52'; },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'state successor category',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.stateOutput.tokenCategoryHex = 'aa'.repeat(32); },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'state successor capability',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.stateOutput.tokenCapability = 'immutable'; },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'state successor fungible amount',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.stateOutput.tokenFungibleAmount = '1'; },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'state successor commitment bytes',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.stateOutput.stateHex = 'ee'.repeat(128); },
      code: 'ERR_STATE_TOKEN',
    },
    {
      vectorId: 'vector:transaction:payout-lock',
      label: 'withdrawal payout locking bytecode',
      fixture: proofFreeWithdrawalFixture,
      mutate: ({ statement }) => { statement.payout.lockingBytecodeHex = '52'; },
      code: 'ERR_PAYOUT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'withdrawal payout token',
      fixture: proofFreeWithdrawalFixture,
      mutate: ({ statement }) => {
        statement.payout.token = {
          categoryHex: 'aa'.repeat(32), capability: 'immutable', commitmentHex: '', amount: '0',
        };
      },
      code: 'ERR_PAYOUT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'withdrawal payout index',
      fixture: proofFreeWithdrawalFixture,
      mutate: ({ statement }) => { statement.payout.outputIndex = 1; },
      code: 'ERR_PAYOUT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'context network header',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.transactionContext.networkId = 'regtest'; },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'context pool header',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.transactionContext.poolInstanceIdHex = 'aa'.repeat(32); },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'context action header',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.transactionContext.actionKind = 'WITHDRAWAL'; },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:proof:wrong-security-profile',
      label: 'context proof-security-profile header',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.transactionContext.proofSecurityProfileDigestHex = 'aa'.repeat(32); },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'context carrier-manifest header',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.transactionContext.carrierManifestDigestHex = 'aa'.repeat(32); },
      code: 'ERR_STATEMENT_CONTEXT',
    },
    {
      vectorId: 'vector:transaction:statement-context-disagreement',
      label: 'false context-digest result',
      fixture: proofFreeDepositFixture,
      mutate: ({ facts }) => { facts.contextDigest = false; },
      code: 'ERR_WITNESS_RESULT',
    },
    {
      vectorId: 'vector:topology:carrier-cross-splice',
      label: 'false proof-session binding result',
      fixture: proofFreeDepositFixture,
      mutate: ({ facts }) => { facts.proofSessionBinding = false; },
      code: 'ERR_WITNESS_RESULT',
    },
    {
      vectorId: 'vector:transaction:input-order',
      label: 'carrier role substitution',
      fixture: proofFreeDepositFixture,
      mutate: ({ statement }) => { statement.transactionContext.inputs[1].role = 'DEPOSIT_FUNDING'; },
      code: 'ERR_INPUT_OUTPUT_ORDER',
    },
  ];

  for (const { vectorId, label, fixture, mutate, code } of cases) {
    rejects(`${vectorId}: ${label}`, fixture(), mutate, code);
  }
});

test('injected callback is an acceptable non-cryptographic relation boundary', () => {
  const fixture = proofFreeWithdrawalFixture();
  fixture.facts = { ...fixture.facts, nullifierInsertion: false };
  fixture.adapters = { nullifierInsertion: () => true };
  accepts(fixture);
});

test('JSON object property order is not treated as a semantic encoding difference', () => {
  const fixture = proofFreeWithdrawalFixture();
  fixture.statement.payout.token = {
    amount: '0', commitmentHex: '', capability: 'none', categoryHex: '',
  };
  accepts(fixture);
});

test('canonicality and BCH monetary bounds reject aliases and ignored token fields', () => {
  rejects('reserve-delta-text-alias', proofFreeDepositFixture(), ({ statement }) => {
    statement.reserveDeltaSats = '010000000';
  }, 'ERR_TICKET_VALUE');
  rejects('immutable-fee-cap-disagreement', proofFreeDepositFixture(), ({ statement }) => {
    statement.fee.maxFeeSats = '9999';
  }, 'ERR_FEE_POLICY');
  rejects('carrier-token-ignored-field', proofFreeDepositFixture(), ({ statement }) => {
    statement.transactionContext.inputs[1].sourceToken.ignored = true;
    statement.transactionContext.outputs[1].token.ignored = true;
  }, 'ERR_TOPOLOGY_OR_CARRIER');
  rejects('output-over-max-money', proofFreeDepositFixture(), ({ statement }) => {
    statement.transactionContext.outputs[1].valueSats = '2100000000000001';
  }, 'ERR_CONTEXT_CODEC');
  rejects('oversized-context-lock', proofFreeDepositFixture(), ({ statement }) => {
    statement.transactionContext.inputs[1].sourceLockingBytecodeHex = '51'.repeat(10_001);
  }, 'ERR_CONTEXT_CODEC');
  rejects('outpoint-index-over-u32', proofFreeDepositFixture(), ({ statement }) => {
    statement.transactionContext.inputs[1].outpointIndex = 0x1_0000_0000;
  }, 'ERR_CONTEXT_CODEC');
  const impossibleCapacity = proofFreeDepositFixture();
  impossibleCapacity.config = { ...impossibleCapacity.config, maxLifetimeDeposits: '210000001' };
  assert.throws(
    () => verifyPoolActionFv1Semantic(impossibleCapacity),
    (error) => error instanceof PoolActionSemanticError && error.code === 'ERR_CONFIG',
  );
});
