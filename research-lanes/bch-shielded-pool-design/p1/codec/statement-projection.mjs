/**
 * Bridge the frozen JSON statement to the frozen fixed transcript projection.
 *
 * The JSON object carries the exact payout locking bytecode. The transcript
 * carries only its domain-separated digest. Because P0 intentionally leaves
 * the digest algorithm unselected, withdrawal projection requires an injected
 * digest adapter. This module constructs the domain preimage but implements no
 * cryptographic primitive.
 */

import {
  assertBytecodeHex,
  assertExactKeys,
  assertHex,
  assertI64,
  assertU16,
  assertU32,
  assertU64,
  bytesToHex,
  fail,
  networkTagFor,
} from './common.mjs';
import {
  encodePoolActionStatement,
  payoutLockDomainPreimage,
  validatePoolActionStatement,
} from './pool-action-statement.mjs';
import { validateTokenRecord } from './token-record.mjs';
import { validateTxContext } from './tx-context.mjs';

const ZERO32 = '00'.repeat(32);
const STATEMENT_KEYS = [
  'schema', 'relationVersion', 'profileId', 'networkId', 'poolInstanceIdHex',
  'proofSecurityProfileDigestHex', 'actionKind', 'stateInput', 'stateOutput',
  'ticketSats', 'reserveDeltaSats', 'noteCommitmentHex', 'nullifierHex',
  'payout', 'fee', 'carrierManifestDigestHex', 'transactionContextDigestHex',
  'transactionContext',
];
const STATE_INPUT_KEYS = [
  'index', 'role', 'outpointTxidWireHex', 'outpointIndex', 'sequence',
  'sourceValueSats', 'sourceLockingBytecodeHex', 'tokenCategoryHex',
  'tokenCapability', 'tokenFungibleAmount', 'stateHex',
];
const STATE_OUTPUT_KEYS = [
  'index', 'role', 'valueSats', 'lockingBytecodeHex', 'tokenCategoryHex',
  'tokenCapability', 'tokenFungibleAmount', 'stateHex',
];
const PAYOUT_KEYS = ['outputIndex', 'amountSats', 'lockingBytecodeHex', 'token'];
const FEE_KEYS = [
  'policyId', 'transparent', 'externalInputIndex', 'externalInputRole',
  'externalAuthorizationMode', 'changeOutputIndex', 'feeSats', 'maxFeeSats',
  'poolSubsidySats', 'tokensForbidden',
];

const isNoneToken = (token) => token.categoryHex === ''
  && token.capability === 'none'
  && token.commitmentHex === ''
  && token.amount === '0';

const validateStateInput = (state) => {
  assertExactKeys(state, STATE_INPUT_KEYS, [], 'statement.stateInput');
  if (state.index !== 0 || state.role !== 'STATE' || state.outpointIndex !== 0 || state.sequence !== 0xffffffff) {
    fail('statement.stateInput is not canonical state input zero');
  }
  assertHex(state.outpointTxidWireHex, 'statement.stateInput.outpointTxidWireHex', 32);
  assertU64(state.sourceValueSats, 'statement.stateInput.sourceValueSats');
  assertBytecodeHex(state.sourceLockingBytecodeHex, 'statement.stateInput.sourceLockingBytecodeHex');
  assertHex(state.tokenCategoryHex, 'statement.stateInput.tokenCategoryHex', 32);
  if (state.tokenCapability !== 'mutable' || state.tokenFungibleAmount !== '0') {
    fail('statement.stateInput must carry a zero-amount mutable state token');
  }
  assertHex(state.stateHex, 'statement.stateInput.stateHex', 128);
};

const validateStateOutput = (state) => {
  assertExactKeys(state, STATE_OUTPUT_KEYS, [], 'statement.stateOutput');
  if (state.index !== 0 || state.role !== 'STATE_SUCCESSOR') {
    fail('statement.stateOutput is not canonical state successor zero');
  }
  assertU64(state.valueSats, 'statement.stateOutput.valueSats');
  assertBytecodeHex(state.lockingBytecodeHex, 'statement.stateOutput.lockingBytecodeHex');
  assertHex(state.tokenCategoryHex, 'statement.stateOutput.tokenCategoryHex', 32);
  if (state.tokenCapability !== 'mutable' || state.tokenFungibleAmount !== '0') {
    fail('statement.stateOutput must carry a zero-amount mutable state token');
  }
  assertHex(state.stateHex, 'statement.stateOutput.stateHex', 128);
};

const validateFee = (fee, actionKind) => {
  assertExactKeys(fee, FEE_KEYS, [], 'statement.fee');
  if (fee.policyId !== 'transparent-single-input-fv1' || fee.transparent !== true) {
    fail('statement.fee has the wrong policy');
  }
  assertU16(fee.externalInputIndex, 'statement.fee.externalInputIndex');
  const expectedRole = actionKind === 'DEPOSIT' ? 'DEPOSIT_FUNDING' : 'FEE_FUNDING';
  if (fee.externalInputRole !== expectedRole || fee.externalAuthorizationMode !== 'bch-sighash-all-forkid-0x41') {
    fail('statement.fee has the wrong external role or authorization mode');
  }
  if (fee.changeOutputIndex !== null) assertU16(fee.changeOutputIndex, 'statement.fee.changeOutputIndex');
  assertU64(fee.feeSats, 'statement.fee.feeSats');
  assertU64(fee.maxFeeSats, 'statement.fee.maxFeeSats');
  if (BigInt(fee.feeSats) > BigInt(fee.maxFeeSats)) fail('statement.fee exceeds maxFeeSats');
  if (fee.poolSubsidySats !== '0' || fee.tokensForbidden !== true) {
    fail('statement.fee permits pool subsidy or external tokens');
  }
};

const normalizeDigestResult = (result) => {
  const digestHex = result instanceof Uint8Array ? bytesToHex(result) : result;
  assertHex(digestHex, 'digestPayoutLock result', 32);
  return digestHex;
};

const equalFields = (actual, expected, fields, label) => {
  for (const field of fields) {
    if (actual[field] !== expected[field]) fail(`${label}.${field} disagrees with transactionContext`);
  }
};

const validateDirectContextCoherence = (statement) => {
  const context = statement.transactionContext;
  const stateInput = context.inputs[0];
  const stateOutput = context.outputs[0];
  equalFields(statement.stateInput, {
    index: stateInput.index,
    role: stateInput.role,
    outpointTxidWireHex: stateInput.outpointTxidWireHex,
    outpointIndex: stateInput.outpointIndex,
    sequence: stateInput.sequence,
    sourceValueSats: stateInput.sourceValueSats,
    sourceLockingBytecodeHex: stateInput.sourceLockingBytecodeHex,
    tokenCategoryHex: stateInput.sourceToken.categoryHex,
    tokenCapability: stateInput.sourceToken.capability,
    tokenFungibleAmount: stateInput.sourceToken.amount,
    stateHex: stateInput.sourceToken.commitmentHex,
  }, STATE_INPUT_KEYS, 'statement.stateInput');
  equalFields(statement.stateOutput, {
    index: stateOutput.index,
    role: stateOutput.role,
    valueSats: stateOutput.valueSats,
    lockingBytecodeHex: stateOutput.lockingBytecodeHex,
    tokenCategoryHex: stateOutput.token.categoryHex,
    tokenCapability: stateOutput.token.capability,
    tokenFungibleAmount: stateOutput.token.amount,
    stateHex: stateOutput.token.commitmentHex,
  }, STATE_OUTPUT_KEYS, 'statement.stateOutput');

  const external = context.inputs.at(-1);
  if (
    statement.fee.externalInputIndex !== external.index
    || statement.fee.externalInputRole !== external.role
  ) {
    fail('statement.fee external input disagrees with transactionContext');
  }
  const carrierCount = context.inputs.length - 2;
  const changeIndex = statement.actionKind === 'DEPOSIT' ? carrierCount + 1 : carrierCount + 2;
  const contextHasChange = context.outputs.at(-1)?.role === 'TRANSPARENT_CHANGE';
  const expectedChangeIndex = contextHasChange ? changeIndex : null;
  if (statement.fee.changeOutputIndex !== expectedChangeIndex) {
    fail('statement.fee change output disagrees with transactionContext');
  }

  const sourceTotal = context.inputs.reduce((sum, input) => sum + BigInt(input.sourceValueSats), 0n);
  const outputTotal = context.outputs.reduce((sum, output) => sum + BigInt(output.valueSats), 0n);
  if (sourceTotal - outputTotal !== BigInt(statement.fee.feeSats)) {
    fail('statement.feeSats disagrees with transactionContext balance');
  }

  if (statement.actionKind === 'WITHDRAWAL') {
    const payout = context.outputs[carrierCount + 1];
    equalFields(statement.payout, {
      outputIndex: payout.index,
      amountSats: payout.valueSats,
      lockingBytecodeHex: payout.lockingBytecodeHex,
    }, ['outputIndex', 'amountSats', 'lockingBytecodeHex'], 'statement.payout');
    equalFields(
      statement.payout.token,
      payout.token,
      ['categoryHex', 'capability', 'commitmentHex', 'amount'],
      'statement.payout.token',
    );
  }
};

export function projectPoolActionJsonStatement(statement, { digestPayoutLock } = {}) {
  assertExactKeys(statement, STATEMENT_KEYS, [], 'statement');
  if (statement.schema !== 'shieldkit-labs/pool-action-fv1-statement/v1') fail('wrong statement schema');
  if (statement.relationVersion !== 1 || statement.profileId !== 'profile:fixed-ticket-serial-pool') {
    fail('wrong relation version or profile');
  }
  networkTagFor(statement.networkId);
  if (statement.actionKind !== 'DEPOSIT' && statement.actionKind !== 'WITHDRAWAL') fail('unknown actionKind');
  assertHex(statement.poolInstanceIdHex, 'statement.poolInstanceIdHex', 32);
  assertHex(statement.proofSecurityProfileDigestHex, 'statement.proofSecurityProfileDigestHex', 32);
  assertHex(statement.carrierManifestDigestHex, 'statement.carrierManifestDigestHex', 32);
  assertHex(statement.transactionContextDigestHex, 'statement.transactionContextDigestHex', 32);
  assertHex(statement.noteCommitmentHex, 'statement.noteCommitmentHex', 32);
  assertHex(statement.nullifierHex, 'statement.nullifierHex', 32);
  if (statement.ticketSats !== '10000000') fail('statement.ticketSats must be 10000000');
  assertI64(statement.reserveDeltaSats, 'statement.reserveDeltaSats');
  validateStateInput(statement.stateInput);
  validateStateOutput(statement.stateOutput);
  validateFee(statement.fee, statement.actionKind);
  validateTxContext(statement.transactionContext);

  if (
    statement.transactionContext.networkId !== statement.networkId
    || statement.transactionContext.poolInstanceIdHex !== statement.poolInstanceIdHex
    || statement.transactionContext.actionKind !== statement.actionKind
    || statement.transactionContext.carrierManifestDigestHex !== statement.carrierManifestDigestHex
    || statement.transactionContext.proofSecurityProfileDigestHex !== statement.proofSecurityProfileDigestHex
  ) {
    fail('statement and transaction context headers disagree');
  }
  validateDirectContextCoherence(statement);

  let payoutOutputIndex = 0xffff;
  let payoutSats = '0';
  let payoutDigest = ZERO32;
  if (statement.actionKind === 'DEPOSIT') {
    if (statement.reserveDeltaSats !== '10000000' || statement.payout !== null) {
      fail('deposit reserve delta or payout is non-canonical');
    }
  } else {
    if (statement.reserveDeltaSats !== '-10000000' || statement.payout === null) {
      fail('withdrawal reserve delta or payout is non-canonical');
    }
    assertExactKeys(statement.payout, PAYOUT_KEYS, [], 'statement.payout');
    assertU16(statement.payout.outputIndex, 'statement.payout.outputIndex');
    if (statement.payout.amountSats !== '10000000') fail('withdrawal payout must be 10000000');
    assertBytecodeHex(statement.payout.lockingBytecodeHex, 'statement.payout.lockingBytecodeHex');
    validateTokenRecord(statement.payout.token, 'statement.payout.token');
    if (!isNoneToken(statement.payout.token)) fail('withdrawal payout must be token-free');
    if (typeof digestPayoutLock !== 'function') {
      fail('withdrawal projection requires a digestPayoutLock adapter for the selected immutable context digest');
    }
    payoutOutputIndex = statement.payout.outputIndex;
    payoutSats = statement.payout.amountSats;
    payoutDigest = normalizeDigestResult(
      digestPayoutLock(payoutLockDomainPreimage(statement.payout.lockingBytecodeHex)),
    );
  }

  const projected = {
    relationVersion: 1,
    profileTag: 1,
    networkId: statement.networkId,
    actionKind: statement.actionKind,
    poolInstanceIdHex: statement.poolInstanceIdHex,
    proofSecurityProfileDigestHex: statement.proofSecurityProfileDigestHex,
    carrierManifestDigestHex: statement.carrierManifestDigestHex,
    oldStateOutpointTxidWireHex: statement.stateInput.outpointTxidWireHex,
    oldStateOutpointIndex: statement.stateInput.outpointIndex,
    oldStateValueSats: statement.stateInput.sourceValueSats,
    oldStateBytesHex: statement.stateInput.stateHex,
    newStateOutputIndex: statement.stateOutput.index,
    newStateValueSats: statement.stateOutput.valueSats,
    newStateBytesHex: statement.stateOutput.stateHex,
    ticketSats: statement.ticketSats,
    reserveDeltaSats: statement.reserveDeltaSats,
    noteCommitmentOrZeroHex: statement.noteCommitmentHex,
    nullifierOrZeroHex: statement.nullifierHex,
    payoutOutputIndexOrffff: payoutOutputIndex,
    payoutSatsOrZero: payoutSats,
    payoutLockingBytecodeDigestOrZeroHex: payoutDigest,
    feeInputIndex: statement.fee.externalInputIndex,
    transparentChangeOutputIndexOrffff: statement.fee.changeOutputIndex ?? 0xffff,
    feeSats: statement.fee.feeSats,
    maxFeeSats: statement.fee.maxFeeSats,
    transactionContextDigestHex: statement.transactionContextDigestHex,
  };
  validatePoolActionStatement(projected);
  return projected;
}

export function encodePoolActionJsonStatement(statement, adapters) {
  return encodePoolActionStatement(projectPoolActionJsonStatement(statement, adapters));
}
