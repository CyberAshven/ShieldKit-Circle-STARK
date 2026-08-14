/** Proof-free semantic fixtures. Their true facts are injected assertions, not cryptographic evidence. */
import { ZERO32 } from './pool-action-fv1-oracle.mjs';

const h = (byte) => byte.repeat(32);
const stateHex = ({ sequence, deposits, withdrawals, pool, note, nullifier }) => {
  const b = Buffer.alloc(128);
  b.write('PAF1'); b.writeUInt16LE(1, 4); b.writeUInt16LE(0, 6);
  b.writeBigUInt64LE(BigInt(sequence), 8); b.writeBigUInt64LE(BigInt(deposits), 16); b.writeBigUInt64LE(BigInt(withdrawals), 24);
  Buffer.from(pool, 'hex').copy(b, 32); Buffer.from(note, 'hex').copy(b, 64); Buffer.from(nullifier, 'hex').copy(b, 96);
  return b.toString('hex');
};
const noToken = Object.freeze({ categoryHex: '', capability: 'none', commitmentHex: '', amount: '0' });
const clone = (value) => JSON.parse(JSON.stringify(value));

export const proofFreeConfig = Object.freeze({
  networkId: 'chipnet', poolInstanceIdHex: h('11'), proofSecurityProfileDigestHex: h('22'), carrierManifestDigestHex: h('33'),
  stateCarrierBaseSats: '1000', maxLifetimeDeposits: '9', maxFeeSats: '10000', stateLockingBytecodeHex: '51', stateTokenCategoryHex: h('44'),
});
export const proofFreeFacts = Object.freeze({
  contextDigest: true, proofSessionBinding: true, noteWellFormed: true, noteAppend: true,
  noteMembership: true, authorization: true, nullifierDerivation: true, nullifierNonMembership: true, nullifierInsertion: true,
});

function makeContext({ actionKind, preHex, postHex, preValue, postValue, payout = null, change = null, fee = '500' }) {
  const stateInput = { index: 0, role: 'STATE', roleOrdinal: 0, outpointTxidWireHex: h('55'), outpointIndex: 0, sequence: 4294967295, sourceValueSats: preValue, sourceLockingBytecodeHex: '51', sourceToken: { categoryHex: proofFreeConfig.stateTokenCategoryHex, capability: 'mutable', commitmentHex: preHex, amount: '0' } };
  const carrierInput = { index: 1, role: 'VERIFIER_CARRIER', roleOrdinal: 0, outpointTxidWireHex: h('55'), outpointIndex: 1, sequence: 4294967295, sourceValueSats: '1000', sourceLockingBytecodeHex: '51', sourceToken: noToken };
  const externalValue = actionKind === 'DEPOSIT' ? (10000000n + BigInt(fee) + BigInt(change?.valueSats ?? '0')).toString() : (BigInt(fee) + BigInt(change?.valueSats ?? '0')).toString();
  const external = { index: 2, role: actionKind === 'DEPOSIT' ? 'DEPOSIT_FUNDING' : 'FEE_FUNDING', roleOrdinal: 0, outpointTxidWireHex: h('66'), outpointIndex: 7, sequence: 4294967295, sourceValueSats: externalValue, sourceLockingBytecodeHex: '51', sourceToken: noToken };
  const outputs = [
    { index: 0, role: 'STATE_SUCCESSOR', roleOrdinal: 0, valueSats: postValue, lockingBytecodeHex: '51', token: { categoryHex: proofFreeConfig.stateTokenCategoryHex, capability: 'mutable', commitmentHex: postHex, amount: '0' } },
    { index: 1, role: 'VERIFIER_CARRIER_SUCCESSOR', roleOrdinal: 0, valueSats: '1000', lockingBytecodeHex: '51', token: noToken },
  ];
  if (payout) outputs.push({ index: 2, role: 'PAYOUT', roleOrdinal: 0, valueSats: '10000000', lockingBytecodeHex: payout.lockingBytecodeHex, token: noToken });
  if (change) outputs.push({ index: outputs.length, role: 'TRANSPARENT_CHANGE', roleOrdinal: 0, valueSats: change.valueSats, lockingBytecodeHex: change.lockingBytecodeHex, token: noToken });
  return { codecVersion: 1, networkId: proofFreeConfig.networkId, poolInstanceIdHex: proofFreeConfig.poolInstanceIdHex, actionKind, transactionVersion: 2, locktime: 0, carrierManifestDigestHex: proofFreeConfig.carrierManifestDigestHex, proofSecurityProfileDigestHex: proofFreeConfig.proofSecurityProfileDigestHex, inputs: [stateInput, carrierInput, external], outputs };
}
function directStateInput(context) { const x = context.inputs[0]; return { index: x.index, role: x.role, outpointTxidWireHex: x.outpointTxidWireHex, outpointIndex: x.outpointIndex, sequence: x.sequence, sourceValueSats: x.sourceValueSats, sourceLockingBytecodeHex: x.sourceLockingBytecodeHex, tokenCategoryHex: x.sourceToken.categoryHex, tokenCapability: x.sourceToken.capability, tokenFungibleAmount: x.sourceToken.amount, stateHex: x.sourceToken.commitmentHex }; }
function directStateOutput(context) { const x = context.outputs[0]; return { index: x.index, role: x.role, valueSats: x.valueSats, lockingBytecodeHex: x.lockingBytecodeHex, tokenCategoryHex: x.token.categoryHex, tokenCapability: x.token.capability, tokenFungibleAmount: x.token.amount, stateHex: x.token.commitmentHex }; }

export function proofFreeDepositFixture() {
  const preHex = stateHex({ sequence: 0, deposits: 0, withdrawals: 0, pool: proofFreeConfig.poolInstanceIdHex, note: h('aa'), nullifier: h('bb') });
  const postHex = stateHex({ sequence: 1, deposits: 1, withdrawals: 0, pool: proofFreeConfig.poolInstanceIdHex, note: h('cc'), nullifier: h('bb') });
  const transactionContext = makeContext({ actionKind: 'DEPOSIT', preHex, postHex, preValue: '1000', postValue: '10001000' });
  return { statement: { schema: 'shieldkit-labs/pool-action-fv1-statement/v1', relationVersion: 1, profileId: 'profile:fixed-ticket-serial-pool', networkId: proofFreeConfig.networkId, poolInstanceIdHex: proofFreeConfig.poolInstanceIdHex, proofSecurityProfileDigestHex: proofFreeConfig.proofSecurityProfileDigestHex, actionKind: 'DEPOSIT', stateInput: directStateInput(transactionContext), stateOutput: directStateOutput(transactionContext), ticketSats: '10000000', reserveDeltaSats: '10000000', noteCommitmentHex: h('77'), nullifierHex: ZERO32, payout: null, fee: { policyId: 'transparent-single-input-fv1', transparent: true, externalInputIndex: 2, externalInputRole: 'DEPOSIT_FUNDING', externalAuthorizationMode: 'bch-sighash-all-forkid-0x41', changeOutputIndex: null, feeSats: '500', maxFeeSats: '10000', poolSubsidySats: '0', tokensForbidden: true }, carrierManifestDigestHex: proofFreeConfig.carrierManifestDigestHex, transactionContextDigestHex: h('88'), transactionContext }, config: proofFreeConfig, facts: proofFreeFacts };
}
export function proofFreeWithdrawalFixture() {
  const preHex = stateHex({ sequence: 1, deposits: 1, withdrawals: 0, pool: proofFreeConfig.poolInstanceIdHex, note: h('cc'), nullifier: h('bb') });
  const postHex = stateHex({ sequence: 2, deposits: 1, withdrawals: 1, pool: proofFreeConfig.poolInstanceIdHex, note: h('cc'), nullifier: h('dd') });
  const transactionContext = makeContext({ actionKind: 'WITHDRAWAL', preHex, postHex, preValue: '10001000', postValue: '1000', payout: { lockingBytecodeHex: '51' } });
  return { statement: { schema: 'shieldkit-labs/pool-action-fv1-statement/v1', relationVersion: 1, profileId: 'profile:fixed-ticket-serial-pool', networkId: proofFreeConfig.networkId, poolInstanceIdHex: proofFreeConfig.poolInstanceIdHex, proofSecurityProfileDigestHex: proofFreeConfig.proofSecurityProfileDigestHex, actionKind: 'WITHDRAWAL', stateInput: directStateInput(transactionContext), stateOutput: directStateOutput(transactionContext), ticketSats: '10000000', reserveDeltaSats: '-10000000', noteCommitmentHex: ZERO32, nullifierHex: h('99'), payout: { outputIndex: 2, amountSats: '10000000', lockingBytecodeHex: '51', token: noToken }, fee: { policyId: 'transparent-single-input-fv1', transparent: true, externalInputIndex: 2, externalInputRole: 'FEE_FUNDING', externalAuthorizationMode: 'bch-sighash-all-forkid-0x41', changeOutputIndex: null, feeSats: '500', maxFeeSats: '10000', poolSubsidySats: '0', tokensForbidden: true }, carrierManifestDigestHex: proofFreeConfig.carrierManifestDigestHex, transactionContextDigestHex: h('88'), transactionContext }, config: proofFreeConfig, facts: proofFreeFacts };
}
export const cloneFixture = clone;
