/**
 * PoolActionFv1 P1 semantic oracle.
 *
 * This is deliberately not a prover, verifier, hash implementation, or parser
 * for a selected cryptographic primitive. Cryptographic predicates enter only
 * through injected adapters or explicit, externally-derived witness facts.
 */

export const TICKET_SATS = 10_000_000n;
export const ZERO32 = '00'.repeat(32);
export const MAX_MONEY_SATS = 2_100_000_000_000_000n;

const HEX = /^[0-9a-f]*$/;
const U64 = /^(0|[1-9][0-9]{0,19})$/;
const NETWORK = /^(?:mainnet|chipnet|regtest)$/;

export class PoolActionSemanticError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PoolActionSemanticError';
    this.code = code;
  }
}

function fail(code, message) { throw new PoolActionSemanticError(code, message); }
function require(condition, code, message) { if (!condition) fail(code, message); }
function own(object, keys, code) {
  require(object !== null && typeof object === 'object' && !Array.isArray(object), code, 'must be an object');
  const actual = Object.keys(object).sort();
  const expected = [...keys].sort();
  require(actual.length === expected.length && actual.every((key, i) => key === expected[i]), code, 'has missing or ignored fields');
}
function hex(value, length, code) {
  require(typeof value === 'string' && value === value.toLowerCase() && HEX.test(value) && value.length === length, code, 'non-canonical hex');
}
function bytecode(value, code) {
  require(
    typeof value === 'string'
      && value === value.toLowerCase()
      && value.length > 0
      && value.length <= 20_000
      && value.length % 2 === 0
      && HEX.test(value),
    code,
    'non-canonical or oversized bytecode hex',
  );
}
function u64(value, code) {
  require(typeof value === 'string' && U64.test(value), code, 'must be canonical uint64 decimal');
  const parsed = BigInt(value);
  require(parsed <= 0xffff_ffff_ffff_ffffn, code, 'uint64 overflow');
  return parsed;
}
function sats(value, code) {
  const parsed = u64(value, code);
  require(parsed <= MAX_MONEY_SATS, code, 'BCH monetary range overflow');
  return parsed;
}
function equal(a, b, code, message) { require(a === b, code, message); }
function tokenNone(token, code) {
  own(token, ['categoryHex', 'capability', 'commitmentHex', 'amount'], code);
  equal(token.categoryHex, '', code, 'token category must be absent');
  equal(token.capability, 'none', code, 'token capability must be none');
  equal(token.commitmentHex, '', code, 'token commitment must be absent');
  equal(token.amount, '0', code, 'token amount must be zero');
}
function tokenMutableState(token, categoryHex, stateHex, code) {
  own(token, ['categoryHex', 'capability', 'commitmentHex', 'amount'], code);
  equal(token.categoryHex, categoryHex, code, 'wrong state category');
  equal(token.capability, 'mutable', code, 'state token must be mutable');
  equal(token.commitmentHex, stateHex, code, 'state commitment mismatch');
  equal(token.amount, '0', code, 'state token fungible amount must be zero');
}
function tokenCanonical(token, code) {
  own(token, ['categoryHex', 'capability', 'commitmentHex', 'amount'], code);
  if (token.capability === 'none') {
    tokenNone(token, code);
    return;
  }
  hex(token.categoryHex, 64, code);
  const amount = u64(token.amount, code);
  if (token.capability === 'fungible-only') {
    equal(token.commitmentHex, '', code, 'fungible-only token commitment must be absent');
    require(amount > 0n, code, 'fungible-only token amount must be nonzero');
    return;
  }
  require(
    token.capability === 'immutable' || token.capability === 'mutable' || token.capability === 'minting',
    code,
    'unknown token capability',
  );
  require(
    typeof token.commitmentHex === 'string'
      && token.commitmentHex === token.commitmentHex.toLowerCase()
      && HEX.test(token.commitmentHex)
      && token.commitmentHex.length % 2 === 0
      && token.commitmentHex.length <= 256,
    code,
    'non-canonical NFT commitment',
  );
}

/** Decode the frozen PAF1 state bytes; no hash or accumulator primitive is used. */
export function decodePoolStateFv1(stateHex) {
  hex(stateHex, 256, 'ERR_STATE_CODEC_OR_INVARIANT');
  const bytes = Buffer.from(stateHex, 'hex');
  require(bytes.subarray(0, 4).equals(Buffer.from('PAF1')), 'ERR_STATE_CODEC_OR_INVARIANT', 'bad PAF1 magic');
  require(bytes.readUInt16LE(4) === 1, 'ERR_STATE_CODEC_OR_INVARIANT', 'unsupported state codec version');
  require(bytes.readUInt16LE(6) === 0, 'ERR_STATE_CODEC_OR_INVARIANT', 'reserved state bytes must be zero');
  return Object.freeze({
    stateCodecVersion: 1,
    sequence: bytes.readBigUInt64LE(8),
    depositCount: bytes.readBigUInt64LE(16),
    withdrawalCount: bytes.readBigUInt64LE(24),
    poolInstanceIdHex: bytes.subarray(32, 64).toString('hex'),
    noteRootHex: bytes.subarray(64, 96).toString('hex'),
    nullifierRootHex: bytes.subarray(96, 128).toString('hex'),
  });
}

function validateState(state, config, valueSats, code) {
  equal(state.poolInstanceIdHex, config.poolInstanceIdHex, code, 'wrong pool instance');
  require(state.withdrawalCount <= state.depositCount, code, 'withdrawal count exceeds deposits');
  require(state.depositCount <= config.maxLifetimeDeposits, code, 'deposit count exceeds lifetime cap');
  const reserve = (state.depositCount - state.withdrawalCount) * TICKET_SATS;
  equal(valueSats, config.stateCarrierBaseSats + reserve, code, 'state value/reserve equation mismatch');
}

function verifyFact(name, payload, adapters, facts) {
  const adapter = adapters?.[name];
  if (adapter !== undefined) {
    require(typeof adapter === 'function', 'ERR_WITNESS_RESULT', `${name} adapter is not a function`);
    require(adapter(Object.freeze(payload)) === true, 'ERR_WITNESS_RESULT', `${name} adapter rejected`);
    return;
  }
  require(facts?.[name] === true, 'ERR_WITNESS_RESULT', `${name} needs an injected adapter or explicit true fact`);
}

function directStateInputFromContext(input) {
  return {
    index: input.index, role: input.role, outpointTxidWireHex: input.outpointTxidWireHex,
    outpointIndex: input.outpointIndex, sequence: input.sequence, sourceValueSats: input.sourceValueSats,
    sourceLockingBytecodeHex: input.sourceLockingBytecodeHex, tokenCategoryHex: input.sourceToken.categoryHex,
    tokenCapability: input.sourceToken.capability, tokenFungibleAmount: input.sourceToken.amount,
    stateHex: input.sourceToken.commitmentHex,
  };
}
function directStateOutputFromContext(output) {
  return {
    index: output.index, role: output.role, valueSats: output.valueSats,
    lockingBytecodeHex: output.lockingBytecodeHex, tokenCategoryHex: output.token.categoryHex,
    tokenCapability: output.token.capability, tokenFungibleAmount: output.token.amount,
    stateHex: output.token.commitmentHex,
  };
}
function exactValue(a, b) {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b)
      && a.length === b.length
      && a.every((value, index) => exactValue(value, b[index]));
  }
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  const aKeys = Object.keys(a).sort();
  const bKeys = Object.keys(b).sort();
  return aKeys.length === bKeys.length
    && aKeys.every((key, index) => key === bKeys[index] && exactValue(a[key], b[key]));
}
function exactObject(a, b, code) { require(exactValue(a, b), code, 'direct statement/context projection mismatch'); }

function validateConfig(config) {
  own(config, [
    'networkId', 'poolInstanceIdHex', 'proofSecurityProfileDigestHex', 'carrierManifestDigestHex',
    'stateCarrierBaseSats', 'maxLifetimeDeposits', 'maxFeeSats', 'stateLockingBytecodeHex',
    'stateTokenCategoryHex',
  ], 'ERR_CONFIG');
  require(typeof config.networkId === 'string' && NETWORK.test(config.networkId), 'ERR_CONFIG', 'unsupported network');
  hex(config.poolInstanceIdHex, 64, 'ERR_CONFIG');
  hex(config.proofSecurityProfileDigestHex, 64, 'ERR_CONFIG');
  hex(config.carrierManifestDigestHex, 64, 'ERR_CONFIG');
  hex(config.stateTokenCategoryHex, 64, 'ERR_CONFIG');
  bytecode(config.stateLockingBytecodeHex, 'ERR_CONFIG');
  const stateCarrierBaseSats = sats(config.stateCarrierBaseSats, 'ERR_CONFIG');
  const maxLifetimeDeposits = u64(config.maxLifetimeDeposits, 'ERR_CONFIG');
  require(
    maxLifetimeDeposits <= (MAX_MONEY_SATS - stateCarrierBaseSats) / TICKET_SATS,
    'ERR_CONFIG',
    'lifetime capacity can exceed BCH monetary range',
  );
  return Object.freeze({ ...config, stateCarrierBaseSats, maxLifetimeDeposits, maxFeeSats: sats(config.maxFeeSats, 'ERR_CONFIG') });
}

function validateContext(statement, config) {
  const context = statement.transactionContext;
  own(context, ['codecVersion', 'networkId', 'poolInstanceIdHex', 'actionKind', 'transactionVersion', 'locktime', 'carrierManifestDigestHex', 'proofSecurityProfileDigestHex', 'inputs', 'outputs'], 'ERR_CONTEXT_CODEC');
  equal(context.codecVersion, 1, 'ERR_CONTEXT_CODEC', 'wrong context version');
  equal(context.networkId, statement.networkId, 'ERR_STATEMENT_CONTEXT', 'network mismatch');
  equal(context.poolInstanceIdHex, statement.poolInstanceIdHex, 'ERR_STATEMENT_CONTEXT', 'pool mismatch');
  equal(context.actionKind, statement.actionKind, 'ERR_STATEMENT_CONTEXT', 'action mismatch');
  equal(context.transactionVersion, 2, 'ERR_CONTEXT_CODEC', 'wrong transaction version');
  equal(context.locktime, 0, 'ERR_CONTEXT_CODEC', 'wrong locktime');
  equal(context.carrierManifestDigestHex, statement.carrierManifestDigestHex, 'ERR_STATEMENT_CONTEXT', 'manifest mismatch');
  equal(context.proofSecurityProfileDigestHex, statement.proofSecurityProfileDigestHex, 'ERR_STATEMENT_CONTEXT', 'security profile mismatch');
  require(Array.isArray(context.inputs) && Array.isArray(context.outputs), 'ERR_CONTEXT_CODEC', 'inputs/outputs must be arrays');
  require(context.inputs.length <= 65_535 && context.outputs.length <= 65_535, 'ERR_CONTEXT_CODEC', 'input/output count exceeds uint16');
  // The direct statement fixes the sole external input position. Deriving N
  // from it, rather than from an attacker-supplied array length, makes extras
  // observable as extras rather than silently reclassifying them as carriers.
  require(Number.isInteger(statement.fee?.externalInputIndex), 'ERR_FEE_POLICY', 'missing external input index');
  const carrierCount = statement.fee.externalInputIndex - 1;
  require(carrierCount >= 1 && context.outputs.length >= carrierCount + 1, 'ERR_TOPOLOGY_OR_CARRIER', 'missing persistent carrier');
  return { context, carrierCount };
}

function validateDirectFee(fee) {
  own(fee, ['policyId', 'transparent', 'externalInputIndex', 'externalInputRole', 'externalAuthorizationMode', 'changeOutputIndex', 'feeSats', 'maxFeeSats', 'poolSubsidySats', 'tokensForbidden'], 'ERR_FEE_POLICY');
  require(Number.isInteger(fee.externalInputIndex) && fee.externalInputIndex >= 2 && fee.externalInputIndex <= 65_535, 'ERR_FEE_POLICY', 'bad external input index');
  require(fee.externalInputRole === 'DEPOSIT_FUNDING' || fee.externalInputRole === 'FEE_FUNDING', 'ERR_FEE_POLICY', 'bad external input role');
  require(fee.changeOutputIndex === null || (Number.isInteger(fee.changeOutputIndex) && fee.changeOutputIndex >= 1 && fee.changeOutputIndex <= 65_535), 'ERR_FEE_POLICY', 'bad change output index');
  sats(fee.feeSats, 'ERR_FEE_POLICY'); sats(fee.maxFeeSats, 'ERR_FEE_POLICY');
  equal(fee.poolSubsidySats, '0', 'ERR_FEE_POLICY', 'pool fee subsidy is forbidden');
}

function validateInput(input, index, expectedRole, ordinal, tokenCode = 'ERR_CONTEXT_CODEC') {
  own(input, ['index', 'role', 'roleOrdinal', 'outpointTxidWireHex', 'outpointIndex', 'sequence', 'sourceValueSats', 'sourceLockingBytecodeHex', 'sourceToken'], 'ERR_CONTEXT_CODEC');
  equal(input.index, index, 'ERR_INPUT_OUTPUT_ORDER', 'input index mismatch');
  equal(input.role, expectedRole, 'ERR_INPUT_OUTPUT_ORDER', 'input role mismatch');
  equal(input.roleOrdinal, ordinal, 'ERR_INPUT_OUTPUT_ORDER', 'input ordinal mismatch');
  require(input.index <= 65_535 && input.roleOrdinal <= 65_535, 'ERR_CONTEXT_CODEC', 'input index/ordinal exceeds uint16');
  hex(input.outpointTxidWireHex, 64, 'ERR_CONTEXT_CODEC');
  require(Number.isInteger(input.outpointIndex) && input.outpointIndex >= 0 && input.outpointIndex <= 0xffff_ffff, 'ERR_CONTEXT_CODEC', 'bad input outpoint index');
  equal(input.sequence, 0xffff_ffff, 'ERR_CONTEXT_CODEC', 'wrong input sequence');
  sats(input.sourceValueSats, 'ERR_CONTEXT_CODEC');
  bytecode(input.sourceLockingBytecodeHex, 'ERR_CONTEXT_CODEC');
  tokenCanonical(input.sourceToken, tokenCode);
}
function validateOutput(output, index, expectedRole, ordinal, tokenCode = 'ERR_CONTEXT_CODEC') {
  own(output, ['index', 'role', 'roleOrdinal', 'valueSats', 'lockingBytecodeHex', 'token'], 'ERR_CONTEXT_CODEC');
  equal(output.index, index, 'ERR_INPUT_OUTPUT_ORDER', 'output index mismatch');
  equal(output.role, expectedRole, 'ERR_INPUT_OUTPUT_ORDER', 'output role mismatch');
  equal(output.roleOrdinal, ordinal, 'ERR_INPUT_OUTPUT_ORDER', 'output ordinal mismatch');
  require(output.index <= 65_535 && output.roleOrdinal <= 65_535, 'ERR_CONTEXT_CODEC', 'output index/ordinal exceeds uint16');
  sats(output.valueSats, 'ERR_CONTEXT_CODEC');
  bytecode(output.lockingBytecodeHex, 'ERR_CONTEXT_CODEC');
  tokenCanonical(output.token, tokenCode);
}

function validateTopologyAndFee(statement, config, context, carrierCount) {
  const { inputs, outputs } = context;
  validateInput(inputs[0], 0, 'STATE', 0, 'ERR_STATE_TOKEN');
  require(inputs[0].outpointIndex === 0, 'ERR_STATE_LINEAGE_OR_SUCCESSOR', 'state source must be vout zero');
  tokenMutableState(inputs[0].sourceToken, config.stateTokenCategoryHex, statement.stateInput.stateHex, 'ERR_STATE_TOKEN');
  exactObject(statement.stateInput, directStateInputFromContext(inputs[0]), 'ERR_STATEMENT_CONTEXT');
  for (let i = 0; i < carrierCount; i += 1) {
    const input = inputs[i + 1];
    validateInput(input, i + 1, 'VERIFIER_CARRIER', i, 'ERR_TOPOLOGY_OR_CARRIER');
    equal(input.outpointTxidWireHex, inputs[0].outpointTxidWireHex, 'ERR_STATE_LINEAGE_OR_SUCCESSOR', 'carrier must share predecessor txid');
    equal(input.outpointIndex, i + 1, 'ERR_STATE_LINEAGE_OR_SUCCESSOR', 'carrier predecessor vout mismatch');
  }
  const external = inputs[carrierCount + 1];
  validateInput(external, carrierCount + 1, statement.fee.externalInputRole, 0, 'ERR_FEE_POLICY');
  tokenNone(external.sourceToken, 'ERR_FEE_POLICY');
  equal(statement.fee.externalInputIndex, carrierCount + 1, 'ERR_FEE_POLICY', 'external funding index mismatch');
  require(inputs.length === carrierCount + 2, 'ERR_NO_IGNORED_CONTEXT', 'extra input');

  validateOutput(outputs[0], 0, 'STATE_SUCCESSOR', 0, 'ERR_STATE_TOKEN');
  tokenMutableState(outputs[0].token, config.stateTokenCategoryHex, statement.stateOutput.stateHex, 'ERR_STATE_TOKEN');
  exactObject(statement.stateOutput, directStateOutputFromContext(outputs[0]), 'ERR_STATEMENT_CONTEXT');
  for (let i = 0; i < carrierCount; i += 1) {
    const input = inputs[i + 1];
    const output = outputs[i + 1];
    validateOutput(output, i + 1, 'VERIFIER_CARRIER_SUCCESSOR', i, 'ERR_TOPOLOGY_OR_CARRIER');
    exactObject(output.token, input.sourceToken, 'ERR_TOPOLOGY_OR_CARRIER');
    equal(output.valueSats, input.sourceValueSats, 'ERR_TOPOLOGY_OR_CARRIER', 'carrier value changed');
    equal(output.lockingBytecodeHex, input.sourceLockingBytecodeHex, 'ERR_TOPOLOGY_OR_CARRIER', 'carrier lock changed');
  }

  const payoutIndex = carrierCount + 1;
  const changeIndex = statement.actionKind === 'DEPOSIT' ? carrierCount + 1 : carrierCount + 2;
  if (statement.actionKind === 'WITHDRAWAL') {
    validateOutput(outputs[payoutIndex], payoutIndex, 'PAYOUT', 0, 'ERR_PAYOUT');
    tokenNone(outputs[payoutIndex].token, 'ERR_PAYOUT');
    exactObject(statement.payout, { outputIndex: payoutIndex, amountSats: outputs[payoutIndex].valueSats, lockingBytecodeHex: outputs[payoutIndex].lockingBytecodeHex, token: outputs[payoutIndex].token }, 'ERR_PAYOUT');
  }
  const expectedWithoutChange = statement.actionKind === 'WITHDRAWAL' ? carrierCount + 2 : carrierCount + 1;
  if (statement.fee.changeOutputIndex === null) {
    require(outputs.length === expectedWithoutChange, 'ERR_NO_IGNORED_CONTEXT', 'unexpected output');
  } else {
    equal(statement.fee.changeOutputIndex, changeIndex, 'ERR_FEE_POLICY', 'change index mismatch');
    validateOutput(outputs[changeIndex], changeIndex, 'TRANSPARENT_CHANGE', 0, 'ERR_FEE_POLICY');
    tokenNone(outputs[changeIndex].token, 'ERR_FEE_POLICY');
    require(outputs.length === expectedWithoutChange + 1, 'ERR_NO_IGNORED_CONTEXT', 'extra output');
  }

  const sourceTotal = inputs.reduce((sum, input) => sum + sats(input.sourceValueSats, 'ERR_CONTEXT_CODEC'), 0n);
  const outputTotal = outputs.reduce((sum, output) => sum + sats(output.valueSats, 'ERR_CONTEXT_CODEC'), 0n);
  require(sourceTotal <= MAX_MONEY_SATS && outputTotal <= MAX_MONEY_SATS, 'ERR_CONSERVATION', 'transaction total exceeds BCH monetary range');
  const fee = sats(statement.fee.feeSats, 'ERR_FEE_POLICY');
  equal(sourceTotal - outputTotal, fee, 'ERR_FEE_POLICY', 'fee does not equal transaction balance');
  const statementMaxFee = sats(statement.fee.maxFeeSats, 'ERR_FEE_POLICY');
  equal(statementMaxFee, config.maxFeeSats, 'ERR_FEE_POLICY', 'statement fee cap differs from immutable config');
  require(fee <= statementMaxFee, 'ERR_FEE_POLICY', 'fee exceeds immutable cap');
  equal(statement.fee.poolSubsidySats, '0', 'ERR_FEE_POLICY', 'pool fee subsidy is forbidden');
  equal(statement.fee.transparent, true, 'ERR_FEE_POLICY', 'fee policy must be transparent');
  equal(statement.fee.policyId, 'transparent-single-input-fv1', 'ERR_FEE_POLICY', 'wrong fee policy');
  equal(statement.fee.externalAuthorizationMode, 'bch-sighash-all-forkid-0x41', 'ERR_FEE_POLICY', 'wrong external sighash mode');
  equal(statement.fee.tokensForbidden, true, 'ERR_FEE_POLICY', 'external tokens forbidden');
  const change = statement.fee.changeOutputIndex === null ? 0n : sats(outputs[changeIndex].valueSats, 'ERR_FEE_POLICY');
  const externalValue = sats(external.sourceValueSats, 'ERR_FEE_POLICY');
  if (statement.actionKind === 'DEPOSIT') equal(externalValue, TICKET_SATS + change + fee, 'ERR_CONSERVATION', 'deposit funding equation');
  else equal(externalValue, change + fee, 'ERR_CONSERVATION', 'withdrawal fee funding equation');
}

/**
 * Verify the P1 accepted language, conditional on injected non-cryptographic
 * witness-result facts/adapters. A true result is explicitly proof-free.
 */
export function verifyPoolActionFv1Semantic({ statement, config, facts = {}, adapters = {} }) {
  const c = validateConfig(config);
  own(statement, [
    'schema', 'relationVersion', 'profileId', 'networkId', 'poolInstanceIdHex', 'proofSecurityProfileDigestHex',
    'actionKind', 'stateInput', 'stateOutput', 'ticketSats', 'reserveDeltaSats', 'noteCommitmentHex',
    'nullifierHex', 'payout', 'fee', 'carrierManifestDigestHex', 'transactionContextDigestHex', 'transactionContext',
  ], 'ERR_STATEMENT_CODEC');
  equal(statement.schema, 'shieldkit-labs/pool-action-fv1-statement/v1', 'ERR_STATEMENT_CODEC', 'wrong statement schema');
  equal(statement.relationVersion, 1, 'ERR_STATEMENT_CODEC', 'wrong relation version');
  equal(statement.profileId, 'profile:fixed-ticket-serial-pool', 'ERR_STATEMENT_CODEC', 'wrong profile');
  equal(statement.networkId, c.networkId, 'ERR_POOL_OR_NETWORK', 'wrong network');
  equal(statement.poolInstanceIdHex, c.poolInstanceIdHex, 'ERR_POOL_OR_NETWORK', 'wrong pool');
  equal(statement.proofSecurityProfileDigestHex, c.proofSecurityProfileDigestHex, 'ERR_POOL_OR_NETWORK', 'wrong security profile');
  equal(statement.carrierManifestDigestHex, c.carrierManifestDigestHex, 'ERR_POOL_OR_NETWORK', 'wrong carrier manifest');
  require(statement.actionKind === 'DEPOSIT' || statement.actionKind === 'WITHDRAWAL', 'ERR_ACTION_SELECTOR', 'only deposit/withdrawal are valid');
  equal(statement.ticketSats, '10000000', 'ERR_TICKET_VALUE', 'wrong ticket');
  hex(statement.noteCommitmentHex, 64, 'ERR_NOTE_OR_NULLIFIER');
  hex(statement.nullifierHex, 64, 'ERR_NOTE_OR_NULLIFIER');
  hex(statement.transactionContextDigestHex, 64, 'ERR_CONTEXT_CODEC');
  validateDirectFee(statement.fee);
  const { context, carrierCount } = validateContext(statement, c);
  validateTopologyAndFee(statement, c, context, carrierCount);
  const pre = decodePoolStateFv1(statement.stateInput.stateHex);
  const post = decodePoolStateFv1(statement.stateOutput.stateHex);
  validateState(pre, c, sats(statement.stateInput.sourceValueSats, 'ERR_STATE_CODEC_OR_INVARIANT'), 'ERR_STATE_CODEC_OR_INVARIANT');
  validateState(post, c, sats(statement.stateOutput.valueSats, 'ERR_STATE_CODEC_OR_INVARIANT'), 'ERR_STATE_CODEC_OR_INVARIANT');
  equal(statement.stateInput.sourceLockingBytecodeHex, c.stateLockingBytecodeHex, 'ERR_STATE_LINEAGE_OR_SUCCESSOR', 'wrong state source lock');
  equal(statement.stateOutput.lockingBytecodeHex, c.stateLockingBytecodeHex, 'ERR_STATE_LINEAGE_OR_SUCCESSOR', 'wrong state successor lock');
  equal(post.sequence, pre.sequence + 1n, 'ERR_STATE_COUNTER', 'sequence must increment once');
  const reserveDelta = statement.actionKind === 'DEPOSIT' ? '10000000' : '-10000000';
  equal(statement.reserveDeltaSats, reserveDelta, 'ERR_TICKET_VALUE', 'wrong or non-canonical reserve delta');

  if (statement.actionKind === 'DEPOSIT') {
    equal(post.depositCount, pre.depositCount + 1n, 'ERR_STATE_COUNTER', 'deposit count must increment');
    equal(post.withdrawalCount, pre.withdrawalCount, 'ERR_STATE_COUNTER', 'withdrawal count must not change');
    require(pre.depositCount < c.maxLifetimeDeposits, 'ERR_LIFETIME_CAPACITY', 'deposit capacity exhausted');
    require(post.noteRootHex !== pre.noteRootHex, 'ERR_NOTE_OR_NULLIFIER', 'deposit note root must change');
    equal(post.nullifierRootHex, pre.nullifierRootHex, 'ERR_NOTE_OR_NULLIFIER', 'deposit nullifier root must not change');
    require(statement.noteCommitmentHex !== ZERO32, 'ERR_NOTE_OR_NULLIFIER', 'deposit note commitment must be nonzero');
    equal(statement.nullifierHex, ZERO32, 'ERR_NOTE_OR_NULLIFIER', 'deposit nullifier must be zero');
    equal(statement.payout, null, 'ERR_PAYOUT', 'deposit payout must be absent');
    equal(statement.fee.externalInputRole, 'DEPOSIT_FUNDING', 'ERR_FEE_POLICY', 'deposit funding role');
    verifyFact('contextDigest', { statement, context }, adapters, facts);
    verifyFact('proofSessionBinding', { statement, context, carrierCount }, adapters, facts);
    verifyFact('noteWellFormed', { statement, pre, post }, adapters, facts);
    verifyFact('noteAppend', { statement, pre, post }, adapters, facts);
  } else {
    equal(post.depositCount, pre.depositCount, 'ERR_STATE_COUNTER', 'withdrawal deposit count must not change');
    equal(post.withdrawalCount, pre.withdrawalCount + 1n, 'ERR_STATE_COUNTER', 'withdrawal count must increment');
    equal(post.noteRootHex, pre.noteRootHex, 'ERR_NOTE_OR_NULLIFIER', 'withdrawal note root must not change');
    require(post.nullifierRootHex !== pre.nullifierRootHex, 'ERR_NOTE_OR_NULLIFIER', 'withdrawal nullifier root must change');
    equal(statement.noteCommitmentHex, ZERO32, 'ERR_NOTE_OR_NULLIFIER', 'withdrawal note commitment must be zero');
    require(statement.nullifierHex !== ZERO32, 'ERR_NOTE_OR_NULLIFIER', 'withdrawal nullifier must be nonzero');
    require(statement.payout !== null, 'ERR_PAYOUT', 'withdrawal requires payout');
    equal(statement.payout.amountSats, '10000000', 'ERR_PAYOUT', 'wrong payout amount');
    tokenNone(statement.payout.token, 'ERR_PAYOUT');
    equal(statement.fee.externalInputRole, 'FEE_FUNDING', 'ERR_FEE_POLICY', 'withdrawal funding role');
    verifyFact('contextDigest', { statement, context }, adapters, facts);
    verifyFact('proofSessionBinding', { statement, context, carrierCount }, adapters, facts);
    verifyFact('noteMembership', { statement, pre, post }, adapters, facts);
    verifyFact('authorization', { statement, pre, post }, adapters, facts);
    verifyFact('nullifierDerivation', { statement, pre, post }, adapters, facts);
    verifyFact('nullifierNonMembership', { statement, pre, post }, adapters, facts);
    verifyFact('nullifierInsertion', { statement, pre, post }, adapters, facts);
  }
  return Object.freeze({ ok: true, proofFree: true, actionKind: statement.actionKind, carrierCount });
}
