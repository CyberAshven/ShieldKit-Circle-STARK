import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from 'node:crypto';

import { bytesToHex, hexToBytes } from "./common.mjs";
import { decodePoolState, encodePoolState, poolStateHex } from "./pool-state.mjs";
import {
  decodeTokenRecord,
  encodeTokenRecord,
  tokenRecordHex,
} from "./token-record.mjs";
import {
  decodeTxContext,
  encodeTxContext,
  txContextDomainPreimage,
  txContextHex,
} from "./tx-context.mjs";
import {
  decodePoolActionStatement,
  encodePoolActionStatement,
  payoutLockDomainPreimage,
  poolActionStatementHex,
} from "./pool-action-statement.mjs";
import {
  encodePoolActionJsonStatement,
  projectPoolActionJsonStatement,
} from './statement-projection.mjs';

const ZERO32 = "00".repeat(32);
const NONE = { categoryHex: "", capability: "none", commitmentHex: "", amount: "0" };
const byteRamp = (start = 0) => Array.from(
  { length: 32 },
  (_, index) => ((start + index) & 0xff).toString(16).padStart(2, '0'),
).join('');
const STATE_CATEGORY = byteRamp(0x20);
const WIRE_TXID = byteRamp(0x80);
const sha256Hex = (bytes) => createHash('sha256').update(bytes).digest('hex');

// Fixture status: semantic-only. These bytes are mechanically derived from
// the frozen wire tables; no cryptographic digest is fabricated or recorded.
const stateFixture = {
  schema: "shieldkit-labs/pool-state-fv1/v1",
  magic: "PAF1",
  stateCodecVersion: 1,
  reservedHex: "0000",
  sequence: "1",
  depositCount: "2",
  withdrawalCount: "1",
  poolInstanceIdHex: "00".repeat(32),
  noteRootHex: "20".repeat(32),
  nullifierRootHex: "40".repeat(32),
};

const stateFixtureHex =
  "50414631" +
  "0100" +
  "0000" +
  "0100000000000000" +
  "0200000000000000" +
  "0100000000000000" +
  "00".repeat(32) +
  "20".repeat(32) +
  "40".repeat(32);

const stateToken = {
  categoryHex: STATE_CATEGORY,
  capability: "mutable",
  commitmentHex: "01".repeat(128),
  amount: "0",
};

const contextFixture = {
  codecVersion: 1,
  networkId: "chipnet",
  poolInstanceIdHex: "01".repeat(32),
  actionKind: "DEPOSIT",
  transactionVersion: 2,
  locktime: 0,
  carrierManifestDigestHex: "02".repeat(32),
  proofSecurityProfileDigestHex: "03".repeat(32),
  inputs: [
    {
      index: 0,
      role: "STATE",
      roleOrdinal: 0,
      outpointTxidWireHex: WIRE_TXID,
      outpointIndex: 0,
      sequence: 0xffffffff,
      sourceValueSats: "10000000",
      sourceLockingBytecodeHex: "51",
      sourceToken: stateToken,
    },
    {
      index: 1,
      role: "VERIFIER_CARRIER",
      roleOrdinal: 0,
      outpointTxidWireHex: WIRE_TXID,
      outpointIndex: 1,
      sequence: 0xffffffff,
      sourceValueSats: "5000",
      sourceLockingBytecodeHex: "52",
      sourceToken: NONE,
    },
    {
      index: 2,
      role: "DEPOSIT_FUNDING",
      roleOrdinal: 0,
      outpointTxidWireHex: "20".repeat(32),
      outpointIndex: 0,
      sequence: 0xffffffff,
      sourceValueSats: "10001000",
      sourceLockingBytecodeHex: "53",
      sourceToken: NONE,
    },
  ],
  outputs: [
    {
      index: 0,
      role: "STATE_SUCCESSOR",
      roleOrdinal: 0,
      valueSats: "20000000",
      lockingBytecodeHex: "54",
      token: { ...stateToken, commitmentHex: "02".repeat(128) },
    },
    {
      index: 1,
      role: "VERIFIER_CARRIER_SUCCESSOR",
      roleOrdinal: 0,
      valueSats: "5000",
      lockingBytecodeHex: "52",
      token: NONE,
    },
  ],
};

const statementFixture = {
  relationVersion: 1,
  profileTag: 1,
  networkId: "chipnet",
  actionKind: "DEPOSIT",
  poolInstanceIdHex: "01".repeat(32),
  proofSecurityProfileDigestHex: "02".repeat(32),
  carrierManifestDigestHex: "03".repeat(32),
  oldStateOutpointTxidWireHex: "04".repeat(32),
  oldStateOutpointIndex: 0,
  oldStateValueSats: "10000000",
  oldStateBytesHex: "00".repeat(128),
  newStateOutputIndex: 0,
  newStateValueSats: "20000000",
  newStateBytesHex: "ff".repeat(128),
  ticketSats: "10000000",
  reserveDeltaSats: "10000000",
  noteCommitmentOrZeroHex: "05".repeat(32),
  nullifierOrZeroHex: ZERO32,
  payoutOutputIndexOrffff: 0xffff,
  payoutSatsOrZero: "0",
  payoutLockingBytecodeDigestOrZeroHex: ZERO32,
  feeInputIndex: 2,
  transparentChangeOutputIndexOrffff: 0xffff,
  feeSats: "1000",
  maxFeeSats: "2000",
  transactionContextDigestHex: "06".repeat(32),
};

const jsonStateInput = (context) => {
  const input = context.inputs[0];
  return {
    index: 0,
    role: 'STATE',
    outpointTxidWireHex: input.outpointTxidWireHex,
    outpointIndex: 0,
    sequence: input.sequence,
    sourceValueSats: input.sourceValueSats,
    sourceLockingBytecodeHex: input.sourceLockingBytecodeHex,
    tokenCategoryHex: input.sourceToken.categoryHex,
    tokenCapability: input.sourceToken.capability,
    tokenFungibleAmount: input.sourceToken.amount,
    stateHex: input.sourceToken.commitmentHex,
  };
};

const jsonStateOutput = (context) => {
  const output = context.outputs[0];
  return {
    index: 0,
    role: 'STATE_SUCCESSOR',
    valueSats: output.valueSats,
    lockingBytecodeHex: output.lockingBytecodeHex,
    tokenCategoryHex: output.token.categoryHex,
    tokenCapability: output.token.capability,
    tokenFungibleAmount: output.token.amount,
    stateHex: output.token.commitmentHex,
  };
};

const jsonStatement = (context, { payout = null } = {}) => ({
  schema: 'shieldkit-labs/pool-action-fv1-statement/v1',
  relationVersion: 1,
  profileId: 'profile:fixed-ticket-serial-pool',
  networkId: context.networkId,
  poolInstanceIdHex: context.poolInstanceIdHex,
  proofSecurityProfileDigestHex: context.proofSecurityProfileDigestHex,
  actionKind: context.actionKind,
  stateInput: jsonStateInput(context),
  stateOutput: jsonStateOutput(context),
  ticketSats: '10000000',
  reserveDeltaSats: context.actionKind === 'DEPOSIT' ? '10000000' : '-10000000',
  noteCommitmentHex: context.actionKind === 'DEPOSIT' ? '70'.repeat(32) : ZERO32,
  nullifierHex: context.actionKind === 'DEPOSIT' ? ZERO32 : '71'.repeat(32),
  payout,
  fee: {
    policyId: 'transparent-single-input-fv1',
    transparent: true,
    externalInputIndex: context.inputs.length - 1,
    externalInputRole: context.actionKind === 'DEPOSIT' ? 'DEPOSIT_FUNDING' : 'FEE_FUNDING',
    externalAuthorizationMode: 'bch-sighash-all-forkid-0x41',
    changeOutputIndex: null,
    feeSats: '1000',
    maxFeeSats: '2000',
    poolSubsidySats: '0',
    tokensForbidden: true,
  },
  carrierManifestDigestHex: context.carrierManifestDigestHex,
  transactionContextDigestHex: '72'.repeat(32),
  transactionContext: context,
});

test("PoolStateFv1 exact 128-byte KAT and full-consumption roundtrip", () => {
  assert.equal(poolStateHex(stateFixture), stateFixtureHex);
  const encoded = encodePoolState({ ...stateFixture, serializedHex: stateFixtureHex });
  assert.equal(encoded.length, 128);
  const decoded = decodePoolState(encoded);
  assert.deepEqual(decoded, { ...stateFixture, serializedHex: stateFixtureHex });
  assert.deepEqual(decodePoolState(stateFixtureHex), decoded);
});

test("PoolStateFv1 rejects aliases, reserved bytes, range overflow, and suffixes", () => {
  assert.throws(() => encodePoolState({ ...stateFixture, poolInstanceIdHex: "AA".repeat(32) }), /lowercase/);
  assert.throws(() => decodePoolState(`${stateFixtureHex}00`), /exactly 128/);
  assert.throws(() => encodePoolState({ ...stateFixture, reservedHex: "0100" }), /reservedHex/);
  assert.throws(() => encodePoolState({ ...stateFixture, sequence: "18446744073709551616" }), /uint64/);
});

test("canonical token record encodes kind, wire category, amount, and commitment", () => {
  assert.equal(tokenRecordHex(NONE), "00");
  const fungible = {
    categoryHex: "11".repeat(32), capability: "fungible-only", commitmentHex: "", amount: "5",
  };
  assert.equal(tokenRecordHex(fungible), "01" + "11".repeat(32) + "0500000000000000" + "00");
  const nft = {
    categoryHex: "22".repeat(32), capability: "mutable", commitmentHex: "aabb", amount: "0",
  };
  assert.equal(tokenRecordHex(nft), "03" + "22".repeat(32) + "0000000000000000" + "02aabb");
  assert.deepEqual(decodeTokenRecord(encodeTokenRecord(nft)), nft);
  const orderSentinel = {
    categoryHex: byteRamp(0), capability: 'mutable', commitmentHex: '', amount: '0',
  };
  assert.equal(
    tokenRecordHex(orderSentinel),
    `03${byteRamp(0)}000000000000000000`,
    'categoryWire32 must retain exact adapter byte order',
  );
});

test("token record rejects kind aliases, invalid lengths, and trailing bytes", () => {
  assert.throws(() => encodeTokenRecord({ ...NONE, categoryHex: ZERO32 }), /none token/);
  assert.throws(() => encodeTokenRecord({ ...NONE, capability: "fungible-only", categoryHex: ZERO32, amount: "0", commitmentHex: "aa" }), /fungible-only/);
  assert.throws(() => decodeTokenRecord("03" + "00".repeat(32) + "00".repeat(8) + "81" + "00".repeat(129)), /exceeds 128/);
  assert.throws(() => decodeTokenRecord("00ff"), /trailing/);
  assert.throws(() => encodeTokenRecord({
    categoryHex: ZERO32, capability: "fungible-only", commitmentHex: "", amount: "0",
  }), /none-token alias/);
});

test("TxContextFv1 canonical role order roundtrips and exposes only its domain preimage", () => {
  const encoded = encodeTxContext(contextFixture);
  const decoded = decodeTxContext(encoded);
  assert.deepEqual(decoded, contextFixture);
  assert.equal(txContextHex(contextFixture), bytesToHex(encoded));
  const domain = new TextEncoder().encode("PoolActionFv1/TxContext");
  const domainPreimage = txContextDomainPreimage(contextFixture);
  assert.deepEqual(domainPreimage.slice(0, domain.length), domain);
  assert.deepEqual(domainPreimage.slice(domain.length), encoded);
  assert.equal(bytesToHex(encoded.slice(119, 151)), WIRE_TXID, 'outpoint txid wire order changed');
  assert.equal(bytesToHex(encoded.slice(171, 203)), STATE_CATEGORY, 'CashToken category wire order changed');
  assert.deepEqual(
    { bytes: encoded.length, sha256: sha256Hex(encoded) },
    { bytes: 659, sha256: '3734955c9fcdeb96bd51ff7cf6c654b3668f69495a912d3bf99f8b322333509f' },
  );
});

test("TxContextFv1 rejects role substitutions, suffixes, and oversized varbytes", () => {
  const reordered = structuredClone(contextFixture);
  reordered.inputs[1].role = "FEE_FUNDING";
  assert.throws(() => encodeTxContext(reordered), /carrier ordinal/);
  assert.throws(() => decodeTxContext(`${txContextHex(contextFixture)}00`), /trailing/);
  const oversized = structuredClone(contextFixture);
  oversized.inputs[0].sourceLockingBytecodeHex = "51".repeat(10001);
  assert.throws(() => encodeTxContext(oversized), /varbytes limit/);
  const emptyLock = structuredClone(contextFixture);
  emptyLock.inputs[0].sourceLockingBytecodeHex = "";
  assert.throws(() => encodeTxContext(emptyLock), /nonempty/);
  const changedCarrierLock = structuredClone(contextFixture);
  changedCarrierLock.outputs[1].lockingBytecodeHex = "56";
  assert.throws(() => encodeTxContext(changedCarrierLock), /lock\/value\/token/);
});

test("fixed PoolActionFv1 statement KAT roundtrips without digest computation", () => {
  const encoded = encodePoolActionStatement(statementFixture);
  const decoded = decodePoolActionStatement(encoded);
  assert.deepEqual(decoded, statementFixture);
  assert.equal(poolActionStatementHex(statementFixture), bytesToHex(encoded));
  const payoutDomain = new TextEncoder().encode("PoolActionFv1/PayoutLock");
  const payoutPreimage = payoutLockDomainPreimage("51");
  assert.deepEqual(payoutPreimage.slice(0, payoutDomain.length), payoutDomain);
  assert.equal(bytesToHex(payoutPreimage.slice(payoutDomain.length)), "010051");
  assert.equal(encoded.length, 589);
  assert.deepEqual(
    { bytes: encoded.length, sha256: sha256Hex(encoded) },
    { bytes: 589, sha256: '1ea9dfaabf4c905aed036403e2425681031b4b3b69124cc639b724151cb9b974' },
  );
});

test('JSON-to-wire projection derives only the payout digest through an injected adapter', () => {
  const depositJson = jsonStatement(structuredClone(contextFixture));
  const depositProjection = projectPoolActionJsonStatement(depositJson);
  assert.equal(depositProjection.payoutOutputIndexOrffff, 0xffff);
  assert.equal(depositProjection.payoutLockingBytecodeDigestOrZeroHex, ZERO32);
  assert.deepEqual(
    encodePoolActionJsonStatement(depositJson),
    encodePoolActionStatement(depositProjection),
  );

  const withdrawalContext = structuredClone(contextFixture);
  withdrawalContext.actionKind = 'WITHDRAWAL';
  withdrawalContext.inputs.at(-1).role = 'FEE_FUNDING';
  withdrawalContext.inputs[0].sourceValueSats = '20000000';
  withdrawalContext.inputs.at(-1).sourceValueSats = '1000';
  withdrawalContext.outputs[0].valueSats = '10000000';
  withdrawalContext.outputs.push({
    index: 2,
    role: 'PAYOUT',
    roleOrdinal: 0,
    valueSats: '10000000',
    lockingBytecodeHex: '57',
    token: NONE,
  });
  const withdrawalJson = jsonStatement(withdrawalContext, {
    payout: { outputIndex: 2, amountSats: '10000000', lockingBytecodeHex: '57', token: NONE },
  });
  let observedPreimage;
  const withdrawalProjection = projectPoolActionJsonStatement(withdrawalJson, {
    digestPayoutLock: (preimage) => {
      observedPreimage = preimage;
      return new Uint8Array(32).fill(0x73);
    },
  });
  assert.deepEqual(observedPreimage, payoutLockDomainPreimage('57'));
  assert.equal(withdrawalProjection.payoutLockingBytecodeDigestOrZeroHex, '73'.repeat(32));
  assert.throws(() => projectPoolActionJsonStatement(withdrawalJson), /requires a digestPayoutLock adapter/);
  assert.throws(() => projectPoolActionJsonStatement(withdrawalJson, {
    digestPayoutLock: () => new Uint8Array(31),
  }), /exactly 32/);
  assert.throws(() => projectPoolActionJsonStatement({ ...depositJson, ignored: true }), /ignored/);
  const incoherentState = structuredClone(depositJson);
  incoherentState.stateInput.sourceValueSats = '1';
  assert.throws(() => projectPoolActionJsonStatement(incoherentState), /disagrees with transactionContext/);
  const incoherentFee = structuredClone(depositJson);
  incoherentFee.fee.feeSats = '999';
  assert.throws(() => projectPoolActionJsonStatement(incoherentFee), /balance/);
});

test("PoolActionFv1 statement rejects action-specific aliases, fee overflow, and suffixes", () => {
  const withdrawal = { ...statementFixture, actionKind: "WITHDRAWAL" };
  assert.throws(() => encodePoolActionStatement(withdrawal), /reserveDeltaSats/);
  assert.throws(() => encodePoolActionStatement({ ...statementFixture, feeSats: "2001" }), /maxFeeSats/);
  assert.throws(() => decodePoolActionStatement(`${poolActionStatementHex(statementFixture)}00`), /trailing/);
  assert.throws(() => encodePoolActionStatement({ ...statementFixture, payoutOutputIndexOrffff: 0x10000 }), /integer/);
  assert.throws(() => encodePoolActionStatement({ ...statementFixture, reserveDeltaSats: "-0" }), /canonical decimal/);
  assert.throws(() => encodePoolActionStatement({ ...statementFixture, reserveDeltaSats: "9223372036854775808" }), /int64/);
});

test("all exported codecs reject non-Uint8Array decode inputs except canonical lowercase hex", () => {
  assert.throws(() => decodePoolState({}), /Uint8Array|lowercase/);
  assert.throws(() => decodeTokenRecord({}), /Uint8Array|lowercase/);
  assert.throws(() => decodeTxContext({}), /Uint8Array|lowercase/);
  assert.throws(() => decodePoolActionStatement({}), /Uint8Array|lowercase/);
  assert.equal(hexToBytes("00")[0], 0);
});
